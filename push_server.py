import os
import json
import hmac
from datetime import datetime, timedelta

from flask import request, jsonify
from pywebpush import webpush, WebPushException

import app as base_app

app = base_app.app

DATABASE = base_app.DATABASE
get_db = base_app.get_db
now_string = base_app.now_string

VAPID_PUBLIC_KEY = os.environ.get("VAPID_PUBLIC_KEY", "")
VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY", "")
VAPID_SUBJECT = os.environ.get("VAPID_SUBJECT", "mailto:admin@example.com")
REMINDER_CRON_SECRET = os.environ.get("REMINDER_CRON_SECRET", "")


def init_push_database():
    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS push_subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            endpoint TEXT NOT NULL UNIQUE,
            p256dh TEXT NOT NULL,
            auth TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS sent_reminders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assignment_id INTEGER NOT NULL,
            reminder_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(assignment_id, reminder_at),
            FOREIGN KEY (assignment_id) REFERENCES assignments(id) ON DELETE CASCADE
        )
    """)

    db.commit()
    db.close()


init_push_database()


@app.route("/manifest.json")
def push_manifest():
    return jsonify({
        "name": "AssignmentFlow",
        "short_name": "AssignmentFlow",
        "start_url": "/dashboard",
        "display": "standalone",
        "background_color": "#0f172a",
        "theme_color": "#6366f1",
        "id": "/assignmentflow"
    })


@app.route("/sw.js")
def push_service_worker():
    code = """
self.addEventListener('push', event => {
    let data = {};
    try {
        data = event.data ? event.data.json() : {};
    } catch (e) {
        data = { title: 'AssignmentFlow 🔔', body: event.data ? event.data.text() : 'New reminder' };
    }

    event.waitUntil(
        self.registration.showNotification(
            data.title || 'AssignmentFlow 🔔',
            {
                body: data.body || 'You have an assignment reminder.',
                tag: data.tag || 'assignmentflow-reminder',
                data: { url: data.url || '/dashboard' }
            }
        )
    );
});

self.addEventListener('notificationclick', event => {
    event.notification.close();
    const url = event.notification.data?.url || '/dashboard';
    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
            for (const client of list) {
                if ('focus' in client) {
                    client.focus();
                    return;
                }
            }
            if (clients.openWindow) return clients.openWindow(url);
        })
    );
});
"""
    return code, 200, {
        "Content-Type": "application/javascript; charset=utf-8",
        "Cache-Control": "no-cache"
    }


def login_required():
    return "user_id" in base_app.session


@app.route("/api/push/public-key")
def push_public_key():
    if not VAPID_PUBLIC_KEY:
        return jsonify({"success": False, "message": "VAPID public key is not configured."}), 503
    return jsonify({"success": True, "publicKey": VAPID_PUBLIC_KEY})


@app.route("/api/push/subscribe", methods=["POST"])
def push_subscribe():
    if not login_required():
        return jsonify({"success": False, "message": "Login required."}), 401

    data = request.get_json(silent=True) or {}
    endpoint = str(data.get("endpoint", "")).strip()
    keys = data.get("keys") or {}
    p256dh = str(keys.get("p256dh", "")).strip()
    auth = str(keys.get("auth", "")).strip()

    if not endpoint or not p256dh or not auth:
        return jsonify({"success": False, "message": "Invalid push subscription."}), 400

    db = get_db()
    db.execute("""
        INSERT INTO push_subscriptions
        (user_id, endpoint, p256dh, auth, created_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(endpoint) DO UPDATE SET
            user_id=excluded.user_id,
            p256dh=excluded.p256dh,
            auth=excluded.auth,
            created_at=excluded.created_at
    """, (base_app.session["user_id"], endpoint, p256dh, auth, now_string()))
    db.commit()
    db.close()

    return jsonify({"success": True, "message": "Push notifications enabled."})


def send_push(subscription, payload):
    webpush(
        subscription_info={
            "endpoint": subscription["endpoint"],
            "keys": {
                "p256dh": subscription["p256dh"],
                "auth": subscription["auth"]
            }
        },
        data=json.dumps(payload),
        vapid_private_key=VAPID_PRIVATE_KEY,
        vapid_claims={"sub": VAPID_SUBJECT},
        ttl=3600
    )


@app.route("/api/push/test", methods=["POST"])
def push_test():
    if not login_required():
        return jsonify({"success": False, "message": "Login required."}), 401
    if not VAPID_PRIVATE_KEY:
        return jsonify({"success": False, "message": "VAPID keys are not configured."}), 503

    db = get_db()
    rows = db.execute(
        "SELECT * FROM push_subscriptions WHERE user_id = ?",
        (base_app.session["user_id"],)
    ).fetchall()
    sent = 0

    for row in rows:
        try:
            send_push(row, {
                "title": "AssignmentFlow 🔔",
                "body": "Push notifications are working!",
                "url": "/dashboard",
                "tag": "assignmentflow-test"
            })
            sent += 1
        except WebPushException as exc:
            if getattr(exc.response, "status_code", None) in (404, 410):
                db.execute("DELETE FROM push_subscriptions WHERE id = ?", (row["id"],))

    db.commit()
    db.close()

    if not sent:
        return jsonify({"success": False, "message": "No active subscription. Enable notifications first."}), 400
    return jsonify({"success": True, "message": "Test notification sent."})


@app.route("/api/process-reminders")
def process_reminders():
    supplied = request.headers.get("X-Cron-Secret", "")
    if not REMINDER_CRON_SECRET or not hmac.compare_digest(supplied, REMINDER_CRON_SECRET):
        return jsonify({"success": False, "message": "Unauthorized."}), 401

    if not VAPID_PRIVATE_KEY:
        return jsonify({"success": False, "message": "VAPID private key is not configured."}), 503

    now = datetime.now()
    db = get_db()
    assignments = db.execute("""
        SELECT * FROM assignments
        WHERE status = 'Pending'
        ORDER BY deadline ASC
    """).fetchall()

    delivered = 0

    for assignment in assignments:
        deadline = datetime.strptime(assignment["deadline"], "%Y-%m-%d %H:%M:%S")
        reminder_at = deadline - timedelta(minutes=assignment["reminder_minutes"])

        if now < reminder_at or now > deadline:
            continue

        reminder_key = reminder_at.strftime("%Y-%m-%d %H:%M:%S")
        already_sent = db.execute(
            "SELECT id FROM sent_reminders WHERE assignment_id = ? AND reminder_at = ?",
            (assignment["id"], reminder_key)
        ).fetchone()
        if already_sent:
            continue

        seconds_left = max(0, int((deadline - now).total_seconds()))
        minutes_left = seconds_left // 60

        if minutes_left <= 0:
            message = f"{assignment['title']} is due now."
        elif minutes_left < 60:
            message = f"{assignment['title']} is due in {minutes_left} minute(s)."
        else:
            hours = minutes_left // 60
            minutes = minutes_left % 60
            message = f"{assignment['title']} is due in {hours} hour(s)"
            if minutes:
                message += f" and {minutes} minute(s)"
            message += "."

        subscriptions = db.execute(
            "SELECT * FROM push_subscriptions WHERE user_id = ?",
            (assignment["user_id"],)
        ).fetchall()

        sent_for_assignment = False
        for subscription in subscriptions:
            try:
                send_push(subscription, {
                    "title": "AssignmentFlow 🔔",
                    "body": f"{message} Subject: {assignment['subject']}",
                    "url": "/dashboard",
                    "tag": f"assignment-{assignment['id']}-{reminder_key}"
                })
                sent_for_assignment = True
                delivered += 1
            except WebPushException as exc:
                if getattr(exc.response, "status_code", None) in (404, 410):
                    db.execute("DELETE FROM push_subscriptions WHERE id = ?", (subscription["id"],))

        if sent_for_assignment:
            db.execute(
                "INSERT OR IGNORE INTO sent_reminders (assignment_id, reminder_at, created_at) VALUES (?, ?, ?)",
                (assignment["id"], reminder_key, now_string())
            )

    db.commit()
    db.close()
    return jsonify({"success": True, "delivered": delivered})


@app.after_request
def inject_push_ui(response):
    if request.path != "/dashboard":
        return response
    if not response.content_type or "text/html" not in response.content_type:
        return response

    html = response.get_data(as_text=True)

    head = '''<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#6366f1">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="AssignmentFlow">'''

    button = '''<button class="icon-btn" onclick="enablePushNotifications()" title="Enable notifications" id="pushButton">🔔</button>'''

    script = r'''<script>
function pushBase64ToBytes(base64) {
    const padding = "=".repeat((4 - base64.length % 4) % 4);
    const raw = atob((base64 + padding).replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from([...raw].map(c => c.charCodeAt(0)));
}

async function enablePushNotifications() {
    if (!("serviceWorker" in navigator) || !("PushManager" in window) || !("Notification" in window)) {
        showToast("Push notifications are not supported here.");
        return;
    }

    try {
        const registration = await navigator.serviceWorker.register("/sw.js");
        const permission = await Notification.requestPermission();
        if (permission !== "granted") {
            showToast("Notification permission was not granted.");
            return;
        }

        const keyResponse = await fetch("/api/push/public-key");
        const keyData = await keyResponse.json();
        if (!keyResponse.ok || !keyData.publicKey) {
            showToast("Push notifications are not configured yet.");
            return;
        }

        let subscription = await registration.pushManager.getSubscription();
        if (!subscription) {
            subscription = await registration.pushManager.subscribe({
                userVisibleOnly: true,
                applicationServerKey: pushBase64ToBytes(keyData.publicKey)
            });
        }

        const saveResponse = await fetch("/api/push/subscribe", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(subscription.toJSON())
        });
        const result = await saveResponse.json();

        if (!saveResponse.ok) {
            showToast(result.message || "Unable to enable notifications.");
            return;
        }

        const button = document.getElementById("pushButton");
        if (button) {
            button.textContent = "🔔✓";
            button.title = "Notifications enabled";
        }
        showToast("🔔 Notifications enabled!");

    } catch (error) {
        console.error("Push setup failed:", error);
        showToast("Unable to enable notifications.");
    }
}

if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").catch(console.error);
}
</script>'''

    if "rel=\"manifest\"" not in html:
        html = html.replace("</head>", head + "</head>", 1)
    if 'id="pushButton"' not in html and 'class="nav-actions"' in html:
        html = html.replace('<div class="nav-actions">', '<div class="nav-actions">' + button, 1)
    html = html.replace("</body>", script + "</body>", 1)

    response.set_data(html)
    return response
