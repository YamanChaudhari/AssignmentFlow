from flask import (
    Flask,
    request,
    redirect,
    session,
    jsonify,
    render_template_string,
    flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import sqlite3
import os


# ============================================================
# APP CONFIGURATION
# ============================================================

app = Flask(__name__)

app.secret_key = "assignment-reminder-final-secret-key-change-this"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "assignment_reminder.db")


# ============================================================
# DATABASE
# ============================================================

def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():

    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            subject TEXT NOT NULL,
            description TEXT DEFAULT '',
            deadline TEXT NOT NULL,
            priority TEXT NOT NULL DEFAULT 'Medium',
            status TEXT NOT NULL DEFAULT 'Pending',
            reminder_minutes INTEGER NOT NULL DEFAULT 60,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        )
    """)

    db.commit()
    db.close()


initialize_database()


# ============================================================
# AUTH HELPERS
# ============================================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:

            return redirect("/login")

        return function(*args, **kwargs)

    return wrapper


def current_user():

    if "user_id" not in session:
        return None

    db = get_db()

    user = db.execute(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    db.close()

    return user


# ============================================================
# TIME HELPERS
# ============================================================

def now_string():

    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def parse_deadline(value):

    formats = [
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M"
    ]

    for fmt in formats:

        try:
            return datetime.strptime(value, fmt)

        except ValueError:
            continue

    return None


# ============================================================
# VALIDATION
# ============================================================

ALLOWED_PRIORITIES = {
    "Low",
    "Medium",
    "High"
}


ALLOWED_REMINDERS = {
    1440,
    360,
    60,
    30
}


# ============================================================
# MAIN PAGE
# ============================================================

@app.route("/")
def home():

    if "user_id" in session:
        return redirect("/dashboard")

    return redirect("/login")


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        db = get_db()

        user = db.execute(
            """
            SELECT *
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        db.close()

        if user and check_password_hash(
            user["password"],
            password
        ):

            session["user_id"] = user["id"]

            session["user_name"] = user["name"]

            return redirect("/dashboard")

        return render_template_string(
            LOGIN_PAGE,
            error="Invalid email or password."
        )

    return render_template_string(
        LOGIN_PAGE,
        error=None
    )


# ============================================================
# REGISTER
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )


        if len(name) < 2:

            return render_template_string(
                REGISTER_PAGE,
                error="Please enter your name."
            )


        if len(password) < 6:

            return render_template_string(
                REGISTER_PAGE,
                error="Password must contain at least 6 characters."
            )


        db = get_db()

        existing = db.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,)
        ).fetchone()


        if existing:

            db.close()

            return render_template_string(
                REGISTER_PAGE,
                error="An account with this email already exists."
            )


        hashed_password = generate_password_hash(
            password
        )


        db.execute(
            """
            INSERT INTO users
            (name, email, password, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                name,
                email,
                hashed_password,
                now_string()
            )
        )

        db.commit()

        db.close()

        return redirect("/login")

    return render_template_string(
        REGISTER_PAGE,
        error=None
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():

    user = current_user()

    if user is None:
        session.clear()
        return redirect("/login")

    return render_template_string(
        DASHBOARD_PAGE,
        user=user
    )


# ============================================================
# GET ASSIGNMENTS API
# ============================================================

@app.route("/api/assignments")
@login_required
def get_assignments():

    user_id = session["user_id"]

    search = request.args.get(
        "search",
        ""
    ).strip()

    status = request.args.get(
        "status",
        "All"
    )

    priority = request.args.get(
        "priority",
        "All"
    )


    db = get_db()

    query = """
        SELECT *
        FROM assignments
        WHERE user_id = ?
    """

    parameters = [user_id]


    if search:

        query += """
            AND (
                LOWER(title) LIKE ?
                OR LOWER(subject) LIKE ?
                OR LOWER(description) LIKE ?
            )
        """

        search_value = f"%{search.lower()}%"

        parameters.extend([
            search_value,
            search_value,
            search_value
        ])


    if status in {
        "Pending",
        "Completed"
    }:

        query += " AND status = ?"

        parameters.append(status)


    if priority in {
        "Low",
        "Medium",
        "High"
    }:

        query += " AND priority = ?"

        parameters.append(priority)


    query += """
        ORDER BY
        CASE
            WHEN status = 'Pending' THEN 0
            ELSE 1
        END,
        deadline ASC
    """


    assignments = db.execute(
        query,
        parameters
    ).fetchall()


    db.close()


    return jsonify([
        dict(assignment)
        for assignment in assignments
    ])


# ============================================================
# DASHBOARD STATISTICS
# ============================================================

@app.route("/api/stats")
@login_required
def statistics():

    user_id = session["user_id"]

    db = get_db()

    total = db.execute(
        """
        SELECT COUNT(*)
        FROM assignments
        WHERE user_id = ?
        """,
        (user_id,)
    ).fetchone()[0]


    pending = db.execute(
        """
        SELECT COUNT(*)
        FROM assignments
        WHERE user_id = ?
        AND status = 'Pending'
        """,
        (user_id,)
    ).fetchone()[0]


    completed = db.execute(
        """
        SELECT COUNT(*)
        FROM assignments
        WHERE user_id = ?
        AND status = 'Completed'
        """,
        (user_id,)
    ).fetchone()[0]


    overdue = db.execute(
        """
        SELECT COUNT(*)
        FROM assignments
        WHERE user_id = ?
        AND status = 'Pending'
        AND deadline < ?
        """,
        (
            user_id,
            now_string()
        )
    ).fetchone()[0]


    db.close()


    completion = 0

    if total > 0:

        completion = round(
            (completed / total) * 100
        )


    return jsonify({
        "total": total,
        "pending": pending,
        "completed": completed,
        "overdue": overdue,
        "completion": completion
    })


# ============================================================
# ADD ASSIGNMENT API
# ============================================================

@app.route(
    "/api/assignments",
    methods=["POST"]
)
@login_required
def add_assignment():

    data = request.get_json(
        silent=True
    ) or {}


    title = str(
        data.get("title", "")
    ).strip()

    subject = str(
        data.get("subject", "")
    ).strip()

    description = str(
        data.get("description", "")
    ).strip()

    deadline_input = str(
        data.get("deadline", "")
    ).strip()

    priority = data.get(
        "priority",
        "Medium"
    )

    reminder_minutes = data.get(
        "reminder_minutes",
        60
    )


    if not title:

        return jsonify({
            "success": False,
            "message": "Assignment title is required."
        }), 400


    if not subject:

        return jsonify({
            "success": False,
            "message": "Subject is required."
        }), 400


    if priority not in ALLOWED_PRIORITIES:

        priority = "Medium"


    try:

        reminder_minutes = int(
            reminder_minutes
        )

    except (TypeError, ValueError):

        reminder_minutes = 60


    if reminder_minutes not in ALLOWED_REMINDERS:

        reminder_minutes = 60


    deadline = parse_deadline(
        deadline_input
    )


    if not deadline:

        return jsonify({
            "success": False,
            "message": "Invalid deadline."
        }), 400


    db = get_db()

    db.execute(
        """
        INSERT INTO assignments
        (
            user_id,
            title,
            subject,
            description,
            deadline,
            priority,
            status,
            reminder_minutes,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session["user_id"],
            title,
            subject,
            description,
            deadline.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            priority,
            "Pending",
            reminder_minutes,
            now_string()
        )
    )

    db.commit()

    db.close()


    return jsonify({
        "success": True,
        "message": "Assignment created successfully."
    })


# ============================================================
# UPDATE ASSIGNMENT API
# ============================================================

@app.route(
    "/api/assignments/<int:assignment_id>",
    methods=["PUT"]
)
@login_required
def update_assignment(
    assignment_id
):

    data = request.get_json(
        silent=True
    ) or {}


    title = str(
        data.get("title", "")
    ).strip()

    subject = str(
        data.get("subject", "")
    ).strip()

    description = str(
        data.get("description", "")
    ).strip()

    deadline_input = str(
        data.get("deadline", "")
    ).strip()

    priority = data.get(
        "priority",
        "Medium"
    )

    reminder_minutes = data.get(
        "reminder_minutes",
        60
    )


    deadline = parse_deadline(
        deadline_input
    )


    if not title or not subject or not deadline:

        return jsonify({
            "success": False,
            "message": "Please provide valid assignment details."
        }), 400


    if priority not in ALLOWED_PRIORITIES:

        priority = "Medium"


    try:

        reminder_minutes = int(
            reminder_minutes
        )

    except (TypeError, ValueError):

        reminder_minutes = 60


    if reminder_minutes not in ALLOWED_REMINDERS:

        reminder_minutes = 60


    db = get_db()


    existing = db.execute(
        """
        SELECT id
        FROM assignments
        WHERE id = ?
        AND user_id = ?
        """,
        (
            assignment_id,
            session["user_id"]
        )
    ).fetchone()


    if not existing:

        db.close()

        return jsonify({
            "success": False,
            "message": "Assignment not found."
        }), 404


    db.execute(
        """
        UPDATE assignments
        SET
            title = ?,
            subject = ?,
            description = ?,
            deadline = ?,
            priority = ?,
            reminder_minutes = ?
        WHERE id = ?
        AND user_id = ?
        """,
        (
            title,
            subject,
            description,
            deadline.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            priority,
            reminder_minutes,
            assignment_id,
            session["user_id"]
        )
    )


    db.commit()

    db.close()


    return jsonify({
        "success": True,
        "message": "Assignment updated successfully."
    })


# ============================================================
# COMPLETE ASSIGNMENT
# ============================================================

@app.route(
    "/api/assignments/<int:assignment_id>/complete",
    methods=["PUT"]
)
@login_required
def complete_assignment(
    assignment_id
):

    db = get_db()


    result = db.execute(
        """
        UPDATE assignments
        SET status = 'Completed'
        WHERE id = ?
        AND user_id = ?
        """,
        (
            assignment_id,
            session["user_id"]
        )
    )


    db.commit()

    db.close()


    if result.rowcount == 0:

        return jsonify({
            "success": False,
            "message": "Assignment not found."
        }), 404


    return jsonify({
        "success": True,
        "message": "Assignment completed."
    })


# ============================================================
# DELETE ASSIGNMENT
# ============================================================

@app.route(
    "/api/assignments/<int:assignment_id>",
    methods=["DELETE"]
)
@login_required
def delete_assignment(
    assignment_id
):

    db = get_db()


    result = db.execute(
        """
        DELETE FROM assignments
        WHERE id = ?
        AND user_id = ?
        """,
        (
            assignment_id,
            session["user_id"]
        )
    )


    db.commit()

    db.close()


    if result.rowcount == 0:

        return jsonify({
            "success": False,
            "message": "Assignment not found."
        }), 404


    return jsonify({
        "success": True,
        "message": "Assignment deleted."
    })


# ============================================================
# REMINDER API
# ============================================================

@app.route("/api/reminders")
@login_required
def reminders():

    user_id = session["user_id"]

    now = datetime.now()

    db = get_db()

    assignments = db.execute(
        """
        SELECT *
        FROM assignments
        WHERE user_id = ?
        AND status = 'Pending'
        ORDER BY deadline ASC
        """,
        (user_id,)
    ).fetchall()

    db.close()


    results = []


    for assignment in assignments:

        deadline = datetime.strptime(
            assignment["deadline"],
            "%Y-%m-%d %H:%M:%S"
        )


        reminder_at = (
            deadline
            - timedelta(
                minutes=assignment[
                    "reminder_minutes"
                ]
            )
        )


        if (
            now >= reminder_at
            and now <= deadline
        ):

            seconds_left = (
                deadline - now
            ).total_seconds()


            minutes_left = max(
                0,
                int(
                    seconds_left / 60
                )
            )


            results.append({

                "id": assignment["id"],

                "title": assignment["title"],

                "subject": assignment["subject"],

                "deadline": deadline.strftime(
                    "%d %b %Y, %I:%M %p"
                ),

                "minutes_left": minutes_left,

                "reminder_minutes":
                    assignment[
                        "reminder_minutes"
                    ]

            })


    return jsonify(results)


# ============================================================
# FULL APPLICATION UI
# ============================================================

DASHBOARD_PAGE = """
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>AssignmentFlow</title>

<style>

:root {

    --bg: #f4f7fb;
    --card: #ffffff;
    --text: #172033;
    --muted: #6b7280;
    --border: #e5e7eb;
    --primary: #5b5ff5;
    --primary-dark: #4548d8;
    --success: #16a34a;
    --danger: #dc2626;
    --warning: #f59e0b;
    --shadow: 0 10px 35px rgba(15, 23, 42, .07);

}

* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

body {

    font-family:
        Inter,
        ui-sans-serif,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;

    background: var(--bg);

    color: var(--text);

    min-height: 100vh;

}


body.dark {

    --bg: #0f172a;
    --card: #172033;
    --text: #f8fafc;
    --muted: #94a3b8;
    --border: #293449;
    --shadow: 0 10px 35px rgba(0,0,0,.25);

}


button,
input,
textarea,
select {

    font: inherit;

}


button {

    cursor: pointer;

    border: none;

}


.navbar {

    background: var(--card);

    border-bottom: 1px solid var(--border);

    height: 72px;

    display: flex;

    align-items: center;

    justify-content: space-between;

    padding: 0 5%;

    position: sticky;

    top: 0;

    z-index: 100;

}


.brand {

    display: flex;

    align-items: center;

    gap: 12px;

    font-size: 21px;

    font-weight: 800;

}


.brand-icon {

    width: 38px;

    height: 38px;

    border-radius: 12px;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );

    display: grid;

    place-items: center;

    color: white;

    font-size: 19px;

}


.nav-actions {

    display: flex;

    align-items: center;

    gap: 12px;

}


.icon-btn {

    width: 40px;

    height: 40px;

    border-radius: 10px;

    background: transparent;

    color: var(--text);

    border: 1px solid var(--border);

}


.profile {

    display: flex;

    align-items: center;

    gap: 10px;

}


.avatar {

    width: 38px;

    height: 38px;

    border-radius: 50%;

    display: grid;

    place-items: center;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #a855f7
        );

    color: white;

    font-weight: 700;

}


.profile-name {

    font-size: 14px;

    font-weight: 700;

}


.logout {

    text-decoration: none;

    color: var(--muted);

    font-size: 13px;

}


.container {

    max-width: 1450px;

    margin: auto;

    padding: 38px 5% 60px;

}


.hero {

    display: flex;

    justify-content: space-between;

    align-items: flex-end;

    gap: 20px;

    margin-bottom: 28px;

}


.hero h1 {

    font-size: clamp(
        28px,
        4vw,
        40px
    );

    letter-spacing: -.03em;

}


.hero p {

    margin-top: 7px;

    color: var(--muted);

}


.primary-btn {

    background:
        linear-gradient(
            135deg,
            var(--primary),
            #8b5cf6
        );

    color: white;

    padding: 12px 18px;

    border-radius: 11px;

    font-weight: 700;

    box-shadow:
        0 8px 20px
        rgba(91,95,245,.25);

}


.primary-btn:hover {

    transform: translateY(-1px);

}


.stats {

    display: grid;

    grid-template-columns:
        repeat(4, 1fr);

    gap: 18px;

    margin-bottom: 25px;

}


.stat {

    background: var(--card);

    border: 1px solid var(--border);

    box-shadow: var(--shadow);

    border-radius: 16px;

    padding: 21px;

    position: relative;

    overflow: hidden;

}


.stat::after {

    content: "";

    position: absolute;

    width: 75px;

    height: 75px;

    right: -25px;

    top: -25px;

    border-radius: 50%;

    background: rgba(
        99,
        102,
        241,
        .09
    );

}


.stat-label {

    color: var(--muted);

    font-size: 13px;

    font-weight: 600;

}


.stat-value {

    font-size: 31px;

    font-weight: 800;

    margin-top: 7px;

}


.progress {

    margin-top: 13px;

    height: 7px;

    border-radius: 100px;

    background: var(--border);

    overflow: hidden;

}


.progress-fill {

    height: 100%;

    background:
        linear-gradient(
            90deg,
            #6366f1,
            #a855f7
        );

    width: 0%;

    transition: .4s;

}


.layout {

    display: grid;

    grid-template-columns:
        minmax(0, 1fr)
        350px;

    gap: 22px;

}


.panel {

    background: var(--card);

    border: 1px solid var(--border);

    border-radius: 18px;

    box-shadow: var(--shadow);

}


.panel-header {

    padding: 19px 20px;

    display: flex;

    justify-content: space-between;

    align-items: center;

    border-bottom: 1px solid var(--border);

    gap: 15px;

}


.panel-title {

    font-size: 17px;

    font-weight: 800;

}


.controls {

    padding: 16px 20px;

    display: grid;

    grid-template-columns:
        1fr
        150px
        150px;

    gap: 10px;

    border-bottom: 1px solid var(--border);

}


.field {

    width: 100%;

    border: 1px solid var(--border);

    background: var(--bg);

    color: var(--text);

    border-radius: 10px;

    padding: 10px 12px;

    outline: none;

}


.field:focus {

    border-color: var(--primary);

}


.assignment-list {

    padding: 18px;

    display: flex;

    flex-direction: column;

    gap: 13px;

}


.assignment {

    border: 1px solid var(--border);

    border-radius: 15px;

    padding: 18px;

    display: flex;

    justify-content: space-between;

    gap: 15px;

    transition: .2s;

}


.assignment:hover {

    transform: translateY(-2px);

    box-shadow: var(--shadow);

}


.assignment.completed {

    opacity: .65;

}


.assignment-main {

    min-width: 0;

}


.assignment-title {

    font-size: 16px;

    font-weight: 800;

    margin-bottom: 7px;

}


.assignment-meta {

    color: var(--muted);

    font-size: 13px;

    display: flex;

    flex-wrap: wrap;

    gap: 8px;

}


.badges {

    margin-top: 12px;

    display: flex;

    flex-wrap: wrap;

    gap: 7px;

}


.badge {

    padding: 5px 8px;

    border-radius: 8px;

    font-size: 11px;

    font-weight: 800;

}


.badge-low {

    background: #dcfce7;

    color: #166534;

}


.badge-medium {

    background: #fef3c7;

    color: #92400e;

}


.badge-high {

    background: #fee2e2;

    color: #991b1b;

}


.badge-status {

    background: #e0e7ff;

    color: #3730a3;

}


.badge-overdue {

    background: #fee2e2;

    color: #991b1b;

}


.countdown {

    color: var(--primary);

    font-weight: 800;

}


.assignment-actions {

    display: flex;

    flex-wrap: wrap;

    justify-content: flex-end;

    align-content: center;

    gap: 7px;

}


.small-btn {

    padding: 8px 11px;

    border-radius: 9px;

    font-size: 12px;

    font-weight: 700;

    background: var(--bg);

    color: var(--text);

    border: 1px solid var(--border);

}


.small-btn.success {

    color: var(--success);

}


.small-btn.danger {

    color: var(--danger);

}


.empty {

    text-align: center;

    padding: 55px 20px;

    color: var(--muted);

}


.empty-icon {

    font-size: 42px;

    margin-bottom: 10px;

}


.upcoming {

    padding: 18px;

}


.upcoming-item {

    display: flex;

    gap: 11px;

    padding: 13px 0;

    border-bottom: 1px solid var(--border);

}


.upcoming-item:last-child {

    border-bottom: none;

}


.date-box {

    min-width: 47px;

    height: 47px;

    border-radius: 12px;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );

    color: white;

    display: grid;

    place-items: center;

    font-weight: 800;

}


.upcoming-info {

    min-width: 0;

}


.upcoming-title {

    font-size: 13px;

    font-weight: 800;

    white-space: nowrap;

    overflow: hidden;

    text-overflow: ellipsis;

}


.upcoming-time {

    color: var(--muted);

    font-size: 11px;

    margin-top: 3px;

}


.modal {

    position: fixed;

    inset: 0;

    background: rgba(
        15,
        23,
        42,
        .55
    );

    backdrop-filter: blur(6px);

    display: none;

    align-items: center;

    justify-content: center;

    padding: 20px;

    z-index: 500;

}


.modal.active {

    display: flex;

}


.modal-box {

    width: min(
        650px,
        100%
    );

    max-height: 92vh;

    overflow-y: auto;

    background: var(--card);

    border-radius: 20px;

    border: 1px solid var(--border);

    box-shadow:
        0 30px 80px
        rgba(0,0,0,.22);

}


.modal-header {

    padding: 20px;

    display: flex;

    justify-content: space-between;

    align-items: center;

    border-bottom: 1px solid var(--border);

}


.modal-body {

    padding: 20px;

}


.form-grid {

    display: grid;

    grid-template-columns:
        1fr
        1fr;

    gap: 15px;

}


.form-group {

    display: flex;

    flex-direction: column;

    gap: 7px;

}


.form-group.full {

    grid-column: 1 / -1;

}


.form-group label {

    font-size: 12px;

    font-weight: 800;

    color: var(--muted);

}


textarea.field {

    min-height: 110px;

    resize: vertical;

}


.modal-footer {

    margin-top: 20px;

    display: flex;

    justify-content: flex-end;

    gap: 9px;

}


.secondary-btn {

    padding: 11px 16px;

    border-radius: 10px;

    background: var(--bg);

    border: 1px solid var(--border);

    color: var(--text);

    font-weight: 700;

}


.toast-container {

    position: fixed;

    right: 20px;

    bottom: 20px;

    z-index: 999;

    display: flex;

    flex-direction: column;

    gap: 10px;

}


.toast {

    min-width: 280px;

    max-width: 360px;

    padding: 14px 16px;

    border-radius: 13px;

    background: #111827;

    color: white;

    box-shadow:
        0 15px 40px
        rgba(0,0,0,.2);

    animation: slideIn .25s ease;

}


@keyframes slideIn {

    from {

        transform:
            translateY(15px);

        opacity: 0;

    }

    to {

        transform:
            translateY(0);

        opacity: 1;

    }

}


@media (max-width: 1000px) {

    .layout {

        grid-template-columns: 1fr;

    }

}


@media (max-width: 800px) {

    .stats {

        grid-template-columns:
            repeat(2, 1fr);

    }

    .controls {

        grid-template-columns: 1fr;

    }

    .hero {

        align-items: flex-start;

        flex-direction: column;

    }

}


@media (max-width: 600px) {

    .navbar {

        padding: 0 16px;

    }

    .container {

        padding: 25px 16px 45px;

    }

    .stats {

        grid-template-columns: 1fr;

    }

    .profile-name,
    .logout {

        display: none;

    }

    .assignment {

        flex-direction: column;

    }

    .assignment-actions {

        justify-content: flex-start;

    }

    .form-grid {

        grid-template-columns: 1fr;

    }

    .form-group.full {

        grid-column: auto;

    }

}

</style>

</head>


<body>

<nav class="navbar">

    <div class="brand">

        <div class="brand-icon">
            ✓
        </div>

        AssignmentFlow

    </div>


    <div class="nav-actions">

        <button
            class="icon-btn"
            onclick="toggleTheme()"
            title="Toggle theme"
        >
            🌙
        </button>


        <div class="profile">

            <div class="avatar">
                {{ user["name"][0]|upper }}
            </div>

            <div class="profile-name">
                {{ user["name"] }}
            </div>

            <a
                class="logout"
                href="/logout"
            >
                Logout
            </a>

        </div>

    </div>

</nav>


<div class="container">


    <div class="hero">

        <div>

            <h1>
                Good to see you, {{ user["name"] }} 👋
            </h1>

            <p>
                Stay organized. Never miss an assignment deadline.
            </p>

        </div>


        <button
            class="primary-btn"
            onclick="openAddModal()"
        >
            + Add Assignment
        </button>

    </div>


    <!-- =====================================================
         STATISTICS
         ===================================================== -->

    <div class="stats">


        <div class="stat">

            <div class="stat-label">
                Total Assignments
            </div>

            <div
                class="stat-value"
                id="totalCount"
            >
                0
            </div>

        </div>


        <div class="stat">

            <div class="stat-label">
                Pending
            </div>

            <div
                class="stat-value"
                id="pendingCount"
            >
                0
            </div>

        </div>


        <div class="stat">

            <div class="stat-label">
                Completed
            </div>

            <div
                class="stat-value"
                id="completedCount"
            >
                0
            </div>

        </div>


        <div class="stat">

            <div class="stat-label">
                Overdue
            </div>

            <div
                class="stat-value"
                id="overdueCount"
            >
                0
            </div>

            <div class="progress">

                <div
                    class="progress-fill"
                    id="progressFill"
                ></div>

            </div>

        </div>


    </div>


    <div class="layout">


        <!-- =================================================
             MAIN ASSIGNMENT PANEL
             ================================================= -->

        <section class="panel">

            <div class="panel-header">

                <div class="panel-title">
                    My Assignments
                </div>

            </div>


            <div class="controls">

                <input
                    class="field"
                    id="searchInput"
                    placeholder="🔎 Search assignments..."
                    oninput="loadAssignments()"
                >


                <select
                    class="field"
                    id="statusFilter"
                    onchange="loadAssignments()"
                >

                    <option value="All">
                        All Status
                    </option>

                    <option value="Pending">
                        Pending
                    </option>

                    <option value="Completed">
                        Completed
                    </option>

                </select>


                <select
                    class="field"
                    id="priorityFilter"
                    onchange="loadAssignments()"
                >

                    <option value="All">
                        All Priority
                    </option>

                    <option value="High">
                        High
                    </option>

                    <option value="Medium">
                        Medium
                    </option>

                    <option value="Low">
                        Low
                    </option>

                </select>

            </div>


            <div
                class="assignment-list"
                id="assignmentList"
            >

            </div>

        </section>


        <!-- =================================================
             UPCOMING PANEL
             ================================================= -->

        <aside class="panel">

            <div class="panel-header">

                <div class="panel-title">
                    Upcoming Deadlines
                </div>

            </div>


            <div
                class="upcoming"
                id="upcomingList"
            >

            </div>

        </aside>


    </div>


</div>


<!-- =========================================================
     ADD / EDIT MODAL
     ========================================================= -->

<div
    class="modal"
    id="assignmentModal"
>

    <div class="modal-box">


        <div class="modal-header">

            <div
                class="panel-title"
                id="modalTitle"
            >
                Add Assignment
            </div>


            <button
                class="icon-btn"
                onclick="closeModal()"
            >
                ×
            </button>

        </div>


        <div class="modal-body">

            <form
                id="assignmentForm"
                onsubmit="saveAssignment(event)"
            >

                <input
                    type="hidden"
                    id="assignmentId"
                >


                <div class="form-grid">


                    <div class="form-group full">

                        <label>
                            Assignment Title
                        </label>

                        <input
                            class="field"
                            id="title"
                            placeholder="Example: Python Practical"
                            required
                        >

                    </div>


                    <div class="form-group">

                        <label>
                            Subject
                        </label>

                        <input
                            class="field"
                            id="subject"
                            placeholder="Example: Python"
                            required
                        >

                    </div>


                    <div class="form-group">

                        <label>
                            Priority
                        </label>

                        <select
                            class="field"
                            id="priority"
                        >

                            <option value="High">
                                High
                            </option>

                            <option
                                value="Medium"
                                selected
                            >
                                Medium
                            </option>

                            <option value="Low">
                                Low
                            </option>

                        </select>

                    </div>


                    <div class="form-group full">

                        <label>
                            Deadline
                        </label>

                        <input
                            class="field"
                            type="datetime-local"
                            id="deadline"
                            required
                        >

                    </div>


                    <div class="form-group full">

                        <label>
                            Reminder
                        </label>

                        <select
                            class="field"
                            id="reminder"
                        >

                            <option value="1440">
                                🔔 1 Day Before
                            </option>

                            <option value="360">
                                🔔 6 Hours Before
                            </option>

                            <option
                                value="60"
                                selected
                            >
                                🔔 1 Hour Before
                            </option>

                            <option value="30">
                                🔔 30 Minutes Before
                            </option>

                        </select>

                    </div>


                    <div class="form-group full">

                        <label>
                            Description
                        </label>

                        <textarea
                            class="field"
                            id="description"
                            placeholder="Add assignment details..."
                        ></textarea>

                    </div>


                </div>


                <div class="modal-footer">

                    <button
                        type="button"
                        class="secondary-btn"
                        onclick="closeModal()"
                    >
                        Cancel
                    </button>


                    <button
                        type="submit"
                        class="primary-btn"
                    >
                        Save Assignment
                    </button>

                </div>


            </form>

        </div>

    </div>

</div>


<!-- =========================================================
     TOASTS
     ========================================================= -->

<div
    class="toast-container"
    id="toastContainer"
></div>


<script>


// ============================================================
// GLOBAL STATE
// ============================================================

let assignments = [];


// ============================================================
// TOAST
// ============================================================

function showToast(message) {

    const container =
        document.getElementById(
            "toastContainer"
        );


    const toast =
        document.createElement(
            "div"
        );


    toast.className = "toast";

    toast.textContent = message;


    container.appendChild(
        toast
    );


    setTimeout(
        function() {

            toast.remove();

        },
        3500
    );

}


// ============================================================
// THEME
// ============================================================

function toggleTheme() {

    document.body.classList.toggle(
        "dark"
    );


    localStorage.setItem(
        "assignment_theme",
        document.body.classList.contains(
            "dark"
        )
        ? "dark"
        : "light"
    );

}


function loadTheme() {

    const theme =
        localStorage.getItem(
            "assignment_theme"
        );


    if (theme === "dark") {

        document.body.classList.add(
            "dark"
        );

    }

}


// ============================================================
// MODAL
// ============================================================

function openAddModal() {

    document.getElementById(
        "assignmentForm"
    ).reset();


    document.getElementById(
        "assignmentId"
    ).value = "";


    document.getElementById(
        "modalTitle"
    ).textContent =
        "Add Assignment";


    document.getElementById(
        "assignmentModal"
    ).classList.add(
        "active"
    );

}


function closeModal() {

    document.getElementById(
        "assignmentModal"
    ).classList.remove(
        "active"
    );

}


function openEditModal(id) {

    const assignment =
        assignments.find(
            item =>
                item.id === id
        );


    if (!assignment) {

        return;

    }


    document.getElementById(
        "assignmentId"
    ).value =
        assignment.id;


    document.getElementById(
        "title"
    ).value =
        assignment.title;


    document.getElementById(
        "subject"
    ).value =
        assignment.subject;


    document.getElementById(
        "description"
    ).value =
        assignment.description || "";


    document.getElementById(
        "priority"
    ).value =
        assignment.priority;


    document.getElementById(
        "reminder"
    ).value =
        assignment.reminder_minutes;


    document.getElementById(
        "deadline"
    ).value =
        assignment.deadline.replace(
            " ",
            "T"
        ).slice(
            0,
            16
        );


    document.getElementById(
        "modalTitle"
    ).textContent =
        "Edit Assignment";


    document.getElementById(
        "assignmentModal"
    ).classList.add(
        "active"
    );

}


// ============================================================
// SAVE ASSIGNMENT
// ============================================================

async function saveAssignment(event) {

    event.preventDefault();


    const id =
        document.getElementById(
            "assignmentId"
        ).value;


    const payload = {

        title:
            document.getElementById(
                "title"
            ).value.trim(),

        subject:
            document.getElementById(
                "subject"
            ).value.trim(),

        description:
            document.getElementById(
                "description"
            ).value.trim(),

        deadline:
            document.getElementById(
                "deadline"
            ).value,

        priority:
            document.getElementById(
                "priority"
            ).value,

        reminder_minutes:
            Number(
                document.getElementById(
                    "reminder"
                ).value
            )

    };


    const url =
        id
        ? `/api/assignments/${id}`
        : "/api/assignments";


    const method =
        id
        ? "PUT"
        : "POST";


    const response =
        await fetch(
            url,
            {

                method: method,

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body:
                    JSON.stringify(
                        payload
                    )

            }
        );


    const data =
        await response.json();


    if (!response.ok) {

        showToast(
            data.message ||
            "Something went wrong."
        );

        return;

    }


    closeModal();

    showToast(
        id
        ? "Assignment updated ✓"
        : "Assignment created ✓"
    );


    await loadAssignments();

    await loadStats();

}


// ============================================================
// LOAD ASSIGNMENTS
// ============================================================

async function loadAssignments() {

    const search =
        document.getElementById(
            "searchInput"
        ).value;


    const status =
        document.getElementById(
            "statusFilter"
        ).value;


    const priority =
        document.getElementById(
            "priorityFilter"
        ).value;


    const url =
        `/api/assignments?search=${encodeURIComponent(
            search
        )}&status=${encodeURIComponent(
            status
        )}&priority=${encodeURIComponent(
            priority
        )}`;


    const response =
        await fetch(url);


    assignments =
        await response.json();


    renderAssignments();

    renderUpcoming();

}


// ============================================================
// RENDER ASSIGNMENTS
// ============================================================

function renderAssignments() {

    const list =
        document.getElementById(
            "assignmentList"
        );


    if (
        assignments.length === 0
    ) {

        list.innerHTML = `

            <div class="empty">

                <div class="empty-icon">
                    📚
                </div>

                <h3>
                    No assignments found
                </h3>

                <p>
                    Add your first assignment to get started.
                </p>

            </div>

        `;

        return;

    }


    list.innerHTML =
        assignments.map(
            assignment =>
                assignmentHTML(
                    assignment
                )
        ).join("");


    updateCountdowns();

}


// ============================================================
// ASSIGNMENT HTML
// ============================================================

function assignmentHTML(
    assignment
) {

    const deadline =
        new Date(
            assignment.deadline.replace(
                " ",
                "T"
            )
        );


    const now =
        new Date();


    const overdue =
        assignment.status ===
            "Pending"
        &&
        deadline < now;


    const priorityClass =
        assignment.priority
            .toLowerCase();


    return `

        <div class="assignment
            ${assignment.status === "Completed"
                ? "completed"
                : ""}"
        >

            <div class="assignment-main">

                <div class="assignment-title">

                    ${escapeHtml(
                        assignment.title
                    )}

                </div>


                <div class="assignment-meta">

                    <span>
                        📘
                        ${escapeHtml(
                            assignment.subject
                        )}
                    </span>

                    <span>
                        •
                    </span>

                    <span>
                        📅
                        ${formatDate(
                            deadline
                        )}
                    </span>

                </div>


                ${
                    assignment.description
                    ?
                    `
                    <div
                        style="
                            margin-top:9px;
                            color:var(--muted);
                            font-size:13px;
                        "
                    >
                        ${escapeHtml(
                            assignment.description
                        )}
                    </div>
                    `
                    :
                    ""
                }


                <div class="badges">

                    <span
                        class="badge badge-${priorityClass}"
                    >
                        ${assignment.priority}
                    </span>


                    <span
                        class="badge badge-status"
                    >
                        ${assignment.status}
                    </span>


                    ${
                        overdue
                        ?
                        `
                        <span
                            class="badge badge-overdue"
                        >
                            Overdue
                        </span>
                        `
                        :
                        `
                        <span
                            class="badge"
                            style="
                                background:var(--bg);
                                color:var(--muted);
                            "
                        >
                            ⏰
                            ${reminderText(
                                assignment.reminder_minutes
                            )}
                        </span>
                        `
                    }


                    ${
                        assignment.status ===
                        "Pending"
                        &&
                        !overdue
                        ?
                        `
                        <span
                            class="countdown"
                            data-deadline="${assignment.deadline}"
                        >
                            ${countdownText(
                                deadline
                            )}
                        </span>
                        `
                        :
                        ""
                    }

                </div>

            </div>


            <div class="assignment-actions">

                ${
                    assignment.status ===
                    "Pending"
                    ?
                    `
                    <button
                        class="small-btn success"
                        onclick="completeAssignment(
                            ${assignment.id}
                        )"
                    >
                        ✓ Done
                    </button>
                    `
                    :
                    ""
                }


                <button
                    class="small-btn"
                    onclick="openEditModal(
                        ${assignment.id}
                    )"
                >
                    ✏ Edit
                </button>


                <button
                    class="small-btn danger"
                    onclick="deleteAssignment(
                        ${assignment.id}
                    )"
                >
                    🗑 Delete
                </button>

            </div>

        </div>

    `;

}


// ============================================================
// UPCOMING
// ============================================================

function renderUpcoming() {

    const container =
        document.getElementById(
            "upcomingList"
        );


    const upcoming =
        assignments
            .filter(
                assignment =>
                    assignment.status ===
                    "Pending"
            )
            .sort(
                (a, b) =>
                    new Date(
                        a.deadline
                    ) -
                    new Date(
                        b.deadline
                    )
            )
            .slice(
                0,
                6
            );


    if (
        upcoming.length === 0
    ) {

        container.innerHTML = `

            <div class="empty">

                <div>
                    ✅
                </div>

                <p style="margin-top:8px;">
                    No upcoming deadlines.
                </p>

            </div>

        `;

        return;

    }


    container.innerHTML =
        upcoming.map(
            assignment => {

                const date =
                    new Date(
                        assignment.deadline.replace(
                            " ",
                            "T"
                        )
                    );


                return `

                    <div class="upcoming-item">

                        <div class="date-box">

                            ${date.getDate()}

                        </div>


                        <div class="upcoming-info">

                            <div
                                class="upcoming-title"
                            >
                                ${escapeHtml(
                                    assignment.title
                                )}
                            </div>

                            <div
                                class="upcoming-time"
                            >
                                ${formatDate(
                                    date
                                )}
                            </div>

                        </div>

                    </div>

                `;

            }
        ).join("");

}


// ============================================================
// COMPLETE
// ============================================================

async function completeAssignment(
    id
) {

    const response =
        await fetch(
            `/api/assignments/${id}/complete`,
            {
                method: "PUT"
            }
        );


    const data =
        await response.json();


    if (!response.ok) {

        showToast(
            data.message ||
            "Unable to complete assignment."
        );

        return;

    }


    showToast(
        "Assignment completed ✓"
    );


    await loadAssignments();

    await loadStats();

}


// ============================================================
// DELETE
// ============================================================

async function deleteAssignment(
    id
) {

    const confirmed =
        confirm(
            "Delete this assignment?"
        );


    if (!confirmed) {

        return;

    }


    const response =
        await fetch(
            `/api/assignments/${id}`,
            {
                method: "DELETE"
            }
        );


    const data =
        await response.json();


    if (!response.ok) {

        showToast(
            data.message ||
            "Unable to delete assignment."
        );

        return;

    }


    localStorage.removeItem(
        "assignment_reminder_" + id
    );


    showToast(
        "Assignment deleted."
    );


    await loadAssignments();

    await loadStats();

}


// ============================================================
// STATISTICS
// ============================================================

async function loadStats() {

    const response =
        await fetch(
            "/api/stats"
        );


    const stats =
        await response.json();


    document.getElementById(
        "totalCount"
    ).textContent =
        stats.total;


    document.getElementById(
        "pendingCount"
    ).textContent =
        stats.pending;


    document.getElementById(
        "completedCount"
    ).textContent =
        stats.completed;


    document.getElementById(
        "overdueCount"
    ).textContent =
        stats.overdue;


    document.getElementById(
        "progressFill"
    ).style.width =
        stats.completion + "%";

}


// ============================================================
// REMINDER SYSTEM
// ============================================================

async function checkReminders() {

    if (
        !("Notification" in window)
    ) {

        return;

    }


    if (
        Notification.permission ===
        "default"
    ) {

        await Notification.requestPermission();

    }


    if (
        Notification.permission !==
        "granted"
    ) {

        return;

    }


    try {

        const response =
            await fetch(
                "/api/reminders"
            );


        if (!response.ok) {

            return;

        }


        const reminders =
            await response.json();


        reminders.forEach(
            reminder => {

                const key =
                    "assignment_reminder_" +
                    reminder.id +
                    "_" +
                    reminder.reminder_minutes;


                if (
                    localStorage.getItem(
                        key
                    )
                ) {

                    return;

                }


                let message;


                if (
                    reminder.minutes_left <= 0
                ) {

                    message =
                        `${reminder.title} is due now.`;

                }

                else if (
                    reminder.minutes_left < 60
                ) {

                    message =
                        `${reminder.title} is due in `
                        +
                        `${reminder.minutes_left} minutes.`;

                }

                else {

                    const hours =
                        Math.floor(
                            reminder.minutes_left /
                            60
                        );


                    const minutes =
                        reminder.minutes_left %
                        60;


                    message =
                        `${reminder.title} is due in `
                        +
                        `${hours} hour(s)`;


                    if (
                        minutes > 0
                    ) {

                        message +=
                            ` and ${minutes} minute(s)`;

                    }

                    message += ".";

                }


                new Notification(
                    "AssignmentFlow 🔔",
                    {

                        body:
                            message
                            +
                            `\nSubject: `
                            +
                            reminder.subject
                            +
                            `\nDeadline: `
                            +
                            reminder.deadline

                    }
                );


                localStorage.setItem(
                    key,
                    "true"
                );


                showToast(
                    "🔔 Reminder: " +
                    reminder.title
                );

            }
        );

    }

    catch (error) {

        console.error(
            "Reminder error:",
            error
        );

    }

}


// ============================================================
// COUNTDOWN
// ============================================================

function updateCountdowns() {

    document
        .querySelectorAll(
            "[data-deadline]"
        )
        .forEach(
            element => {

                const deadline =
                    new Date(
                        element.dataset.deadline
                            .replace(
                                " ",
                                "T"
                            )
                    );


                element.textContent =
                    countdownText(
                        deadline
                    );

            }
        );

}


function countdownText(
    deadline
) {

    const difference =
        deadline.getTime()
        -
        Date.now();


    if (
        difference <= 0
    ) {

        return "Due now";

    }


    const minutes =
        Math.floor(
            difference /
            60000
        );


    if (
        minutes < 60
    ) {

        return `${minutes}m left`;

    }


    const hours =
        Math.floor(
            minutes /
            60
        );


    const remainingMinutes =
        minutes %
        60;


    if (
        hours < 24
    ) {

        return (
            `${hours}h `
            +
            `${remainingMinutes}m left`
        );

    }


    const days =
        Math.floor(
            hours /
            24
        );


    return `${days}d left`;

}


// ============================================================
// FORMAT HELPERS
// ============================================================

function formatDate(
    date
) {

    return date.toLocaleString(
        [],
        {
            day: "2-digit",
            month: "short",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit"
        }
    );

}


function reminderText(
    minutes
) {

    if (
        minutes === 1440
    ) {

        return "1 day reminder";

    }

    if (
        minutes === 360
    ) {

        return "6 hour reminder";

    }

    if (
        minutes === 60
    ) {

        return "1 hour reminder";

    }

    return "30 minute reminder";

}


// ============================================================
// SECURITY HELPER FOR UI
// ============================================================

function escapeHtml(
    value
) {

    return String(
        value
    )
    .replace(
        /&/g,
        "&amp;"
    )
    .replace(
        /</g,
        "&lt;"
    )
    .replace(
        />/g,
        "&gt;"
    )
    .replace(
        /"/g,
        "&quot;"
    )
    .replace(
        /'/g,
        "&#039;"
    );

}


// ============================================================
// INITIALIZE
// ============================================================

loadTheme();

loadAssignments();

loadStats();

checkReminders();


// Refresh data every 30 seconds

setInterval(
    function() {

        checkReminders();

        loadAssignments();

        loadStats();

    },
    30000
);


// Update countdown every second

setInterval(
    updateCountdowns,
    1000
);


// Close modal when clicking outside

document
    .getElementById(
        "assignmentModal"
    )
    .addEventListener(
        "click",
        function(event) {

            if (
                event.target === this
            ) {

                closeModal();

            }

        }
    );


</script>

</body>

</html>
"""


# ============================================================
# LOGIN PAGE
# ============================================================

LOGIN_PAGE = """

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>Login - AssignmentFlow</title>

<style>

* {
    box-sizing: border-box;
}

body {

    margin: 0;

    min-height: 100vh;

    display: grid;

    place-items: center;

    font-family:
        Inter,
        system-ui,
        sans-serif;

    background:
        linear-gradient(
            135deg,
            #eef2ff,
            #f5f3ff
        );

}


.auth {

    width: min(
        420px,
        92%
    );

}


.brand {

    text-align: center;

    font-size: 27px;

    font-weight: 900;

    color: #20243a;

    margin-bottom: 25px;

}


.card {

    background: white;

    border: 1px solid #e5e7eb;

    border-radius: 22px;

    padding: 32px;

    box-shadow:
        0 25px 70px
        rgba(51,65,85,.13);

}


h1 {

    margin: 0;

    font-size: 25px;

}


.subtitle {

    color: #6b7280;

    margin-top: 7px;

}


label {

    display: block;

    margin-top: 20px;

    margin-bottom: 7px;

    font-size: 13px;

    font-weight: 800;

}


input {

    width: 100%;

    padding: 13px;

    border:
        1px solid #d1d5db;

    border-radius: 11px;

    font-size: 14px;

    outline: none;

}


input:focus {

    border-color: #6366f1;

}


button {

    width: 100%;

    margin-top: 24px;

    padding: 13px;

    border: none;

    border-radius: 11px;

    color: white;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );

    font-weight: 800;

    cursor: pointer;

}


.error {

    margin-top: 15px;

    background: #fee2e2;

    color: #991b1b;

    padding: 11px;

    border-radius: 10px;

    font-size: 13px;

}


.link {

    text-align: center;

    margin-top: 20px;

    color: #6b7280;

    font-size: 14px;

}


.link a {

    color: #6366f1;

    text-decoration: none;

    font-weight: 800;

}


</style>

</head>


<body>


<div class="auth">


    <div class="brand">
        ✓ AssignmentFlow
    </div>


    <div class="card">

        <h1>
            Welcome back
        </h1>

        <p class="subtitle">
            Sign in to manage your assignments.
        </p>


        {% if error %}

        <div class="error">
            {{ error }}
        </div>

        {% endif %}


        <form
            method="POST"
        >

            <label>
                Email
            </label>

            <input
                type="email"
                name="email"
                required
                autocomplete="email"
            >


            <label>
                Password
            </label>

            <input
                type="password"
                name="password"
                required
                autocomplete="current-password"
            >


            <button
                type="submit"
            >
                Login
            </button>

        </form>


        <div class="link">

            Don't have an account?

            <a href="/register">
                Create one
            </a>

        </div>

    </div>

</div>


</body>

</html>

"""


# ============================================================
# REGISTER PAGE
# ============================================================

REGISTER_PAGE = """

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>Register - AssignmentFlow</title>

<style>

* {
    box-sizing: border-box;
}

body {

    margin: 0;

    min-height: 100vh;

    display: grid;

    place-items: center;

    font-family:
        Inter,
        system-ui,
        sans-serif;

    background:
        linear-gradient(
            135deg,
            #eef2ff,
            #f5f3ff
        );

}


.auth {

    width: min(
        420px,
        92%
    );

}


.brand {

    text-align: center;

    font-size: 27px;

    font-weight: 900;

    color: #20243a;

    margin-bottom: 25px;

}


.card {

    background: white;

    border: 1px solid #e5e7eb;

    border-radius: 22px;

    padding: 32px;

    box-shadow:
        0 25px 70px
        rgba(51,65,85,.13);

}


h1 {

    margin: 0;

}


.subtitle {

    color: #6b7280;

    margin-top: 7px;

}


label {

    display: block;

    margin-top: 20px;

    margin-bottom: 7px;

    font-size: 13px;

    font-weight: 800;

}


input {

    width: 100%;

    padding: 13px;

    border:
        1px solid #d1d5db;

    border-radius: 11px;

    font-size: 14px;

    outline: none;

}


input:focus {

    border-color: #6366f1;

}


button {

    width: 100%;

    margin-top: 24px;

    padding: 13px;

    border: none;

    border-radius: 11px;

    color: white;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );

    font-weight: 800;

    cursor: pointer;

}


.error {

    margin-top: 15px;

    background: #fee2e2;

    color: #991b1b;

    padding: 11px;

    border-radius: 10px;

    font-size: 13px;

}


.link {

    text-align: center;

    margin-top: 20px;

    color: #6b7280;

    font-size: 14px;

}


.link a {

    color: #6366f1;

    text-decoration: none;

    font-weight: 800;

}


</style>

</head>


<body>


<div class="auth">


    <div class="brand">
        ✓ AssignmentFlow
    </div>


    <div class="card">

        <h1>
            Create your account
        </h1>

        <p class="subtitle">
            Start managing your academic deadlines.
        </p>


        {% if error %}

        <div class="error">
            {{ error }}
        </div>

        {% endif %}


        <form
            method="POST"
        >

            <label>
                Full Name
            </label>

            <input
                type="text"
                name="name"
                required
                autocomplete="name"
            >


            <label>
                Email
            </label>

            <input
                type="email"
                name="email"
                required
                autocomplete="email"
            >


            <label>
                Password
            </label>

            <input
                type="password"
                name="password"
                minlength="6"
                required
                autocomplete="new-password"
            >


            <button
                type="submit"
            >
                Create Account
            </button>

        </form>


        <div class="link">

            Already have an account?

            <a href="/login">
                Login
            </a>

        </div>

    </div>

</div>


</body>

</html>

"""


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
