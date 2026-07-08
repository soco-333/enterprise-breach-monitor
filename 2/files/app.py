from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
import sqlite3
import requests
import hashlib
import os
from datetime import datetime

import notifier

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-to-a-random-secret-in-production")

DB_PATH = "monitoring.db"
CHECK_INTERVAL_MINUTES = int(os.environ.get("CHECK_INTERVAL_MINUTES", "30"))


# ─────────────────────────────────────────────────────────────────────────────
# Database setup
# ─────────────────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT NOT NULL
        )""")

    cursor.execute("INSERT OR IGNORE INTO login (username, password, email) VALUES (?, ?, ?)",
                    ("sohan", generate_password_hash("1234"), "sohan@example.com"))

    conn.commit()
    conn.close()


def init_monitoring_db():
    conn = get_db()
    cursor = conn.cursor()

    # NOTE: we never store the raw password here — only a SHA-1 hash,
    # purely so a user can see "this credential was checked before"
    # without the DB itself becoming a breach.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS monitoring (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            checked_by TEXT,
            target_email TEXT,
            password_sha1 TEXT,
            email_breached INTEGER,
            email_breach_count INTEGER,
            password_breached INTEGER,
            password_breach_count INTEGER,
            risk_score INTEGER,
            risk_level TEXT,
            checked_at TEXT
        )
    """)

    conn.commit()
    conn.close()


def init_watchlist_db():
    conn = get_db()
    cursor = conn.cursor()

    # Passwords are NEVER stored here — only the full SHA-1 hash, which is
    # enough to keep re-running the k-Anonymity check against HIBP.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS watchlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            target_email TEXT,
            password_sha1 TEXT,
            notify_email TEXT,
            telegram_chat_id TEXT,
            whatsapp_number TEXT,
            channels TEXT,
            last_email_breach_count INTEGER DEFAULT 0,
            last_password_breached INTEGER DEFAULT 0,
            created_at TEXT,
            last_checked TEXT
        )
    """)

    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def opening():
    if session.get("username"):
        return redirect(url_for("dashboardfun"))
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM login WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user["password"], password):
        session["username"] = username
        return redirect(url_for("dashboardfun"))
    else:
        flash("Invalid username or password")
        return redirect(url_for("opening"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("opening"))


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard + breach checking
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/dashboard", methods=["GET", "POST"])
def dashboardfun():
    if not session.get("username"):
        return redirect(url_for("opening"))

    username = session["username"]
    result = None

    if request.method == "POST":
        target_email = request.form.get("email2", "").strip()
        password2 = request.form.get("password2", "")

        email_result = check_email_breach(target_email) if target_email else None
        password_result = check_password_breach(password2) if password2 else None

        risk_score, risk_level = calculate_risk(email_result, password_result)

        password_sha1 = hashlib.sha1(password2.encode()).hexdigest().upper() if password2 else None

        save_monitoring_record(
            checked_by=username,
            target_email=target_email,
            password_sha1=password_sha1,
            email_result=email_result,
            password_result=password_result,
            risk_score=risk_score,
            risk_level=risk_level,
        )

        result = {
            "email": target_email,
            "email_result": email_result,
            "password_result": password_result,
            "risk_score": risk_score,
            "risk_level": risk_level,
        }

    history = get_history(username)
    watchlist = get_watchlist(username)
    return render_template("dashboard.html", username=username, result=result, history=history, watchlist=watchlist)


def check_email_breach(email):
    """Query XposedOrNot for breaches tied to an email address."""
    try:
        url = f"https://api.xposedornot.com/v1/check-email/{email}"
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            data = response.json()
            # XposedOrNot nests the actual breach list under "breaches" -> [[...]]
            breaches = data.get("breaches", [[]])
            breach_list = breaches[0] if breaches else []
            return {
                "breached": bool(breach_list),
                "count": len(breach_list),
                "sources": breach_list,
            }
        elif response.status_code == 404:
            return {"breached": False, "count": 0, "sources": []}
        else:
            return {"breached": None, "count": 0, "sources": [], "error": f"HTTP {response.status_code}"}
    except Exception as e:
        print(f"ERROR checking email breach: {e}")
        return {"breached": None, "count": 0, "sources": [], "error": str(e)}


def check_password_breach(password2):
    """Hashes the password, then delegates to the hash-based checker.
    The raw password never leaves this function."""
    sha1 = hashlib.sha1(password2.encode()).hexdigest().upper()
    return check_password_breach_by_hash(sha1)


def check_password_breach_by_hash(sha1):
    """k-Anonymity check against Have I Been Pwned's Pwned Passwords API.
    Only the first 5 chars of the SHA-1 hash are ever sent over the network.
    Takes a full SHA-1 hash directly, so re-checks never need the raw password.
    """
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            hashes = response.text.splitlines()
            for line in hashes:
                h, count = line.split(":")
                if h == suffix:
                    return {"breached": True, "count": int(count)}
            return {"breached": False, "count": 0}
        else:
            return {"breached": None, "count": 0, "error": f"HTTP {response.status_code}"}
    except Exception as e:
        print(f"ERROR checking password breach: {e}")
        return {"breached": None, "count": 0, "error": str(e)}


def calculate_risk(email_result, password_result):
    """Simple weighted risk score, 0-100, from breach signals."""
    score = 0

    if email_result:
        if email_result.get("breached"):
            count = email_result.get("count", 0)
            score += 40 + min(count * 3, 30)  # up to +70
    if password_result:
        if password_result.get("breached"):
            count = password_result.get("count", 0)
            if count > 100000:
                score += 30
            elif count > 1000:
                score += 20
            else:
                score += 10

    score = min(score, 100)

    if score == 0:
        level = "Low"
    elif score < 40:
        level = "Moderate"
    elif score < 70:
        level = "High"
    else:
        level = "Critical"

    return score, level


def save_monitoring_record(checked_by, target_email, password_sha1, email_result, password_result, risk_score, risk_level):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO monitoring (
            checked_by, target_email, password_sha1,
            email_breached, email_breach_count,
            password_breached, password_breach_count,
            risk_score, risk_level, checked_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        checked_by,
        target_email,
        password_sha1,
        1 if email_result and email_result.get("breached") else 0,
        email_result.get("count", 0) if email_result else 0,
        1 if password_result and password_result.get("breached") else 0,
        password_result.get("count", 0) if password_result else 0,
        risk_score,
        risk_level,
        datetime.utcnow().isoformat(timespec="seconds"),
    ))
    conn.commit()
    conn.close()


def get_history(username, limit=20):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM monitoring
        WHERE checked_by = ?
        ORDER BY id DESC
        LIMIT ?
    """, (username, limit))
    rows = cursor.fetchall()
    conn.close()
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Continuous monitoring (watchlist)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/watchlist/add", methods=["POST"])
def add_watch():
    if not session.get("username"):
        return redirect(url_for("opening"))

    username = session["username"]
    target_email = request.form.get("watch_email", "").strip() or None
    password = request.form.get("watch_password", "")
    notify_email = request.form.get("notify_email", "").strip() or None
    telegram_chat_id = request.form.get("telegram_chat_id", "").strip() or None
    whatsapp_number = request.form.get("whatsapp_number", "").strip() or None

    channels = request.form.getlist("channels")  # e.g. ["email", "telegram"]

    if not target_email and not password:
        flash("Provide an email and/or password to monitor.")
        return redirect(url_for("dashboardfun"))

    if not channels or not any([notify_email, telegram_chat_id, whatsapp_number]):
        flash("Select at least one alert channel and provide its contact detail.")
        return redirect(url_for("dashboardfun"))

    password_sha1 = hashlib.sha1(password.encode()).hexdigest().upper() if password else None

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO watchlist (
            username, target_email, password_sha1,
            notify_email, telegram_chat_id, whatsapp_number, channels,
            last_email_breach_count, last_password_breached,
            created_at, last_checked
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?, NULL)
    """, (
        username, target_email, password_sha1,
        notify_email, telegram_chat_id, whatsapp_number, ",".join(channels),
        datetime.utcnow().isoformat(timespec="seconds"),
    ))
    conn.commit()
    conn.close()

    flash("Added to continuous monitoring.")
    return redirect(url_for("dashboardfun"))


@app.route("/watchlist/delete/<int:watch_id>", methods=["POST"])
def delete_watch(watch_id):
    if not session.get("username"):
        return redirect(url_for("opening"))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM watchlist WHERE id = ? AND username = ?", (watch_id, session["username"]))
    conn.commit()
    conn.close()

    return redirect(url_for("dashboardfun"))


def get_watchlist(username):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM watchlist WHERE username = ? ORDER BY id DESC", (username,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def run_watchlist_checks():
    """Called on a schedule. Re-checks every watched target and fires
    alerts for anything newly breached since the last check."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM watchlist")
    rows = cursor.fetchall()
    conn.close()

    for row in rows:
        alerts = []
        new_email_count = row["last_email_breach_count"]
        new_password_breached = row["last_password_breached"]

        if row["target_email"]:
            email_result = check_email_breach(row["target_email"])
            if email_result and email_result.get("breached"):
                count = email_result.get("count", 0)
                if count > row["last_email_breach_count"]:
                    alerts.append(f"New breach detected for {row['target_email']} "
                                  f"({count} total source(s), up from {row['last_email_breach_count']}).")
                new_email_count = count

        if row["password_sha1"]:
            password_result = check_password_breach_by_hash(row["password_sha1"])
            if password_result and password_result.get("breached") and not row["last_password_breached"]:
                alerts.append("A monitored password hash has newly appeared in a breach corpus. "
                               "Change this password immediately.")
                new_password_breached = 1

        if alerts:
            message = "BREACH MONITOR ALERT\n\n" + "\n".join(alerts)
            notifier.dispatch_alert(
                channels=row["channels"].split(",") if row["channels"] else [],
                message=message,
                notify_email=row["notify_email"],
                telegram_chat_id=row["telegram_chat_id"],
                whatsapp_number=row["whatsapp_number"],
            )

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE watchlist
            SET last_email_breach_count = ?, last_password_breached = ?, last_checked = ?
            WHERE id = ?
        """, (new_email_count, new_password_breached,
              datetime.utcnow().isoformat(timespec="seconds"), row["id"]))
        conn.commit()
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    init_monitoring_db()
    init_watchlist_db()

    scheduler = BackgroundScheduler()
    scheduler.add_job(run_watchlist_checks, "interval", minutes=CHECK_INTERVAL_MINUTES)
    scheduler.start()

    app.run(debug=True, use_reloader=False)  # reloader off so the scheduler doesn't start twice
