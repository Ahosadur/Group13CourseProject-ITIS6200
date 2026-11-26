import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from pathlib import Path

from flask import (
    Flask, abort, flash, jsonify, redirect, render_template_string,
    request, session, url_for
)
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerificationError, VerifyMismatchError


# ============================================================
# Configuration
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "data" / "users.db"

FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
ADMIN_ACCESS_KEY = os.environ.get("ADMIN_ACCESS_KEY")

# Generate temporary secrets for this application session.
# These values exist only while this Python process is running.

FLASK_SECRET_KEY = secrets.token_urlsafe(32)
ADMIN_ACCESS_KEY = secrets.token_urlsafe(24)

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # Local HTTP demonstration only
    PERMANENT_SESSION_LIFETIME=1800,
)

# Proposal baseline: Argon2id, Type.ID, m=19 MiB, t=2, p=1.
password_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
    type=Type.ID,
)

# Inactive-account migration policy
# Accounts still using MD5 after this deadline must reset their passwords.
migration_deadline = datetime(
    2026, 12, 24, 0, 0, 0, tzinfo=timezone.utc
    #2026, 11, 25, 0, 0, 0, tzinfo=timezone.utc
)

minimum_new_password_length = 12


def migration_deadline_passed():
    return datetime.now(timezone.utc) >= migration_deadline

# Authentication protection policy (tunable for the demonstration).
# Account: 8 failures in 10 minutes; IP: 20 failures in 5 minutes.
ACCOUNT_FAILURE_LIMIT = 8
ACCOUNT_WINDOW_SECONDS = 600
IP_FAILURE_LIMIT = 20
IP_WINDOW_SECONDS = 300
PROGRESSIVE_COOLDOWNS = (0, 0, 2, 4, 8, 16, 30)
ARGON2_MAX_CONCURRENT = 2
argon2_slots = threading.BoundedSemaphore(ARGON2_MAX_CONCURRENT)


# ============================================================
# Database and audit helpers
# ============================================================

def get_database_connection():
    if not DATABASE.exists():
        raise FileNotFoundError(f"Database not found: {DATABASE}")
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def format_eastern_time(value):
    """Convert a stored UTC timestamp to America/New_York for display."""
    if not value:
        return "Not migrated"

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

        # Treat timestamps without an offset as UTC.
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        eastern = parsed.astimezone(ZoneInfo("America/New_York"))

        return eastern.strftime("%b %d, %Y · %I:%M:%S %p %Z")

    except (ValueError, TypeError):
        return value


@app.template_filter("eastern_time")
def eastern_time_filter(value):
    return format_eastern_time(value)

def initialize_migration_events():
    """Additive initialization: does not modify or regenerate the user dataset."""
    connection = get_database_connection()
    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS migration_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                event_type TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_migration_events_event_id
            ON migration_events(event_id DESC)
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS auth_attempts (
                attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username_key TEXT NOT NULL,
                ip_key TEXT NOT NULL,
                succeeded INTEGER NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_auth_attempts_user_time
            ON auth_attempts(username_key, created_at DESC)
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_auth_attempts_ip_time
            ON auth_attempts(ip_key, created_at DESC)
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                event_type TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_events_event_id
            ON security_events(event_id DESC)
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS demo_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL, scenario TEXT NOT NULL, stage TEXT NOT NULL,
                username TEXT NOT NULL, source_ip TEXT NOT NULL,
                attempt_no INTEGER NOT NULL DEFAULT 0,
                attempts_total INTEGER NOT NULL DEFAULT 0,
                credential_label TEXT NOT NULL, outcome TEXT NOT NULL,
                detail TEXT NOT NULL, created_at TEXT NOT NULL
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_demo_events_event_id ON demo_events(event_id)")
        # Live-only audit stream: records real requests handled by Flask routes.
        # Unlike demo_events, this table is never populated with seeded history.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS live_security_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                username TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                attempt_no INTEGER NOT NULL DEFAULT 0,
                account_attempts INTEGER NOT NULL DEFAULT 0,
                ip_attempts INTEGER NOT NULL DEFAULT 0,
                credential_label TEXT NOT NULL DEFAULT '[REDACTED]',
                outcome TEXT NOT NULL,
                detail TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_live_security_events_id ON live_security_events(event_id)")
        connection.commit()
    finally:
        connection.close()


def insert_migration_event(connection, user_id, username, event_type, details):
    connection.execute("""
        INSERT INTO migration_events
            (user_id, username, event_type, details, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, username, event_type, details, utc_now()))


def record_migration_event(user_id, username, event_type, details):
    connection = get_database_connection()
    try:
        insert_migration_event(
            connection, user_id, username, event_type, details
        )
        connection.commit()
    finally:
        connection.close()


initialize_migration_events()


def get_user_by_username(username):
    connection = get_database_connection()
    try:
        return connection.execute("""
            SELECT user_id, username, password_hash,
                   hash_scheme, migration_status, migrated_at
            FROM users WHERE username = ?
        """, (username,)).fetchone()
    finally:
        connection.close()


def get_user_by_id(user_id):
    connection = get_database_connection()
    try:
        return connection.execute("""
            SELECT user_id, username, hash_scheme,
                   migration_status, migrated_at
            FROM users WHERE user_id = ?
        """, (user_id,)).fetchone()
    finally:
        connection.close()


# ============================================================
# Authentication protection and security audit helpers
# ============================================================

def keyed_identifier(value):
    # Avoid storing raw usernames/IP addresses in the rate-limit key table.
    return hmac.new(
        FLASK_SECRET_KEY.encode("utf-8"),
        value.encode("utf-8", errors="replace"),
        hashlib.sha256,
    ).hexdigest()


def client_ip():
    # Trust REMOTE_ADDR only. Do not trust X-Forwarded-For in this local app.
    return request.remote_addr or "unknown"


def record_security_event(username, event_type, details):
    connection = get_database_connection()
    try:
        connection.execute(
            """INSERT INTO security_events (username, event_type, details, created_at)
               VALUES (?, ?, ?, ?)""",
            (username[:100] or "(empty)", event_type, details, utc_now()),
        )
        connection.commit()
    finally:
        connection.close()


def record_demo_event(run_id, scenario, stage, username, source_ip,
                      attempt_no=0, attempts_total=0,
                      credential_label="[REDACTED]", outcome="INFO", detail=""):
    """Write structured demo telemetry for the separate read-only terminal monitor."""
    connection = get_database_connection()
    try:
        connection.execute(
            """INSERT INTO demo_events
               (run_id, scenario, stage, username, source_ip, attempt_no,
                attempts_total, credential_label, outcome, detail, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (run_id, scenario, stage, username[:100], source_ip[:100],
             int(attempt_no), int(attempts_total), credential_label[:40],
             outcome[:40], detail[:500], utc_now()),
        )
        connection.commit()
    finally:
        connection.close()


def record_live_security_event(event_type, username="(unknown)", source_ip="unknown",
                               attempt_no=0, account_attempts=0, ip_attempts=0,
                               outcome="INFO", detail=""):
    """Persist telemetry for an actual request processed by this Flask app.

    Password values are deliberately never accepted by this function.
    """
    connection = get_database_connection()
    try:
        connection.execute(
            """INSERT INTO live_security_events
               (event_type, username, source_ip, attempt_no, account_attempts,
                ip_attempts, credential_label, outcome, detail, created_at)
               VALUES (?, ?, ?, ?, ?, ?, '[REDACTED]', ?, ?, ?)""",
            (event_type[:60], (username or "(empty)")[:100], (source_ip or "unknown")[:100],
             int(attempt_no), int(account_attempts), int(ip_attempts),
             outcome[:40], detail[:500], utc_now()),
        )
        connection.commit()
    finally:
        connection.close()


def get_recent_failure_counts(username, ip_address):
    """Return real failed-attempt counts for the configured rolling windows."""
    now = time.time()
    user_key = keyed_identifier("user:" + username.strip().lower())
    ip_key = keyed_identifier("ip:" + ip_address)
    connection = get_database_connection()
    try:
        account_count = connection.execute(
            """SELECT COUNT(*) FROM auth_attempts
               WHERE username_key=? AND succeeded=0 AND created_at>=?""",
            (user_key, now - ACCOUNT_WINDOW_SECONDS),
        ).fetchone()[0]
        ip_count = connection.execute(
            """SELECT COUNT(*) FROM auth_attempts
               WHERE ip_key=? AND succeeded=0 AND created_at>=?""",
            (ip_key, now - IP_WINDOW_SECONDS),
        ).fetchone()[0]
    finally:
        connection.close()
    return account_count, ip_count


def get_rate_limit_state(username, ip_address):
    now = time.time()
    user_key = keyed_identifier("user:" + username.strip().lower())
    ip_key = keyed_identifier("ip:" + ip_address)

    connection = get_database_connection()
    try:
        user_rows = connection.execute(
            """SELECT created_at, succeeded FROM auth_attempts
               WHERE username_key=? AND created_at>=?
               ORDER BY created_at DESC""",
            (user_key, now - ACCOUNT_WINDOW_SECONDS),
        ).fetchall()
        ip_count = connection.execute(
            """SELECT COUNT(*) AS n FROM auth_attempts
               WHERE ip_key=? AND succeeded=0 AND created_at>=?""",
            (ip_key, now - IP_WINDOW_SECONDS),
        ).fetchone()["n"]
    finally:
        connection.close()

    # Count consecutive failures since the most recent successful login.
    failures = 0
    for attempt in user_rows:
        if attempt["succeeded"]:
            break
        failures += 1

    if failures >= ACCOUNT_FAILURE_LIMIT:
        oldest_counted_failure = user_rows[failures - 1]["created_at"]
        retry = max(1, int(ACCOUNT_WINDOW_SECONDS - (now - oldest_counted_failure)))
        return False, retry, "account_failure_limit"

    if ip_count >= IP_FAILURE_LIMIT:
        return False, IP_WINDOW_SECONDS, "ip_failure_limit"

    if failures:
        cooldown_index = min(failures - 1, len(PROGRESSIVE_COOLDOWNS) - 1)
        cooldown = PROGRESSIVE_COOLDOWNS[cooldown_index]
        last_failure_age = now - user_rows[0]["created_at"]
        if cooldown > last_failure_age:
            return False, max(1, int(cooldown - last_failure_age)), "progressive_delay"

    return True, 0, None


def record_auth_attempt(username, ip_address, succeeded):
    now = time.time()
    user_key = keyed_identifier("user:" + username.strip().lower())
    ip_key = keyed_identifier("ip:" + ip_address)
    connection = get_database_connection()
    try:
        connection.execute(
            """INSERT INTO auth_attempts
               (username_key, ip_key, succeeded, created_at)
               VALUES (?, ?, ?, ?)""",
            (user_key, ip_key, int(succeeded), now),
        )
        # Keep the demonstration database bounded.
        connection.execute(
            "DELETE FROM auth_attempts WHERE created_at < ?",
            (now - 86400,),
        )
        connection.commit()
    finally:
        connection.close()


def acquire_argon2_slot():
    return argon2_slots.acquire(blocking=False)


def release_argon2_slot():
    argon2_slots.release()


# ============================================================
# Password verification and rehash-on-next-login
# ============================================================

def verify_legacy_md5(password, stored_hash):
    candidate = hashlib.md5(password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(candidate, stored_hash)


def verify_argon2id(password, stored_hash):
    if not acquire_argon2_slot():
        raise RuntimeError("argon2_capacity")
    try:
        try:
            return password_hasher.verify(stored_hash, password)
        except (VerifyMismatchError, VerificationError):
            return False
    finally:
        release_argon2_slot()


def migrate_md5_account(user, password):
    """
    Upgrade only after successful MD5 verification.
    The conditional UPDATE protects against stale concurrent logins.
    The hash replacement and completion events commit in one transaction.
    """
    if not acquire_argon2_slot():
        raise RuntimeError("argon2_capacity")
    try:
        new_hash = password_hasher.hash(password)
    finally:
        release_argon2_slot()
    migrated_at = utc_now()

    connection = get_database_connection()
    try:
        cursor = connection.execute("""
            UPDATE users
               SET password_hash = ?,
                   hash_scheme = 'argon2id',
                   migration_status = 'migrated',
                   migrated_at = ?
             WHERE user_id = ?
               AND hash_scheme = 'md5'
               AND password_hash = ?
        """, (
            new_hash, migrated_at, user["user_id"], user["password_hash"]
        ))

        if cursor.rowcount == 1:
            insert_migration_event(
                connection, user["user_id"], user["username"],
                "argon2id_hash_generated",
                "A new Argon2id hash was generated from the submitted password."
            )
            insert_migration_event(
                connection, user["user_id"], user["username"],
                "legacy_hash_replaced",
                "The stored MD5 verifier was replaced; it was not retained."
            )
            insert_migration_event(
                connection, user["user_id"], user["username"],
                "migration_completed",
                "The account now uses direct Argon2id authentication."
            )
            connection.commit()
            return True
        connection.rollback()
    finally:
        connection.close()

    # A concurrent login may have won the conditional update.
    current = get_user_by_username(user["username"])
    if (
        current
        and current["hash_scheme"] == "argon2id"
        and verify_argon2id(password, current["password_hash"])
    ):
        return False
    return None


# def authenticate_user(username, password):
#     user = get_user_by_username(username)
#     if user is None:
#         return False, False

#     if user["hash_scheme"] == "md5":
#         if not verify_legacy_md5(password, user["password_hash"]):
#             return False, False

#         record_migration_event(
#             user["user_id"], user["username"], "legacy_md5_verified",
#             "The submitted password matched the legacy MD5 verifier."
#         )
#         result = migrate_md5_account(user, password)
#         if result is None:
#             return False, False
#         return True, result

#     if user["hash_scheme"] == "argon2id":
#         return verify_argon2id(password, user["password_hash"]), False

#     # Unknown schemes fail closed.
#     return False, False


def authenticate_user(username, password):
    user = get_user_by_username(username)

    if user is None:
        return False, False, False

    if user["hash_scheme"] == "md5":
        if not verify_legacy_md5(password, user["password_hash"]):
            return False, False, False

        record_migration_event(
            user["user_id"], user["username"], "legacy_md5_verified",
            "The submitted password matched the legacy MD5 verifier."
        )

        # After the deadline, require a password reset instead
        # of automatically migrating the old password.
        if migration_deadline_passed():
            record_migration_event(
                user["user_id"], user["username"],
                "forced_password_reset_required",
                "Legacy MD5 account authenticated after the migration deadline."
            )
            return True, False, True

        result = migrate_md5_account(user, password)

        if result is None:
            return False, False, False

        return True, result, False

    if user["hash_scheme"] == "argon2id":
        return verify_argon2id(password, user["password_hash"]), False, False

    # Unknown schemes fail closed.
    return False, False, False


# ============================================================
# Small presentation helpers
# ============================================================

def ensure_csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


def validate_csrf():
    supplied = request.form.get("_csrf", "")
    expected = session.get("_csrf", "")
    if not supplied or not expected or not hmac.compare_digest(supplied, expected):
        # The admin CSRF demonstration uses Flask's test client. Keep its
        # telemetry in demo_events only; never mislabel it as a real request.
        automated_test = bool(request.environ.get("PM_AUTOMATED_TEST", False))
        if not automated_test:
            try:
                record_security_event(
                    request.form.get("username", "(form)"),
                    "csrf_rejected",
                    f"Rejected {request.method} {request.path}: missing or invalid CSRF token."
                )
            except Exception:
                # CSRF rejection must still fail closed if audit storage is unavailable.
                pass
            try:
                record_live_security_event(
                    "csrf_rejected", request.form.get("username", "(form)"),
                    client_ip(), outcome="REJECTED",
                    detail=f"Real {request.method} {request.path} request rejected: missing or invalid CSRF token; HTTP 400."
                )
            except Exception:
                pass
        abort(400, description="Invalid form token. Refresh the page and try again.")


@app.context_processor
def inject_csrf():
    return {"csrf_token": ensure_csrf_token}


# ============================================================
# HTML: shared design system and user-facing pages
# ============================================================

LOGIN_PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure Migration | Sign in</title>
<style>
:root{--bg:#0b1220;--panel:#111c2e;--panel2:#17243a;--line:#26364f;--text:#edf3fc;--muted:#9aabc2;--blue:#67a6ff;--green:#50d6a0;--amber:#f4bd62}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(ellipse at 15% 5%,#18345b 0,transparent 38%),var(--bg);color:var(--text);font:15px/1.55 Inter,Segoe UI,Arial,sans-serif;display:grid;place-items:center;padding:28px}
.shell{width:min(1050px,100%);display:grid;grid-template-columns:1.05fr .95fr;border:1px solid var(--line);border-radius:22px;overflow:hidden;background:#101a2b;box-shadow:0 24px 80px #0007}
.story{padding:54px;background:linear-gradient(145deg,#132844,#101a2b 70%);display:flex;flex-direction:column;justify-content:space-between;min-height:590px}
.brand{display:flex;align-items:center;gap:12px;font-weight:750;letter-spacing:.08em;font-size:13px}.mark{width:38px;height:38px;border-radius:12px;background:#1c3c63;color:#9dc5ff;display:grid;place-items:center;font-size:20px}
h1{font-size:38px;line-height:1.12;letter-spacing:-.04em;margin:55px 0 18px}.lead{color:#b6c6dc;max-width:460px;font-size:16px}
.pill{display:inline-flex;align-items:center;gap:8px;border:1px solid #315276;border-radius:999px;padding:7px 11px;color:#bcd8ff;font-size:12px;width:max-content}
.dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 12px #50d6a0}
.story-foot{color:#8ea3bf;font-size:12px}
.form-side{padding:54px 48px;display:flex;flex-direction:column;justify-content:center}.eyebrow{color:var(--blue);font-size:11px;font-weight:800;letter-spacing:.16em;text-transform:uppercase}
h2{font-size:25px;margin:8px 0 5px}.sub{color:var(--muted);margin:0 0 28px}
label{display:block;color:#c7d4e6;font-size:13px;font-weight:650;margin:16px 0 7px}
input{width:100%;padding:14px 15px;border-radius:10px;border:1px solid #344762;background:#0c1626;color:white;font-size:15px;outline:none}
input:focus{border-color:var(--blue);box-shadow:0 0 0 3px #67a6ff22}
button,.button{border:0;border-radius:10px;padding:13px 18px;background:linear-gradient(100deg,#347ed7,#4b9aff);color:white;font-weight:750;cursor:pointer;text-decoration:none;display:inline-flex;justify-content:center;align-items:center}
button{width:100%;margin-top:22px}.admin-link{margin-top:12px;background:#1a2a40;border:1px solid #344762;color:#c9dcf5}
.notice{padding:12px 14px;border:1px solid #38516f;background:#172a43;border-radius:10px;margin:0 0 14px;color:#d6e7ff;font-size:13px}
.notice.error{border-color:#76434a;background:#351e29;color:#ffd9dd}
.small{color:#879bb5;font-size:12px;margin-top:24px}
@media(max-width:760px){.shell{grid-template-columns:1fr}.story{min-height:300px;padding:32px}.story h1{margin:35px 0 12px;font-size:30px}.form-side{padding:35px 28px}}
</style></head>
<body><main class="shell">
<section class="story">
<div><div class="brand"><span class="mark">⌑</span> PASSWORD SECURITY MIGRATION</div>
<h1>Modernizing authentication.<br><span style="color:#78b4ff">One login at a time.</span></h1>
<p class="lead">A controlled migration from legacy unsalted MD5 password verifiers to memory-hard Argon2id hashing, without forcing every active user through a simultaneous password reset.</p>
<div class="pill"><span class="dot"></span> LOCAL DEMONSTRATION ENVIRONMENT</div></div>
<div class="story-foot">Graduate Security Project · Group 13 · Argon2id baseline: m=19 MiB, t=2, p=1</div>
</section>
<section class="form-side">
<div class="eyebrow">User authentication</div><h2>Welcome back</h2>
<p class="sub">Sign in with your existing account credentials.</p>
{% for message in get_flashed_messages() %}<div class="notice">{{ message }}</div>{% endfor %}
<form method="post" action="{{ url_for('login') }}">
<input type="hidden" name="_csrf" value="{{ csrf_token() }}">
<label for="username">Username</label><input id="username" name="username" autocomplete="username" placeholder="e.g. user0001" required>
<label for="password">Password</label><input id="password" type="password" name="password" autocomplete="current-password" placeholder="Enter your password" required>
<button type="submit">Sign in securely →</button>
</form>
<a class="button admin-link" href="{{ url_for('admin_login') }}">Open administrator console</a>
<p class="small">The login process checks the account's current hash scheme. A successful legacy MD5 login triggers an automatic Argon2id upgrade.</p>
</section></main></body></html>
"""


RESET_PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Required Password Reset</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:#0b1220;color:#edf3fc;
font:15px/1.55 Segoe UI,Arial,sans-serif;display:grid;place-items:center;padding:24px}
.panel{width:min(460px,100%);background:#111c2e;border:1px solid #26364f;
border-radius:18px;padding:36px;box-shadow:0 20px 60px #0006}
h1{font-size:27px;margin:0 0 10px}
p{color:#9aabc2}
.notice{padding:12px;background:#351e29;border:1px solid #76434a;
border-radius:9px;color:#ffd9dd;margin:14px 0}
label{display:block;margin:18px 0 7px;color:#c7d4e6;font-weight:650}
input{width:100%;padding:13px;border-radius:9px;border:1px solid #344762;
background:#0c1626;color:white;font-size:15px}
button{width:100%;margin-top:22px;padding:14px;border:0;border-radius:9px;
background:#347ed7;color:white;font-weight:750;font-size:15px;cursor:pointer}
.small{font-size:12px;color:#879bb5;margin-top:18px}
</style>
</head>
<body>
<main class="panel">
<h1>Password reset required</h1>
<p>Your account still uses the legacy MD5 password system. The migration deadline has passed. Choose a new password to secure your account with Argon2id.</p>

{% for message in get_flashed_messages() %}
<div class="notice">{{ message }}</div>
{% endfor %}

<form method="post" action="{{ url_for('password_reset') }}">
<input type="hidden" name="_csrf" value="{{ csrf_token() }}">

<label for="new_password">New password</label>
<input id="new_password" type="password" name="new_password"
autocomplete="new-password" minlength="12" required>

<label for="confirm_password">Confirm new password</label>
<input id="confirm_password" type="password" name="confirm_password"
autocomplete="new-password" minlength="12" required>

<button type="submit">Reset password securely</button>
</form>

<p class="small">Your new password must contain at least 12 characters.</p>
</main>
</body>
</html>
"""


USER_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Account security status</title><style>
body{margin:0;background:#0b1220;color:#edf3fc;font:15px/1.55 Segoe UI,Arial,sans-serif;padding:32px}
.wrap{max-width:760px;margin:5vh auto}.panel{background:#111c2e;border:1px solid #293b55;border-radius:18px;padding:30px;box-shadow:0 20px 60px #0005}
.kicker{color:#78b4ff;text-transform:uppercase;letter-spacing:.15em;font-size:11px;font-weight:800}
h1{margin:8px 0;font-size:30px}.muted{color:#9aabc2}.status{margin:22px 0;padding:18px;border-radius:12px;background:#14263a;border:1px solid #315276}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.item{background:#0d1727;border:1px solid #293b55;border-radius:10px;padding:14px}.label{color:#91a6c1;font-size:12px}.value{font-size:17px;font-weight:750;margin-top:5px}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:24px}a,button{padding:11px 16px;border-radius:9px;background:#2f79d0;color:white;text-decoration:none;border:0;font-weight:700;cursor:pointer}.secondary{background:#1b2b42;border:1px solid #354b68}
@media(max-width:600px){.grid{grid-template-columns:1fr}}
</style></head><body><main class="wrap"><section class="panel">
<div class="kicker">Authentication result</div><h1>You're signed in, {{ user["username"] }}.</h1>
<p class="muted">{{ message }}</p>
<div class="status"><strong>Account security status</strong><div class="grid" style="margin-top:14px">
<div class="item"><div class="label">Current hash scheme</div><div class="value">{{ user["hash_scheme"] }}</div></div>
<div class="item"><div class="label">Migration status</div><div class="value">{{ user["migration_status"] }}</div></div>
<div class="item"><div class="label">Migration timestamp</div><div class="value" style="font-size:13px">
    {{ user["migrated_at"]|eastern_time }}
</div></div>
<div class="item"><div class="label">Authentication path</div><div class="value">{{ "Legacy → Argon2id upgrade" if migrated else "Direct Argon2id verification" }}</div></div>
</div></div>
<p class="muted">The application never displays or logs the submitted password or stored password hash.</p>
<div class="actions"><form method="post" action="{{ url_for('logout') }}"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><button>Sign out</button></form><a class="secondary" href="{{ url_for('index') }}">Home</a><a class="secondary" href="{{ url_for('admin_login') }}">Admin console</a></div>
</section></main></body></html>
"""


ADMIN_LOGIN_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin access</title><style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1220;color:#edf3fc;font:15px Segoe UI,Arial;padding:24px}
.card{width:min(440px,100%);padding:34px;background:#111c2e;border:1px solid #293b55;border-radius:18px}
.kicker{color:#78b4ff;font-size:11px;letter-spacing:.15em;font-weight:800}h1{margin:9px 0}p{color:#9aabc2;line-height:1.5}
input{width:100%;box-sizing:border-box;padding:13px;border-radius:9px;border:1px solid #344762;background:#0c1626;color:white;margin:10px 0 16px}
button,a{display:inline-block;padding:12px 16px;border:0;border-radius:9px;background:#347ed7;color:white;text-decoration:none;font-weight:700;cursor:pointer}
a{background:#1a2a40;border:1px solid #344762;margin-left:7px}.notice{padding:10px;background:#351e29;border:1px solid #76434a;border-radius:8px;color:#ffd9dd}
</style></head><body><section class="card"><div class="kicker">RESTRICTED CONSOLE</div><h1>Administrator access</h1>
<p>Enter the local demonstration administrator key to view migration operations and account metadata.</p>
{% for message in get_flashed_messages() %}<div class="notice">{{ message }}</div>{% endfor %}
<form method="post" action="{{ url_for('admin_login') }}"><input type="hidden" name="_csrf" value="{{ csrf_token() }}">
<label for="admin_key">Administrator key</label><input id="admin_key" type="password" name="admin_key" required autocomplete="current-password">
<button type="submit">Unlock console</button><a href="{{ url_for('index') }}">Back to login</a></form></section></body></html>
"""


ADMIN_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Migration Operations Center</title>
<style>
:root{--bg:#0a1220;--surface:#111d30;--surface2:#16253a;--line:#293d59;--text:#edf3fc;--muted:#91a5bf;--blue:#70adff;--green:#4ed6a0;--amber:#f4bd62;--red:#ff7885}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 Inter,Segoe UI,Arial,sans-serif}
.topbar{height:70px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 max(24px,calc((100% - 1280px)/2));background:#0d1727;position:sticky;top:0;z-index:5}
.brand{font-weight:800;letter-spacing:.07em;display:flex;gap:11px;align-items:center}.mark{width:34px;height:34px;border-radius:10px;background:#1c3b61;color:#9dc8ff;display:grid;place-items:center;font-size:18px}
.top-actions{display:flex;gap:10px;align-items:center}.top-actions a,.top-actions button{background:#1a2b43;color:#d8e8ff;border:1px solid #354b68;padding:9px 13px;border-radius:8px;text-decoration:none;font-weight:650;cursor:pointer}
main{max-width:1280px;margin:30px auto;padding:0 24px}.heading{display:flex;justify-content:space-between;align-items:flex-end;gap:20px;margin-bottom:24px}
.kicker{font-size:10px;color:var(--blue);font-weight:850;letter-spacing:.18em;text-transform:uppercase}
h1{font-size:30px;letter-spacing:-.035em;margin:5px 0}.sub{color:var(--muted);margin:0}
.live{display:flex;align-items:center;gap:8px;color:#a8c0d9;font-size:12px}.live-dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 12px #4ed6a0}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:20px 0}
.card,.panel{background:var(--surface);border:1px solid var(--line);border-radius:14px}
.card{padding:19px}.card-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.09em;font-weight:750}
.card-value{font-size:30px;font-weight:800;letter-spacing:-.04em;margin:8px 0 2px}.card-note{font-size:11px;color:var(--muted)}
.blue{color:var(--blue)}.green{color:var(--green)}.amber{color:var(--amber)}
.panel{padding:21px;margin-top:16px}.panel-head{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:16px}
h2{font-size:16px;margin:0}.hint{font-size:11px;color:var(--muted)}
.progress-track{height:12px;border-radius:99px;background:#26364d;overflow:hidden}.progress-fill{height:100%;background:linear-gradient(90deg,#3989e8,#4ed6a0);border-radius:99px;transition:width .4s}
.progress-meta{display:flex;justify-content:space-between;color:var(--muted);font-size:12px;margin-top:9px}
.layout{display:grid;grid-template-columns:1.15fr .85fr;gap:16px}
.search{display:flex;gap:9px;max-width:600px}.search input,.filter{background:#0c1727;border:1px solid #354a66;border-radius:8px;padding:11px 12px;color:var(--text);outline:none}
.search input{flex:1;min-width:0}.search input:focus,.filter:focus{border-color:var(--blue)}
button.primary{border:0;background:#347ed7;color:white;padding:11px 15px;border-radius:8px;font-weight:750;cursor:pointer}
.account-result{margin-top:15px;padding:15px;background:#0c1727;border:1px solid var(--line);border-radius:10px}
.result-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}.result-cell{padding:10px;background:#142238;border-radius:8px}.result-label{font-size:10px;color:var(--muted);text-transform:uppercase}.result-value{font-size:13px;font-weight:750;margin-top:3px;overflow-wrap:anywhere}
.badge{display:inline-flex;padding:4px 8px;border-radius:99px;font-size:10px;font-weight:800;letter-spacing:.03em}
.badge.md5{background:#4a351d;color:#ffd28a}.badge.argon{background:#123e35;color:#7df0c0}.badge.neutral{background:#27364b;color:#c4d2e4}
.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:570px}th,td{text-align:left;padding:11px 10px;border-bottom:1px solid #26384f;font-size:12px;vertical-align:top}
th{color:#91a5bf;font-size:10px;text-transform:uppercase;letter-spacing:.08em;font-weight:800}td{color:#d6e1ef}
.event{font-weight:750;color:#9cc6ff}.empty{padding:22px;color:var(--muted);text-align:center}
.footer{color:#7388a4;font-size:11px;text-align:center;padding:25px}
.statusline{font-size:11px;color:var(--muted)}.error{color:#ff9ba4}

.event-tabs{display:flex;gap:9px;border-bottom:1px solid var(--line);margin:4px 0 12px;padding-bottom:10px;flex-wrap:wrap}
.event-tab{display:inline-flex;align-items:center;gap:9px;background:#0c1727;border:1px solid #354a66;color:#b9cbe0;padding:10px 15px;border-radius:9px;font-weight:750;cursor:pointer}
.event-tab:hover{border-color:#70adff;color:#edf3fc}
.event-tab.active{background:#1b3859;border-color:#5799e8;color:#fff;box-shadow:inset 0 0 0 1px #5799e833}
.tab-count{display:inline-grid;place-items:center;min-width:23px;height:21px;padding:0 6px;border-radius:99px;background:#263b56;color:#cfe3ff;font-size:10px}
.event-tab-caption{font-size:11px;color:var(--muted);margin:0 0 8px}
.event-kind{display:inline-flex;padding:4px 8px;border-radius:7px;background:#1b3452;color:#a9d0ff;font-weight:800;font-size:11px}
.event-kind.automated{background:#3a2d1b;color:#ffd28a}
.event-outcome{font-weight:800}.event-outcome.pass,.event-outcome.success{color:var(--green)}.event-outcome.fail,.event-outcome.blocked,.event-outcome.rejected{color:#ff9ba4}
@media(max-width:900px){.cards{grid-template-columns:repeat(2,1fr)}.layout{grid-template-columns:1fr}}
@media(max-width:560px){.heading{display:block}.live{margin-top:14px}.cards{grid-template-columns:1fr 1fr}.card{padding:14px}.card-value{font-size:25px}.topbar{padding:0 14px}.top-actions a{font-size:11px;padding:8px}}
</style></head>
<body>
<header class="topbar"><div class="brand"><span class="mark">⌑</span> MIGRATION OPERATIONS CENTER</div>
<div class="top-actions"><a href="{{ url_for('index') }}">User login</a>
<form method="post" action="{{ url_for('admin_logout') }}" style="margin:0"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><button>Lock console</button></form></div></header>
<main>
<section class="heading"><div><div class="kicker">Password security · Group 13</div><h1>Migration overview</h1><p class="sub">Operational view of the legacy-to-modern password migration.</p></div>
<div class="live"><span class="live-dot"></span><span id="live-status">Connected · live updates enabled</span></div></section>

<section class="cards">
<div class="card"><div class="card-label">Total accounts</div><div class="card-value" id="total-count">—</div><div class="card-note">Accounts in the inherited database</div></div>
<div class="card"><div class="card-label">Legacy MD5</div><div class="card-value amber" id="md5-count">—</div><div class="card-note">Still require successful login migration</div></div>
<div class="card"><div class="card-label">Argon2id</div><div class="card-value green" id="argon-count">—</div><div class="card-note">Direct modern password verifiers</div></div>
<div class="card"><div class="card-label">Migration progress</div><div class="card-value blue" id="progress-value">—</div><div class="card-note" id="progress-count">Calculating migration coverage</div></div>
</section>

<section class="panel"><div class="panel-head"><h2>Overall migration progress</h2><span class="hint" id="updated-at">Waiting for first update</span></div>
<div class="progress-track"><div class="progress-fill" id="progress-bar" style="width:0%"></div></div>
<div class="progress-meta"><span id="remaining-label">Legacy accounts remaining</span><strong id="coverage-label">0%</strong></div></section>

<div class="layout">
<section class="panel"><div class="panel-head"><h2>Account inspection</h2><span class="hint">Read-only · no hashes exposed</span></div>
<form class="search" id="account-search"><input id="username-input" type="search" placeholder="Search username, e.g. user0001" autocomplete="off"><button class="primary" type="submit">Inspect</button></form>
<div id="account-result" class="account-result" style="display:none"></div>
<div id="account-error" class="statusline" style="margin-top:10px" aria-live="polite"></div>
</section>
<section class="panel"><div class="panel-head"><h2>Migration design</h2><span class="badge neutral">Proposal baseline</span></div>
<div class="result-grid">
<div class="result-cell"><div class="result-label">Legacy verifier</div><div class="result-value">Unsalted MD5</div></div>
<div class="result-cell"><div class="result-label">Target verifier</div><div class="result-value green">Argon2id</div></div>
<div class="result-cell"><div class="result-label">Memory cost</div><div class="result-value">19 MiB</div></div>
<div class="result-cell"><div class="result-label">Time / parallelism</div><div class="result-value">t=2 · p=1</div></div>
</div><p class="hint" style="margin:14px 0 0">A successful legacy login triggers an immediate hash replacement. Subsequent logins verify Argon2id directly.</p>
</section></div>

<section class="panel"><div class="panel-head"><h2>Recent migration activity</h2><span class="hint">Persisted SQLite events · updates every 3 seconds</span></div>
<div class="table-wrap"><table><thead><tr><th>Time (Eastern)</th><th>Source</th><th>Account</th><th>Event</th><th>Details</th></tr></thead><tbody id="events-body"><tr><td colspan="4" class="empty">Loading migration activity…</td></tr></tbody></table></div>
</section>


<section class="panel" id="security-demo">
  <div class="panel-head">
    <h2>Security Demonstration Lab</h2>
    <span class="badge neutral">Admin-only · isolated tests</span>
  </div>
  <p class="hint">Run the existing protection checks without changing user password hashes or using your normal browser IP for the test traffic. Demo rate-limit records are removed after each run.</p>
  <div class="demo-grid">
    <button class="demo-button" data-test="progressive">Test progressive delay</button>
    <button class="demo-button" data-test="account">Test account throttling</button>
    <button class="demo-button" data-test="ip">Test IP throttling</button>
    <button class="demo-button" data-test="csrf">Test CSRF rejection</button>
    <button class="demo-button" data-test="argon">Test Argon2 capacity</button>
    <button class="demo-button" data-test="all">Run all tests</button>
  </div>
  <div id="demo-status" class="statusline" aria-live="polite">Ready. Select a test to begin.</div>
  <div id="demo-results" class="demo-results"></div>
</section>
<style>
.demo-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:10px;margin:16px 0}
.demo-button{width:100%;margin:0;background:#1a2b43;border:1px solid #354b68;color:#d8e8ff;padding:12px;border-radius:9px;font-weight:700;cursor:pointer}
.demo-button:hover{border-color:#70adff;background:#203957}
.demo-button:disabled{opacity:.55;cursor:wait}
.demo-results{display:grid;gap:9px;margin-top:12px}
.demo-result{padding:12px 14px;border:1px solid #293d59;border-radius:9px;background:#0d1829}
.demo-result.pass{border-color:#27664f}.demo-result.fail{border-color:#8a414b}
.demo-result strong{display:block;margin-bottom:4px}.demo-result small{color:#91a5bf}
</style>

<section class="panel" id="security-events-panel">
  <div class="panel-head"><h2>Authentication security events</h2><span class="hint">Manual activity and automated security checks</span></div>
  <div class="event-tabs" role="tablist" aria-label="Security event source">
    <button class="event-tab active" id="manual-tab" type="button" role="tab" aria-selected="true" aria-controls="manual-events-panel" data-source="manual">
      Manual tests <span class="tab-count" id="manual-count">—</span>
    </button>
    <button class="event-tab" id="automated-tab" type="button" role="tab" aria-selected="false" aria-controls="automated-events-panel" data-source="automated">
      Automated tests <span class="tab-count" id="automated-count">—</span>
    </button>
  </div>
  <div class="event-tab-caption" id="event-tab-caption">Real browser and DevTools requests handled by Flask.</div>
  <div class="table-wrap"><table><thead><tr><th>Time (Eastern)</th><th>Account</th><th>Test / Event</th><th>Result and details</th></tr></thead>
    <tbody id="security-events-body"><tr><td colspan="4" class="empty">Loading security events…</td></tr></tbody></table></div>
</section>
<div class="footer">Sensitive credentials and password hashes are never displayed. Local academic demonstration build — not production deployment.</div>
</main>
<script>
const DEMO_CSRF = {{ csrf_token()|tojson }};
const byId = (id) => document.getElementById(id);
async function runDemo(testName) {
    const buttons = [...document.querySelectorAll(".demo-button")];
    buttons.forEach(button => button.disabled = true);
    byId("demo-status").textContent = "Running " + testName + " test…";
    try {
        const body = new URLSearchParams({_csrf: DEMO_CSRF, test: testName});
        const response = await fetch("{{ url_for('admin_api_demo') }}", {
            method: "POST",
            headers: {"Content-Type":"application/x-www-form-urlencoded"},
            credentials: "same-origin",
            body
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || ("HTTP " + response.status));
        const results = testName === "all" ? data.results : [data.result];
        for (const result of results) {
            const item = document.createElement("div");
            item.className = "demo-result " + (result.passed ? "pass" : "fail");
            const title = document.createElement("strong");
            title.textContent = (result.passed ? "PASS · " : "CHECK · ") + result.title;
            const detail = document.createElement("div");
            detail.textContent = result.detail;
            const note = document.createElement("small");
            note.textContent = result.note || "";
            item.append(title, detail, note);
            byId("demo-results").prepend(item);
        }
        byId("demo-status").textContent = data.summary;
        refreshOverview(); refreshEvents(); refreshSecurityEvents();
    } catch (error) {
        byId("demo-status").textContent = "Demo request failed: " + error.message;
    } finally {
        buttons.forEach(button => button.disabled = false);
    }
}
document.querySelectorAll(".demo-button").forEach(button => {
    button.addEventListener("click", () => runDemo(button.dataset.test));
});

function safeText(value) { return String(value ?? ""); }
function formatEasternTime(value) {
    if (!value) return "Not migrated";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return String(value);
    }

    return new Intl.DateTimeFormat("en-US", {
        timeZone: "America/New_York",
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: true,
        timeZoneName: "short"
    }).format(date);
}
function renderEvents(events) {
  const body = byId("events-body");
  if (!events.length) {
    body.innerHTML = '<tr><td colspan="4" class="empty">No migration events recorded yet.</td></tr>';
    return;
  }
  body.replaceChildren();
  for (const event of events) {
    const row = document.createElement("tr");
    for (const value of [
    formatEasternTime(event.created_at),
    event.username,
    event.event_type,
    event.details
]) {
      const cell = document.createElement("td");
      cell.textContent = safeText(value);
      if (value === event.event_type) cell.className = "event";
      row.appendChild(cell);
    }
    body.appendChild(row);
  }
}
async function refreshOverview() {
  try {
    const response = await fetch("{{ url_for('admin_api_overview') }}", {cache:"no-store"});
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    byId("total-count").textContent = data.total.toLocaleString();
    byId("md5-count").textContent = data.md5_count.toLocaleString();
    byId("argon-count").textContent = data.argon_count.toLocaleString();
    byId("progress-value").textContent = data.progress.toFixed(2) + "%";
    byId("progress-count").textContent = data.argon_count.toLocaleString() + " of " + data.total.toLocaleString() + " accounts migrated";
    byId("progress-bar").style.width = Math.min(100, data.progress) + "%";
    byId("coverage-label").textContent = data.progress.toFixed(2) + "% complete";
    byId("remaining-label").textContent = data.md5_count.toLocaleString() + " legacy accounts remaining";
    byId("updated-at").textContent = "Updated " + new Date().toLocaleTimeString();
    byId("live-status").textContent = "Connected · live updates enabled";
  } catch (error) {
    byId("live-status").textContent = "Update unavailable — retrying";
  }
}
async function refreshEvents() {
  try {
    const response = await fetch("{{ url_for('admin_api_events') }}", {cache:"no-store"});
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    renderEvents(data.events);
  } catch (error) {
    byId("events-body").innerHTML = '<tr><td colspan="4" class="empty">Unable to load events. Retrying…</td></tr>';
  }
}
let activeSecuritySource = "manual";
const eventTabDescriptions = {
  manual: "Real browser and DevTools requests handled by Flask. No dashboard-generated test data.",
  automated: "Isolated Security Demonstration Lab results. These are automated checks, not real user requests."
};
function setSecurityTab(source) {
  activeSecuritySource = source;
  document.querySelectorAll(".event-tab").forEach(tab => {
    const selected = tab.dataset.source === source;
    tab.classList.toggle("active", selected);
    tab.setAttribute("aria-selected", selected ? "true" : "false");
  });
  byId("event-tab-caption").textContent = eventTabDescriptions[source];
  refreshSecurityEvents();
}
document.querySelectorAll(".event-tab").forEach(tab => {
  tab.addEventListener("click", () => setSecurityTab(tab.dataset.source));
});
async function refreshSecurityEvents() {
  try {
    const response = await fetch("{{ url_for('admin_api_security_events') }}?source=" + encodeURIComponent(activeSecuritySource), {cache:"no-store"});
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    byId("manual-count").textContent = data.counts?.manual ?? "—";
    byId("automated-count").textContent = data.counts?.automated ?? "—";
    const body = byId("security-events-body");
    body.replaceChildren();
    if (!data.events.length) {
      const row = document.createElement("tr");
      const cell = document.createElement("td");
      cell.colSpan = 4; cell.className = "empty";
      cell.textContent = activeSecuritySource === "manual" ? "No manual browser or DevTools events recorded yet." : "No automated test events recorded yet.";
      row.appendChild(cell); body.appendChild(row); return;
    }
    for (const event of data.events) {
      const row = document.createElement("tr");
      const values = [formatEasternTime(event.created_at), event.username, event.event_type, event.details];
      values.forEach((value, index) => {
        const cell = document.createElement("td");
        if (index === 2) {
          const label = document.createElement("span");
          label.className = "event-kind" + (activeSecuritySource === "automated" ? " automated" : "");
          label.textContent = safeText(value);
          cell.appendChild(label);
        } else if (index === 3) {
          cell.textContent = safeText(value);
          if (event.outcome) {
            const result = document.createElement("span");
            result.className = "event-outcome " + String(event.outcome).toLowerCase();
            result.textContent = "  ·  " + String(event.outcome).toUpperCase();
            cell.appendChild(result);
          }
        } else {
          cell.textContent = safeText(value);
        }
        row.appendChild(cell);
      });
      body.appendChild(row);
    }
  } catch (error) {
    byId("security-events-body").innerHTML = '<tr><td colspan="4" class="empty">Unable to load security events. Retrying…</td></tr>';
  }
}

byId("account-search").addEventListener("submit", async (event) => {
  event.preventDefault();
  const username = byId("username-input").value.trim();
  byId("account-error").textContent = "";
  byId("account-result").style.display = "none";
  if (!username) { byId("account-error").textContent = "Enter a username to inspect."; return; }
  try {
    const response = await fetch("{{ url_for('admin_api_account') }}?username=" + encodeURIComponent(username), {cache:"no-store"});
    const data = await response.json();
    if (!response.ok || !data.account) { byId("account-error").textContent = "No matching account found."; return; }
    const a = data.account;
    const schemeClass = a.hash_scheme === "argon2id" ? "argon" : "md5";
    byId("account-result").innerHTML = `
      <div class="panel-head"><strong>${escapeHtml(a.username)}</strong><span class="badge ${schemeClass}">${escapeHtml(a.hash_scheme)}</span></div>
      <div class="result-grid">
        <div class="result-cell"><div class="result-label">User ID</div><div class="result-value">${escapeHtml(a.user_id)}</div></div>
        <div class="result-cell"><div class="result-label">Migration status</div><div class="result-value">${escapeHtml(a.migration_status)}</div></div>
        <div class="result-cell"><div class="result-label">Migration timestamp</div><div class="result-value">${escapeHtml(formatEasternTime(a.migrated_at))}</div></div>
        <div class="result-cell"><div class="result-label">Current state</div><div class="result-value">${a.hash_scheme === "argon2id" ? "Modern verifier active" : "Legacy verifier — migrates on successful login"}</div></div>
      </div>`;
    byId("account-result").style.display = "block";
  } catch (error) {
    byId("account-error").textContent = "Account lookup failed. Please retry.";
  }
});
function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
}
refreshOverview(); refreshEvents(); refreshSecurityEvents();
setInterval(refreshOverview, 3000);
setInterval(refreshEvents, 3000);
setInterval(refreshSecurityEvents, 3000);
</script></body></html>
"""


# ============================================================
# User routes
# ============================================================

@app.route("/", methods=["GET"])
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template_string(LOGIN_PAGE)


@app.route("/login", methods=["POST"])
def login():
    validate_csrf()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        record_live_security_event(
            "login_incomplete", username or "(empty)", client_ip(),
            outcome="REJECTED", detail="Actual login POST did not include both username and password."
        )
        flash("Please enter both username and password.")
        return redirect(url_for("index"))

    ip_address = client_ip()
    allowed, retry_after, reason = get_rate_limit_state(username, ip_address)
    if not allowed:
        record_security_event(
            username, "login_throttled",
            f"Protection={reason}; retry_after_seconds={retry_after}; source={ip_address}"
        )
        account_count, ip_count = get_recent_failure_counts(username, ip_address)
        record_live_security_event(
            "login_throttled", username, ip_address,
            attempt_no=max(account_count, ip_count) + 1,
            account_attempts=account_count, ip_attempts=ip_count,
            outcome="BLOCKED",
            detail=f"Actual login POST blocked by {reason}; retry_after={retry_after}s."
        )
        response = redirect(url_for("index"))
        response.headers["Retry-After"] = str(retry_after)
        flash(f"Too many attempts or a progressive delay is active. Try again in about {retry_after} seconds.")
        return response

    try:
        #authenticated, migrated = authenticate_user(username, password)
        authenticated, migrated, reset_required = authenticate_user(username, password)
    except RuntimeError as exc:
        if str(exc) == "argon2_capacity":
            record_security_event(
                username, "argon2_capacity_rejected",
                f"Concurrent Argon2id limit ({ARGON2_MAX_CONCURRENT}) reached; request rejected before verification."
            )
            record_live_security_event(
                "argon2_capacity_rejected", username, ip_address,
                outcome="REJECTED", detail=f"Actual login request rejected: all {ARGON2_MAX_CONCURRENT} Argon2 slots are occupied."
            )
            response = redirect(url_for("index"))
            response.status_code = 503
            flash("Authentication is temporarily busy. Please retry shortly.")
            return response
        raise
    except sqlite3.Error:
        app.logger.exception("Database error during authentication.")
        flash("Authentication could not be completed. Please retry.")
        return redirect(url_for("index"))

    record_auth_attempt(username, ip_address, authenticated)
    account_count, ip_count = get_recent_failure_counts(username, ip_address)
    record_live_security_event(
        "login_success" if authenticated else "login_failed",
        username, ip_address,
        attempt_no=max(account_count, ip_count),
        account_attempts=account_count, ip_attempts=ip_count,
        outcome="SUCCESS" if authenticated else "FAILED",
        detail=("Actual login POST authenticated successfully." if authenticated
                else "Actual login POST rejected: username/password combination did not authenticate.")
    )
    if not authenticated:
        record_security_event(
            username, "login_failed",
            f"Invalid credentials; source={ip_address}"
        )
        flash("Invalid username or password.")
        return redirect(url_for("index"))

    record_security_event(
        username, "login_success",
        f"Authentication succeeded; source={ip_address}; migrated={bool(migrated)}"
    )
    user = get_user_by_username(username)
    if user is None:
        flash("Account state could not be loaded.")
        return redirect(url_for("index"))

    session.clear()
    session.permanent = True

    if reset_required:
        session["password_reset_user_id"] = user["user_id"]
        session["password_reset_username"] = user["username"]
        return redirect(url_for("password_reset"))

    session["user_id"] = user["user_id"]
    session["username"] = user["username"]
    session["login_migrated"] = bool(migrated)

    return redirect(url_for("dashboard"))


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("index"))
    user = get_user_by_id(session["user_id"])
    if user is None:
        session.clear()
        return redirect(url_for("index"))
    migrated = bool(session.pop("login_migrated", False))
    message = (
        "Your legacy password was verified and upgraded to Argon2id during this login."
        if migrated else
        "Your credentials were verified directly using the account's Argon2id verifier."
    )
    return render_template_string(
        USER_PAGE, user=user, migrated=migrated, message=message
    )



@app.route("/reset-password", methods=["GET", "POST"])
def password_reset():
    # Only users who authenticated with an expired MD5 account may reset here.
    user_id = session.get("password_reset_user_id")
    username = session.get("password_reset_username")

    if not user_id or not username:
        return redirect(url_for("index"))

    user = get_user_by_username(username)

    # Refuse stale reset sessions or accounts that are no longer MD5.
    if not user or user["user_id"] != user_id or user["hash_scheme"] != "md5":
        session.clear()
        flash("Please sign in again to continue.")
        return redirect(url_for("index"))

    if request.method == "GET":
        return render_template_string(RESET_PAGE)

    validate_csrf()

    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if len(new_password) < minimum_new_password_length:
        flash("Your new password must contain at least 12 characters.")
        return render_template_string(RESET_PAGE), 400

    if new_password != confirm_password:
        flash("The passwords do not match.")
        return render_template_string(RESET_PAGE), 400

    if not acquire_argon2_slot():
        flash("Password security service is busy. Please try again.")
        return render_template_string(RESET_PAGE), 503

    try:
        new_hash = password_hasher.hash(new_password)
    finally:
        release_argon2_slot()

    migrated_at = utc_now()
    connection = get_database_connection()

    try:
        cursor = connection.execute("""
            UPDATE users
               SET password_hash = ?,
                   hash_scheme = 'argon2id',
                   migration_status = 'migrated',
                   migrated_at = ?
             WHERE user_id = ?
               AND hash_scheme = 'md5'
        """, (new_hash, migrated_at, user_id))

        if cursor.rowcount != 1:
            connection.rollback()
            session.clear()
            flash("The account changed. Please sign in again.")
            return redirect(url_for("index"))

        insert_migration_event(
            connection, user_id, username,
            "argon2id_hash_generated",
            "A new Argon2id hash was generated during the required password reset."
        )
        insert_migration_event(
            connection, user_id, username,
            "legacy_hash_replaced",
            "The stored MD5 verifier was replaced; it was not retained."
        )
        insert_migration_event(
            connection, user_id, username,
            "forced_password_reset_completed",
            "The account completed the required password reset after the migration deadline."
        )
        insert_migration_event(
            connection, user_id, username,
            "migration_completed",
            "The account now uses direct Argon2id authentication."
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

    session.clear()
    flash("Password reset complete. Please sign in with your new password.")
    return redirect(url_for("index"))


@app.route("/logout", methods=["POST"])
def logout():
    validate_csrf()
    session.clear()
    flash("You have been signed out.")
    return redirect(url_for("index"))


# ============================================================
# Administrator access and monitoring APIs
# ============================================================

def require_admin():
    if not session.get("is_admin"):
        abort(401)


@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if session.get("is_admin"):
        return render_template_string(ADMIN_PAGE)
    if request.method == "POST":
        validate_csrf()
        supplied = request.form.get("admin_key", "")
        if hmac.compare_digest(supplied, ADMIN_ACCESS_KEY):
            session["is_admin"] = True
            session.permanent = True
            return redirect(url_for("admin_login"))
        flash("Administrator key was not accepted.")
    return render_template_string(ADMIN_LOGIN_PAGE)


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    require_admin()
    validate_csrf()
    session.pop("is_admin", None)
    return redirect(url_for("admin_login"))


@app.route("/admin/api/overview", methods=["GET"])
def admin_api_overview():
    require_admin()
    connection = get_database_connection()
    try:
        row = connection.execute("""
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN hash_scheme='md5' THEN 1 ELSE 0 END) AS md5_count,
                   SUM(CASE WHEN hash_scheme='argon2id' THEN 1 ELSE 0 END) AS argon_count
              FROM users
        """).fetchone()
    finally:
        connection.close()

    total = row["total"] or 0
    md5_count = row["md5_count"] or 0
    argon_count = row["argon_count"] or 0
    progress = (argon_count / total * 100) if total else 0
    return jsonify({
        "total": total,
        "md5_count": md5_count,
        "argon_count": argon_count,
        "progress": round(progress, 2),
    })


@app.route("/admin/api/events", methods=["GET"])
def admin_api_events():
    require_admin()
    connection = get_database_connection()
    try:
        rows = connection.execute("""
            SELECT username, event_type, details, created_at
              FROM migration_events
             ORDER BY event_id DESC
             LIMIT 20
        """).fetchall()
    finally:
        connection.close()
    return jsonify({"events": [dict(row) for row in rows]})


@app.route("/admin/api/security-events", methods=["GET"])
def admin_api_security_events():
    require_admin()
    requested_source = request.args.get("source", "manual").strip().lower()
    if requested_source not in ("manual", "automated"):
        return jsonify({"error": "source must be manual or automated"}), 400

    connection = get_database_connection()
    try:
        security_rows = connection.execute("""
            SELECT username, event_type, details, created_at
              FROM security_events
              ORDER BY event_id DESC
        """).fetchall()
        live_rows = connection.execute("""
            SELECT username, event_type, detail AS details, outcome, created_at
              FROM live_security_events
             ORDER BY event_id DESC 
        """).fetchall()
        demo_rows = connection.execute("""
            SELECT username, scenario, stage, source_ip, attempt_no,
                   attempts_total, outcome, detail, created_at
              FROM demo_events
             ORDER BY event_id DESC 
        """).fetchall()
    finally:
        connection.close()

    manual_events = []
    automated_events = []
    seen_manual = set()
    seen_auto = set()

    # Existing security_events are genuine route-level events except for the
    # older test-client CSRF entries, which have unmistakable demo identifiers.
    for row in security_rows:
        item = dict(row)
        old_demo_csrf = (item["username"] == "demo-csrf-user" or "DEMO-CSRF-IP" in item["details"])
        if old_demo_csrf:
            item["event_type"] = "CSRF PROTECTION · Automated test"
            item["details"] = "Test-client POST without a CSRF token was rejected with HTTP 400."
            item["outcome"] = "PASS"
            key = (item["username"], item["event_type"], item["created_at"])
            if key not in seen_auto:
                automated_events.append(item); seen_auto.add(key)
        else:
            item["event_type"] = _manual_event_label(item["event_type"])
            item["outcome"] = _event_outcome(item["event_type"], item["details"])
            key = (item["username"], item["event_type"], item["created_at"])
            if key not in seen_manual:
                manual_events.append(item); seen_manual.add(key)

    for row in live_rows:
        item = dict(row)
        item["event_type"] = _manual_event_label(item["event_type"])
        key = (item["username"], item["event_type"], item["created_at"])
        if key not in seen_manual:
            manual_events.append(item); seen_manual.add(key)

    scenario_labels = {
        "progressive": "PROGRESSIVE DELAY",
        "account": "ACCOUNT THROTTLING",
        "ip": "IP THROTTLING",
        "csrf": "CSRF PROTECTION",
        "argon": "ARGON2 CAPACITY",
    }
    stage_labels = {
        "test_started": "Test started",
        "synthetic_history_loaded": "Failure history prepared",
        "protection_evaluated": "Protection decision evaluated",
        "test_finished": "Test completed",
        "request_submitted": "Invalid-token request submitted",
        "slots_occupied": "Concurrency slots occupied",
        "third_slot_test": "Additional request checked",
    }
    for row in demo_rows:
        item = dict(row)
        scenario = item.pop("scenario")
        stage = item.pop("stage")
        source_ip = item.pop("source_ip")
        attempt_no = item.pop("attempt_no")
        attempts_total = item.pop("attempts_total")
        outcome = item.get("outcome", "INFO")
        detail = item.pop("detail")
        item["event_type"] = f"{scenario_labels.get(scenario, scenario.upper())} · {stage_labels.get(stage, stage.replace('_', ' ').title())}"
        item["details"] = detail
        if scenario in ("progressive", "account", "ip"):
            item["details"] += f" Source: {source_ip}; attempt: {attempt_no}/{attempts_total}."
        item["outcome"] = outcome
        key = (item["username"], item["event_type"], item["created_at"])
        if key not in seen_auto:
            automated_events.append(item); seen_auto.add(key)

    manual_events.sort(key=lambda item: item["created_at"], reverse=True)
    automated_events.sort(key=lambda item: item["created_at"], reverse=True)
    selected = manual_events if requested_source == "manual" else automated_events
    return jsonify({
        "source": requested_source,
        "counts": {"manual": len(manual_events), "automated": len(automated_events)},
        "events": selected[:100],
    })


def _manual_event_label(event_type):
    labels = {
        "login_failed": "LOGIN · Invalid credentials",
        "login_success": "LOGIN · Successful authentication",
        "login_throttled": "RATE LIMIT · Request blocked",
        "csrf_rejected": "CSRF PROTECTION · Request rejected",
        "argon2_capacity_rejected": "ARGON2 CAPACITY · Request deferred",
        "login_incomplete": "LOGIN · Incomplete submission",
    }
    return labels.get(event_type, event_type.replace("_", " ").upper())


def _event_outcome(event_type, details):
    text = (event_type + " " + details).lower()
    if "success" in text or "migrated" in text:
        return "SUCCESS"
    if "throttled" in text or "blocked" in text or "rejected" in text or "invalid" in text:
        return "BLOCKED"
    return "RECORDED"


@app.route("/admin/api/account", methods=["GET"])
def admin_api_account():
    require_admin()
    username = request.args.get("username", "").strip()
    if not username or len(username) > 100:
        return jsonify({"account": None}), 400

    connection = get_database_connection()
    try:
        row = connection.execute("""
            SELECT user_id, username, hash_scheme, migration_status, migrated_at
              FROM users WHERE username = ?
        """, (username,)).fetchone()
    finally:
        connection.close()

    return jsonify({"account": dict(row) if row else None})




# ============================================================
# Administrator-only, isolated security demonstration tests
# ============================================================

def _demo_seed_attempts(username, ip_address, count, age_seconds=5):
    """Create synthetic rate-limit history for a test identity/IP only."""
    now = time.time()
    user_key = keyed_identifier("user:" + username.strip().lower())
    ip_key = keyed_identifier("ip:" + ip_address)
    connection = get_database_connection()
    try:
        for index in range(count):
            # Keep all attempts in the relevant window, but make the newest
            # attempt old enough that progressive cooldown itself has elapsed.
            created = now - age_seconds - (index * 2)
            connection.execute(
                """INSERT INTO auth_attempts
                   (username_key, ip_key, succeeded, created_at)
                   VALUES (?, ?, 0, ?)""",
                (user_key, ip_key, created),
            )
        connection.commit()
    finally:
        connection.close()
    return user_key, ip_key


def _demo_cleanup_attempts(keys):
    connection = get_database_connection()
    try:
        for key in keys:
            connection.execute(
                "DELETE FROM auth_attempts WHERE username_key=? OR ip_key=?",
                (key, key),
            )
        connection.commit()
    finally:
        connection.close()


def _demo_rate_test(kind, run_id):
    suffix = secrets.token_hex(6)
    synthetic_ip = "DEMO-IP-" + suffix
    username = "demo-" + kind + "-" + suffix
    inserted_keys = []
    try:
        if kind == "progressive":
            count = 3
            user_key, ip_key = _demo_seed_attempts(username, synthetic_ip, count, 0.5)
            inserted_keys.extend([user_key, ip_key])
            for number in range(1, count + 1):
                record_demo_event(run_id, kind, "synthetic_history_loaded", username,
                    synthetic_ip, number, count, "[REDACTED]", "FAILED",
                    "Synthetic prior failure record; no password was stored.")
            allowed, retry, reason = get_rate_limit_state(username, synthetic_ip)
            passed = not allowed and reason == "progressive_delay" and retry > 0
            record_demo_event(run_id, kind, "protection_evaluated", username,
                synthetic_ip, count + 1, count, "[REDACTED]",
                "BLOCKED" if not allowed else "ALLOWED",
                f"Decision={reason}; retry_after={retry}s.")
            return {"title":"Progressive delay", "passed":passed,
                "detail":f"{count} synthetic failures loaded; next attempt blocked by {reason}, retry={retry}s.",
                "note":"History is synthetic, not live password submissions."}
        if kind == "account":
            count = ACCOUNT_FAILURE_LIMIT
            user_key, ip_key = _demo_seed_attempts(username, synthetic_ip, count, 5)
            inserted_keys.extend([user_key, ip_key])
            for number in range(1, count + 1):
                record_demo_event(run_id, kind, "synthetic_history_loaded", username,
                    synthetic_ip, number, count, "[REDACTED]", "FAILED",
                    "Synthetic prior failure record; no password was stored.")
            allowed, retry, reason = get_rate_limit_state(username, synthetic_ip)
            passed = not allowed and reason == "account_failure_limit"
            record_demo_event(run_id, kind, "protection_evaluated", username,
                synthetic_ip, count + 1, count, "[REDACTED]",
                "BLOCKED" if not allowed else "ALLOWED",
                f"Decision={reason}; retry_after={retry}s.")
            return {"title":"Account failure threshold", "passed":passed,
                "detail":f"{count} synthetic failures for {username}; next attempt was {reason}.",
                "note":"No real account was locked or modified."}
        if kind == "ip":
            count = IP_FAILURE_LIMIT
            for index in range(count):
                demo_username = f"{username}-{index+1:02d}"
                user_key, ip_key = _demo_seed_attempts(demo_username, synthetic_ip, 1, 5)
                inserted_keys.extend([user_key, ip_key])
                record_demo_event(run_id, kind, "synthetic_history_loaded", demo_username,
                    synthetic_ip, index + 1, count, "[REDACTED]", "FAILED",
                    "One synthetic failed attempt from the shared synthetic source IP.")
            allowed, retry, reason = get_rate_limit_state(username + "-1", synthetic_ip)
            passed = not allowed and reason == "ip_failure_limit"
            record_demo_event(run_id, kind, "protection_evaluated", username + "-1",
                synthetic_ip, count + 1, count, "[REDACTED]",
                "BLOCKED" if not allowed else "ALLOWED",
                f"Decision={reason}; retry_after={retry}s.")
            return {"title":"IP failure threshold", "passed":passed,
                "detail":f"{count} synthetic failures across separate accounts from {synthetic_ip}; next attempt was {reason}.",
                "note":"Synthetic source IP; localhost IP history is untouched."}
    finally:
        if inserted_keys:
            _demo_cleanup_attempts(inserted_keys)
    raise ValueError("Unknown rate-limit demo.")


def _demo_csrf_test(run_id):
    client = app.test_client()
    response = client.post(
        "/login",
        data={"username":"demo-csrf-user", "password":"NotARealPassword"},
        environ_base={"REMOTE_ADDR":"DEMO-CSRF-IP", "PM_AUTOMATED_TEST": True},
        follow_redirects=False,
    )
    passed = response.status_code == 400
    record_demo_event(run_id, "csrf", "request_submitted", "demo-csrf-user",
        "DEMO-CSRF-IP", 1, 1, "[REDACTED]", "REJECTED" if passed else "UNEXPECTED",
        f"POST /login without token returned HTTP {response.status_code}.")
    return {"title":"CSRF rejection", "passed":passed,
            "detail":f"POST /login without a CSRF token returned HTTP {response.status_code}; expected HTTP 400.",
            "note":"The request is rejected before password verification. A csrf_rejected event is recorded."}


def _demo_argon_capacity_test(run_id):
    acquired = 0
    try:
        for _ in range(ARGON2_MAX_CONCURRENT):
            if acquire_argon2_slot():
                acquired += 1
        third = acquire_argon2_slot()
        if third:
            release_argon2_slot()
        passed = acquired == ARGON2_MAX_CONCURRENT and not third
        record_demo_event(run_id, "argon", "slots_occupied", "demo-argon-user",
            "IN_PROCESS", acquired, ARGON2_MAX_CONCURRENT, "[NOT APPLICABLE]",
            "OCCUPIED", f"Acquired {acquired} of {ARGON2_MAX_CONCURRENT} slots.")
        record_demo_event(run_id, "argon", "third_slot_test", "demo-argon-user",
            "IN_PROCESS", acquired + 1, ARGON2_MAX_CONCURRENT, "[NOT APPLICABLE]",
            "REJECTED" if not third else "ACCEPTED",
            "Third acquisition tested against the application's actual semaphore.")
        return {"title":"Argon2 capacity gate", "passed":passed,
                "detail":f"Occupied {acquired} of {ARGON2_MAX_CONCURRENT} slots; next acquisition was {'accepted' if third else 'rejected'} as expected.",
                "note":"Deterministic in-process semaphore test. It verifies the same gate used by Argon2 verification and migration; it is not a concurrent HTTP load test."}
    finally:
        for _ in range(acquired):
            release_argon2_slot()


@app.route("/admin/api/demo", methods=["POST"])
def admin_api_demo():
    require_admin()
    validate_csrf()
    selected = request.form.get("test", "")
    allowed = {"progressive", "account", "ip", "csrf", "argon", "all"}
    if selected not in allowed:
        return jsonify({"error":"Unknown demo test."}), 400

    tests = ["progressive", "account", "ip", "csrf", "argon"] if selected == "all" else [selected]
    results = []
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(3)
    for test_name in tests:
        try:
            record_demo_event(run_id, test_name, "test_started", "DEMO",
                "ADMIN-CONSOLE", 0, 0, "[NOT APPLICABLE]", "STARTED",
                "Administrator started this test.")
            if test_name in {"progressive", "account", "ip"}:
                result = _demo_rate_test(test_name, run_id)
            elif test_name == "csrf":
                result = _demo_csrf_test(run_id)
            else:
                result = _demo_argon_capacity_test(run_id)
        except Exception as exc:
            result = {"title":test_name, "passed":False,
                      "detail":f"Test raised {type(exc).__name__}: {exc}",
                      "note":"Check the Flask terminal for the traceback."}
        results.append(result)
        record_demo_event(run_id, test_name, "test_finished", "DEMO",
            "ADMIN-CONSOLE", 0, 0, "[NOT APPLICABLE]",
            "PASS" if result["passed"] else "FAIL", result["detail"])

    passed_count = sum(1 for result in results if result["passed"])
    summary = f"{passed_count}/{len(results)} demonstration checks passed."
    return jsonify({"results":results, "result":results[0] if results else None, "summary":summary})


# ============================================================
# Local development entry point
# ============================================================

if __name__ == "__main__":
    print()
    print("=" * 60)
    print("       PASSWORD MIGRATION OPERATIONS CENTER")
    print("=" * 60)

    print(f"Database: {DATABASE}")
    print("Argon2id baseline: m=19456 KiB, t=2, p=1")

    print(
        f"Protections: account={ACCOUNT_FAILURE_LIMIT}/{ACCOUNT_WINDOW_SECONDS}s, "
        f"IP={IP_FAILURE_LIMIT}/{IP_WINDOW_SECONDS}s, "
        f"Argon2 concurrency={ARGON2_MAX_CONCURRENT}"
    )

    print()
    print("USER LOGIN:")
    print("http://127.0.0.1:5000/")

    print()
    print("ADMIN CONSOLE:")
    print("http://127.0.0.1:5000/admin")

    print()
    print("=" * 60)
    print("TEMPORARY ADMINISTRATOR KEY")
    print("=" * 60)
    print(ADMIN_ACCESS_KEY)
    print("=" * 60)
    print("This key is valid only for the current application session.")
    print("Stopping the application will invalidate this key.")
    print("=" * 60)
    print()

    try:
        app.run(
            host="127.0.0.1",
            port=5000,
            debug=False
        )
    except KeyboardInterrupt:
        print("\nApplication stopped. Temporary credentials discarded.")
