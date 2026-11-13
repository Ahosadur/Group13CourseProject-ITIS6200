"""Live + demonstration monitor for the password-migration Flask app.

Start Flask first, then run this in a second PowerShell window.
Shows real application requests AND dashboard test-suite events, clearly labelled.
Passwords and password hashes are never queried or displayed.
"""
from datetime import datetime
from pathlib import Path
import sqlite3
import sys
import time

ROOT = Path(__file__).resolve().parent
DB = ROOT / "data" / "users.db"
POLL_SECONDS = 0.20


def connect():
    db = sqlite3.connect(DB, timeout=5)
    db.row_factory = sqlite3.Row
    return db


def table_exists(db, name):
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def stamp(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone().strftime("%H:%M:%S")
    except Exception:
        return str(value)


def print_real(row):
    print(f"[{stamp(row['created_at'])}] REAL REQUEST | {row['event_type'].replace('_', ' ').upper()} | {row['outcome']}")
    print(f"  Account : {row['username']}")
    print(f"  Source  : {row['source_ip']}")
    if row['attempt_no'] or row['account_attempts'] or row['ip_attempts']:
        print(f"  Failures: account {row['account_attempts']}/8 | source IP {row['ip_attempts']}/20")
    print("  Password: [REDACTED]")
    print(f"  Result  : {row['detail']}")
    print("-" * 76)


def print_demo(row):
    print(f"[{stamp(row['created_at'])}] AUTOMATED TEST | {row['scenario'].upper()} / {row['stage'].replace('_', ' ').upper()} | {row['outcome']}")
    print(f"  Test run: {row['run_id']}")
    print(f"  Account : {row['username']}")
    print(f"  Source  : {row['source_ip']}")
    if row['attempt_no'] or row['attempts_total']:
        print(f"  Attempts: {row['attempt_no']}/{row['attempts_total']}")
    print(f"  Credential: {row['credential_label'] or '[REDACTED]'}")
    print(f"  Result  : {row['detail']}")
    print("-" * 76)


def main():
    if not DB.exists():
        print(f"Database not found: {DB}")
        sys.exit(1)

    with connect() as db:
        live_ok = table_exists(db, "live_security_events")
        demo_ok = table_exists(db, "demo_events")
        if not live_ok and not demo_ok:
            print("Neither live_security_events nor demo_events exists.")
            print("Start the updated Flask app once, then restart this monitor.")
            sys.exit(1)
        last_live = db.execute("SELECT COALESCE(MAX(event_id),0) FROM live_security_events").fetchone()[0] if live_ok else 0
        last_demo = db.execute("SELECT COALESCE(MAX(event_id),0) FROM demo_events").fetchone()[0] if demo_ok else 0

    print("\n" + "=" * 76)
    print(" PASSWORD MIGRATION | LIVE + TEST MONITOR")
    print("=" * 76)
    print(f"Database : {DB}")
    print("REAL REQUEST : actual browser/DevTools requests handled by Flask")
    print("AUTOMATED TEST: dashboard Run Test / Run All test-suite events")
    print("Privacy       : passwords and hashes are never queried; credentials are redacted")
    print("Waiting       : perform browser tests or click Run all tests in the admin panel")
    print("Stop          : Ctrl+C\n")

    try:
        while True:
            with connect() as db:
                live_rows = db.execute(
                    "SELECT * FROM live_security_events WHERE event_id>? ORDER BY event_id", (last_live,)
                ).fetchall() if live_ok else []
                demo_rows = db.execute(
                    "SELECT * FROM demo_events WHERE event_id>? ORDER BY event_id", (last_demo,)
                ).fetchall() if demo_ok else []

            # Both tables have independent IDs; order by their timestamps for readable output.
            combined = [(r['created_at'], 'live', r) for r in live_rows]
            combined += [(r['created_at'], 'demo', r) for r in demo_rows]
            combined.sort(key=lambda item: item[0])
            for _, source, row in combined:
                if source == 'live':
                    print_real(row)
                    last_live = max(last_live, row['event_id'])
                else:
                    print_demo(row)
                    last_demo = max(last_demo, row['event_id'])
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        print("\nMonitor stopped.")


if __name__ == "__main__":
    main()
