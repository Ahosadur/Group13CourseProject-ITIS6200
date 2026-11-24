
import sqlite3
from pathlib import Path
from datetime import datetime

# Database configuration
DB_PATH = Path("data/users.db")
BACKUP_DIR = Path("backups")

# Only these event tables are approved for clearing.
TABLES_TO_CLEAR = [
    "live_security_events",
    "demo_events"
]

# These tables must remain untouched.
PROTECTED_TABLES = [
    "users",
    "migration_events",
    "auth_attempts"
]


def get_count(cursor, table):
    cursor.execute(f'SELECT COUNT(*) FROM "{table}"')
    return cursor.fetchone()[0]


def clear_event_history():
    if not DB_PATH.exists():
        raise FileNotFoundError(f"Database not found: {DB_PATH}")

    BACKUP_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / f"before_event_clear_{timestamp}.db"

    # Create a consistent SQLite backup.
    with sqlite3.connect(DB_PATH) as source:
        with sqlite3.connect(backup_path) as backup:
            source.backup(backup)

    print(f"\nBackup created: {backup_path}")

    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.cursor()

        # Verify required tables exist.
        cursor.execute("""
            SELECT name FROM sqlite_master
            WHERE type = 'table'
        """)
        existing_tables = {row[0] for row in cursor.fetchall()}

        required = TABLES_TO_CLEAR + PROTECTED_TABLES

        missing = set(required) - existing_tables
        if missing:
            raise RuntimeError(
                f"Missing expected tables: {sorted(missing)}"
            )

        # Record protected table counts before deletion.
        protected_before = {
            table: get_count(cursor, table)
            for table in PROTECTED_TABLES
        }

        event_counts = {
            table: get_count(cursor, table)
            for table in TABLES_TO_CLEAR
        }

        print("\nEVENTS TO BE CLEARED:")
        for table, count in event_counts.items():
            print(f"{table}: {count} records")

        print("\nPROTECTED TABLES:")
        for table, count in protected_before.items():
            print(f"{table}: {count} records")

        confirmation = input(
            "\nType CLEAR EVENTS to continue: "
        )

        if confirmation != "CLEAR EVENTS":
            print("Operation cancelled.")
            return

        try:
            # Start an atomic transaction.
            cursor.execute("BEGIN IMMEDIATE")

            for table in TABLES_TO_CLEAR:
                cursor.execute(f'DELETE FROM "{table}"')

            # Verify protected table counts.
            protected_after = {
                table: get_count(cursor, table)
                for table in PROTECTED_TABLES
            }

            if protected_before != protected_after:
                raise RuntimeError(
                    "Protected table counts changed. Rolling back."
                )

            connection.commit()

            print("\nSUCCESS: Event history cleared.")

            for table in TABLES_TO_CLEAR:
                print(f"{table}: {get_count(cursor, table)} records")

            print("\nProtected tables remain unchanged:")
            for table, count in protected_after.items():
                print(f"{table}: {count} records")

            print(f"\nBackup preserved at: {backup_path}")

        except Exception:
            connection.rollback()
            raise


if __name__ == "__main__":
    try:
        clear_event_history()
    except Exception as error:
        print(f"\nERROR: {error}")
