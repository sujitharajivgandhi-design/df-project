import json
import os
import sqlite3
from pathlib import Path
from typing import Any

DATABASE_PATH = Path(
    os.getenv(
        "BROWSER_DATABASE_PATH",
        str(Path(__file__).resolve().parent / "browser_history.db"),
    )
)


def get_connection():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(DATABASE_PATH))
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                investigation_id TEXT PRIMARY KEY,
                received_at TEXT NOT NULL,
                data TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_investigations_received_at
            ON investigations(received_at)
        """)


def save_investigation(investigation: dict[str, Any]) -> None:
    investigation_id = investigation["investigation_id"]
    received_at = investigation["received_at"]
    data = json.dumps(investigation, ensure_ascii=False)

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO investigations
                (investigation_id, received_at, data)
            VALUES (?, ?, ?)
            ON CONFLICT(investigation_id) DO UPDATE SET
                received_at = excluded.received_at,
                data = excluded.data
            """,
            (investigation_id, received_at, data),
        )


def get_investigation(
    investigation_id: str,
) -> dict[str, Any] | None:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT data FROM investigations
            WHERE investigation_id = ?
            """,
            (investigation_id,),
        ).fetchone()

    return json.loads(row["data"]) if row else None


def get_latest_investigation() -> dict[str, Any] | None:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT data FROM investigations
            ORDER BY received_at DESC
            LIMIT 1
            """
        ).fetchone()

    return json.loads(row["data"]) if row else None
