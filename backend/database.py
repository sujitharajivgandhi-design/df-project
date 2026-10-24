import json
import os
from typing import Any

import psycopg
from psycopg.rows import dict_row

DATABASE_URL = os.getenv("DATABASE_URL")


def get_connection():
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL environment variable is not configured."
        )

    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
        connect_timeout=10,
    )


def initialize_database() -> None:
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                investigation_id TEXT PRIMARY KEY,
                received_at TEXT NOT NULL,
                data JSONB NOT NULL
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_investigations_received_at
            ON investigations(received_at)
        """)


def save_investigation(investigation: dict[str, Any]) -> None:
    data = json.dumps(investigation, ensure_ascii=False)

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO investigations
                (investigation_id, received_at, data)
            VALUES (%s, %s, %s::jsonb)
            ON CONFLICT (investigation_id) DO UPDATE SET
                received_at = EXCLUDED.received_at,
                data = EXCLUDED.data
            """,
            (
                investigation["investigation_id"],
                investigation["received_at"],
                data,
            ),
        )


def get_investigation(
    investigation_id: str,
) -> dict[str, Any] | None:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT data FROM investigations
            WHERE investigation_id = %s
            """,
            (investigation_id,),
        ).fetchone()

    return row["data"] if row else None


def get_latest_investigation() -> dict[str, Any] | None:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT data FROM investigations
            ORDER BY received_at DESC
            LIMIT 1
            """
        ).fetchone()

    return row["data"] if row else None