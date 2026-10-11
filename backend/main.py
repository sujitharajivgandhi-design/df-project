
import os
import secrets
import sys
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

app = FastAPI(title="AI Forensics Browser History API", version="0.3.0")

API_TOKEN = os.getenv("EXTENSION_API_TOKEN", "")
INVESTIGATIONS: dict[str, dict[str, Any]] = {}


class HistoryRecord(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    title: str = Field(default="", max_length=2048)
    lastVisitTime: int | None = None
    visitCount: int = Field(default=0, ge=0)


class HistorySubmission(BaseModel):
    investigation_id: str = Field(min_length=8, max_length=128)
    start_date: str
    end_date: str
    records: list[HistoryRecord] = Field(max_length=10000)


def require_token(authorization: str | None) -> None:
    if not API_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="Set EXTENSION_API_TOKEN in the backend environment.",
        )

    expected = f"Bearer {API_TOKEN}"
    if not authorization or not secrets.compare_digest(authorization, expected):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing bearer token.",
        )


@app.get("/health")
def health():
    return {"status": "ok", "service": "browser-history-api"}


@app.post("/api/history")
def receive_history(
    payload: HistorySubmission,
    authorization: str | None = Header(default=None),
):
    require_token(authorization)

    try:
        start = datetime.fromisoformat(payload.start_date).date()
        end = datetime.fromisoformat(payload.end_date).date()
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Dates must use YYYY-MM-DD format.",
        )

    if start > end:
        raise HTTPException(
            status_code=400,
            detail="start_date must be on or before end_date.",
        )

    records = []
    for record in payload.records:
        url = record.url.strip()
        if url.lower().startswith(("http://", "https://")):
            records.append({
                "url": url,
                "title": record.title,
                "lastVisitTime": record.lastVisitTime,
                "visitCount": record.visitCount,
            })

    investigation = {
        "investigation_id": payload.investigation_id,
        "start_date": start.isoformat(),
        "end_date": end.isoformat(),
        "received_at": datetime.now(timezone.utc).isoformat(),
        "record_count": len(records),
        "records": records,
        "status": "received_not_analyzed",
    }

    # Store the submission before analysis so it remains available
    # if model loading or prediction fails.
    INVESTIGATIONS[payload.investigation_id] = investigation

    try:
        from models.history_analyzer import analyze_history

        results = analyze_history(records)
        investigation["analysis"] = results
        investigation["analyzed_url_count"] = len(results)
        investigation["phishing_count"] = sum(
            1 for item in results if item.get("status") == "PHISHING"
        )
        investigation["benign_count"] = sum(
            1 for item in results if item.get("status") == "BENIGN"
        )
        investigation["status"] = "analyzed"

    except Exception as exc:
        investigation["status"] = "analysis_failed"
        investigation["analysis_error"] = str(exc)

    return {
        "ok": True,
        "investigation_id": payload.investigation_id,
        "received_records": len(records),
        "status": investigation["status"],
        "analyzed_url_count": investigation.get("analyzed_url_count", 0),
        "phishing_count": investigation.get("phishing_count", 0),
        "benign_count": investigation.get("benign_count", 0),
        "analysis_error": investigation.get("analysis_error"),
    }


# Define /latest BEFORE /{investigation_id}.
@app.get("/api/history/latest")
def get_latest_history(
    authorization: str | None = Header(default=None),
):
    require_token(authorization)

    if not INVESTIGATIONS:
        raise HTTPException(
            status_code=404,
            detail="No investigations submitted yet.",
        )

    latest = max(
        INVESTIGATIONS.values(),
        key=lambda item: item.get("received_at", ""),
    )
    return latest


@app.get("/api/history/{investigation_id}")
def get_history(
    investigation_id: str,
    authorization: str | None = Header(default=None),
):
    require_token(authorization)

    result = INVESTIGATIONS.get(investigation_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found. Submit the history again.",
        )

    return result
