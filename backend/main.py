
import os
import secrets
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.database import (
    initialize_database,
    save_investigation,
    get_investigation,
    get_latest_investigation,
)

app = FastAPI(
    title="AI Forensics Browser History API",
    version="0.4.1",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_TOKEN = os.getenv("EXTENSION_API_TOKEN") or "browser-test-token-123"


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
            detail="EXTENSION_API_TOKEN is not configured.",
        )

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authorization header is missing.",
        )

    expected = f"Bearer {API_TOKEN}"

    if not secrets.compare_digest(authorization.strip(), expected):
        raise HTTPException(
            status_code=401,
            detail="Authorization header does not match the configured token.",
        )


@app.on_event("startup")
def startup():
    try:
        initialize_database()
    except Exception as exc:
        raise RuntimeError(
            "Could not initialize the PostgreSQL database. "
            "Check DATABASE_URL and database connectivity."
        ) from exc


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "browser-history-api",
    }


@app.post("/api/history")
def receive_history(
    payload: HistorySubmission,
    authorization: str | None = Header(default=None),
):
    require_token(authorization)

    try:
        start = datetime.fromisoformat(payload.start_date).date()
        end = datetime.fromisoformat(payload.end_date).date()
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="Dates must use YYYY-MM-DD format.",
        ) from exc

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

    # Analyze browser history and log the actual failure.
    try:
        from models.history_analyzer import analyze_history

        results = analyze_history(records)

        investigation["analysis"] = results
        investigation["analyzed_url_count"] = len(results)
        investigation["phishing_count"] = sum(
            1 for item in results
            if item.get("status") == "PHISHING"
        )
        investigation["benign_count"] = sum(
            1 for item in results
            if item.get("status") == "BENIGN"
        )
        investigation["status"] = "analyzed"

    except Exception as exc:
        print(
            "History analysis failed:",
            type(exc).__name__,
            str(exc)[:300],
            flush=True,
        )
        investigation["status"] = "analysis_failed"
        investigation["analysis_error"] = (
            "History analysis failed. Check backend logs."
        )

    # Save the investigation to PostgreSQL.
    try:
        save_investigation(investigation)
    except Exception as exc:
        print(
            "Saving investigation failed:",
            type(exc).__name__,
            str(exc)[:300],
            flush=True,
        )
        raise HTTPException(
            status_code=503,
            detail="Could not save investigation to PostgreSQL. "
                   "Check DATABASE_URL and database logs.",
        ) from exc

    return {
        "ok": True,
        "investigation_id": payload.investigation_id,
        "received_records": len(records),
        "status": investigation["status"],
        "analyzed_url_count": investigation.get(
            "analyzed_url_count", 0
        ),
        "phishing_count": investigation.get("phishing_count", 0),
        "benign_count": investigation.get("benign_count", 0),
        "analysis_error": investigation.get("analysis_error"),
    }


# Keep /latest before /{investigation_id}.
@app.get("/api/history/latest")
def latest_history(
    authorization: str | None = Header(default=None),
):
    require_token(authorization)

    try:
        result = get_latest_investigation()
    except Exception as exc:
        print(
            "Latest investigation retrieval failed:",
            type(exc).__name__,
            str(exc)[:300],
            flush=True,
        )
        raise HTTPException(
            status_code=503,
            detail="Could not retrieve investigation from PostgreSQL.",
        ) from exc

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="No investigations submitted yet.",
        )

    return result


@app.get("/api/history/{investigation_id}")
def history_by_id(
    investigation_id: str,
    authorization: str | None = Header(default=None),
):
    require_token(authorization)

    try:
        result = get_investigation(investigation_id)
    except Exception as exc:
        print(
            "Investigation retrieval failed:",
            type(exc).__name__,
            str(exc)[:300],
            flush=True,
        )
        raise HTTPException(
            status_code=503,
            detail="Could not retrieve investigation from PostgreSQL.",
        ) from exc

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found.",
        )

    return result


@app.post("/api/history/analyze-v3")
def analyze_history_with_v3(
    payload: HistorySubmission,
    authorization: str | None = Header(default=None),
):
    require_token(authorization)

    try:
        from models.history_analyzer_v3 import analyze_history_v3

        records = [
            {
                "url": record.url.strip(),
                "title": record.title,
                "lastVisitTime": record.lastVisitTime,
                "visitCount": record.visitCount,
            }
            for record in payload.records
            if record.url.strip().lower().startswith(
                ("http://", "https://")
            )
        ]

        results = analyze_history_v3(records)

        return {
            "ok": True,
            "model_version": "v3",
            "label_mapping_verified": False,
            "analyzed_url_count": len(results),
            "results": results,
        }

    except Exception as exc:
        print(
            "V3 history analysis failed:",
            type(exc).__name__,
            str(exc)[:300],
            flush=True,
        )
        raise HTTPException(
            status_code=500,
            detail=f"V3 analysis failed: {str(exc)[:300]}",
        ) from exc
