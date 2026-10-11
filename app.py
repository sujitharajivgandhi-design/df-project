
import base64
import re
from datetime import date, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import streamlit as st

from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


# --------------------------------------------------
# APP CONFIGURATION
# --------------------------------------------------
st.set_page_config(
    page_title="AI Browser & Email Forensics",
    page_icon="🔍",
    layout="wide",
)

st.title("🔍 AI-Based Browser & Email Forensics Engine")
st.caption("Browser History Analysis • Gmail Metadata • Suspicious URL Checks")

ROOT_DIR = Path(__file__).resolve().parent
BROWSER_DIR = ROOT_DIR / "browser"
BROWSER_DIR.mkdir(exist_ok=True)

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


# --------------------------------------------------
# SESSION STATE
# --------------------------------------------------
if "gmail_credentials" not in st.session_state:
    st.session_state.gmail_credentials = None

if "gmail_oauth_state" not in st.session_state:
    st.session_state.gmail_oauth_state = None


# --------------------------------------------------
# GOOGLE OAUTH CONFIG
# --------------------------------------------------
def get_oauth_config():
    try:
        auth = st.secrets["auth"]
        return {
            "client_id": auth["client_id"],
            "client_secret": auth["client_secret"],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    except Exception:
        return None


def create_oauth_flow(state=None):
    config = get_oauth_config()
    if not config:
        return None

    redirect_uri = st.secrets["auth"]["redirect_uri"]

    flow = Flow.from_client_config(
        {"web": config},
        scopes=SCOPES,
        state=state,
    )
    flow.redirect_uri = redirect_uri
    return flow


def handle_gmail_callback():
    query_params = st.query_params
    error = query_params.get("error")
    code = query_params.get("code")
    state = query_params.get("state")

    if error:
        st.error(f"Google login was not completed: {error}")
        return

    if not code:
        return

    expected_state = st.session_state.gmail_oauth_state
    if expected_state and state != expected_state:
        st.error("OAuth state mismatch. Please restart Gmail login.")
        return

    try:
        flow = create_oauth_flow(state=state)
        if flow is None:
            st.error("Google OAuth secrets are missing.")
            return

        flow.fetch_token(code=code)
        st.session_state.gmail_credentials = flow.credentials
        st.session_state.gmail_oauth_state = None

        # Remove OAuth parameters from the page URL.
        st.query_params.clear()
        st.success("Gmail connected successfully.")
        st.rerun()

    except Exception as exc:
        st.error("Gmail sign-in failed. Check the Google OAuth settings.")
        st.caption(str(exc))


def gmail_login_button():
    try:
        flow = create_oauth_flow()
        if flow is None:
            st.error(
                "Google OAuth secrets are not configured. "
                "Add client_id, client_secret and redirect_uri "
                "under [auth] in Streamlit Secrets."
            )
            return

        authorization_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
        )

        st.session_state.gmail_oauth_state = state
        st.link_button(
            "🔵 Sign in with Google",
            authorization_url,
            use_container_width=True,
        )

    except Exception:
        st.error("Unable to start Google login. Check your OAuth settings.")


def get_gmail_service():
    credentials = st.session_state.gmail_credentials
    if not credentials:
        return None

    return build(
        "gmail",
        "v1",
        credentials=credentials,
        cache_discovery=False,
    )


# Handle Google redirect before displaying the rest of the app.
handle_gmail_callback()


# --------------------------------------------------
# URL ANALYSIS
# --------------------------------------------------
SUSPICIOUS_TERMS = [
    "login-verify",
    "account-verify",
    "free-gift",
    "password-reset",
    "secure-update",
    "wallet-connect",
    "urgent-action",
]

def analyze_url(value):
    if pd.isna(value):
        return "Empty URL"

    raw_url = str(value).strip()
    if not raw_url:
        return "Empty URL"

    parsed = urlparse(
        raw_url if "://" in raw_url else "https://" + raw_url
    )
    host = (parsed.hostname or "").lower()

    if not host:
        return "Invalid URL"

    if parsed.scheme.lower() == "http":
        return "Review: HTTP, not HTTPS"

    if host.startswith("xn--") or ".xn--" in host:
        return "Review: internationalized domain"

    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
        return "Review: IP address used as host"

    if host.count("-") >= 3:
        return "Review: unusually many hyphens in domain"

    if any(term in raw_url.lower() for term in SUSPICIOUS_TERMS):
        return "Review: suspicious keyword"

    return "No obvious indicator"


# --------------------------------------------------
# BROWSER HISTORY ANALYSIS
# --------------------------------------------------
def find_url_column(df):
    candidates = [
        "url",
        "urls",
        "website",
        "site",
        "domain",
        "visited_url",
    ]
    lower_map = {str(col).strip().lower(): col for col in df.columns}

    for name in candidates:
        if name in lower_map:
            return lower_map[name]

    for col in df.columns:
        if "url" in str(col).lower():
            return col

    return None


def find_date_column(df):
    for col in df.columns:
        name = str(col).strip().lower()
        if any(term in name for term in ["date", "time", "timestamp", "visit"]):
            return col
    return None


def analyze_browser_file(uploaded_file):
    try:
        df = pd.read_csv(uploaded_file)
    except Exception as exc:
        st.error(f"Could not read CSV: {exc}")
        return

    if df.empty:
        st.warning("The uploaded CSV has no records.")
        return

    st.subheader("Browser History Dataset")
    st.write(f"Records loaded: **{len(df)}**")
    st.dataframe(df.head(100), use_container_width=True)

    url_col = find_url_column(df)

    if url_col is None:
        st.warning(
            "No URL column was detected. Please use a column such as "
            "'url', 'website' or 'visited_url'."
        )
        return

    results = df.copy()
    results["Forensic URL Result"] = results[url_col].apply(analyze_url)

    st.subheader("URL Investigation Results")
    suspicious = results[
        results["Forensic URL Result"] != "No obvious indicator"
    ]

    c1, c2, c3 = st.columns(3)
    c1.metric("Total records", len(results))
    c2.metric("Flagged for review", len(suspicious))
    c3.metric("Unique URLs", results[url_col].nunique())

    st.dataframe(results, use_container_width=True)

    csv_bytes = results.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇️ Download Analysis CSV",
        data=csv_bytes,
        file_name="browser_forensics_results.csv",
        mime="text/csv",
    )

    date_col = find_date_column(results)
    if date_col:
        parsed_dates = pd.to_datetime(results[date_col], errors="coerce")
        if parsed_dates.notna().any():
            st.subheader("Visits Over Time")
            daily_counts = (
                parsed_dates.dropna()
                .dt.date.value_counts()
                .sort_index()
            )
            st.bar_chart(daily_counts)


# --------------------------------------------------
# GMAIL METADATA ANALYSIS
# --------------------------------------------------
def show_gmail_messages():
    st.subheader("Gmail Forensics — Read-only Metadata")

    service = get_gmail_service()
    if service is None:
        st.info("Connect Gmail to inspect email metadata.")
        gmail_login_button()
        return

    max_results = st.selectbox(
        "Number of recent emails",
        [10, 25, 50],
        index=0,
    )

    if not st.button("🔎 Fetch Email Metadata"):
        return

    try:
        response = (
            service.users()
            .messages()
            .list(userId="me", maxResults=max_results)
            .execute()
        )
        messages = response.get("messages", [])
        rows = []

        progress = st.progress(0)
        for index, message in enumerate(messages):
            details = (
                service.users()
                .messages()
                .get(
                    userId="me",
                    id=message["id"],
                    format="metadata",
                    metadataHeaders=["From", "To", "Subject", "Date"],
                )
                .execute()
            )

            headers = {
                item["name"].lower(): item["value"]
                for item in details.get("payload", {}).get("headers", [])
            }

            rows.append(
                {
                    "Message ID": message.get("id"),
                    "Date": headers.get("date", ""),
                    "From": headers.get("from", ""),
                    "To": headers.get("to", ""),
                    "Subject": headers.get("subject", ""),
                    "Labels": ", ".join(details.get("labelIds", [])),
                }
            )
            progress.progress((index + 1) / max(len(messages), 1))

        progress.empty()

        if rows:
            email_df = pd.DataFrame(rows)
            st.metric("Emails inspected", len(email_df))
            st.dataframe(email_df, use_container_width=True)

            st.download_button(
                "⬇️ Download Email Metadata",
                email_df.to_csv(index=False).encode("utf-8"),
                file_name="gmail_metadata_report.csv",
                mime="text/csv",
            )
        else:
            st.info("No email messages were returned.")

    except HttpError as exc:
        st.error(
            "Gmail API request failed. Check that Gmail API is enabled "
            "and that your account is listed as a test user."
        )
        st.caption(str(exc))
    except Exception as exc:
        st.error("Could not retrieve Gmail metadata.")
        st.caption(str(exc))


# --------------------------------------------------
# MAIN INTERFACE
# --------------------------------------------------
tab_browser, tab_email, tab_about = st.tabs(
    ["🌐 Browser Forensics", "📧 Email Forensics", "ℹ️ About"]
)

with tab_browser:
    st.header("Browser History Investigation")
    st.write(
        "Upload a browser-history CSV file to review URLs and identify "
        "items that may deserve further investigation."
    )

    uploaded_file = st.file_uploader(
        "Upload browser history CSV",
        type=["csv"],
        key="browser_csv",
    )

    if uploaded_file is not None:
        analyze_browser_file(uploaded_file)
    else:
        st.info("Upload a CSV file to begin browser analysis.")

    default_history = BROWSER_DIR / "history.csv"
    if default_history.exists():
        with st.expander("Use existing browser/history.csv"):
            if st.button("Analyze saved history.csv"):
                with default_history.open("rb") as file_obj:
                    analyze_browser_file(file_obj)


with tab_email:
    st.header("Gmail Investigation")

    if st.session_state.gmail_credentials:
        st.success("Gmail is connected.")
        if st.button("Disconnect Gmail"):
            st.session_state.gmail_credentials = None
            st.session_state.gmail_oauth_state = None
            st.rerun()

        show_gmail_messages()
    else:
        st.info(
            "Gmail access uses the read-only Gmail scope. "
            "This app retrieves email metadata; it does not send or delete emails."
        )
        gmail_login_button()


with tab_about:
    st.header("About This Project")
    st.markdown(
        """
        **AI-Based Browser & Email Forensics Engine**

        Features:
        - Browser-history CSV inspection
        - Basic suspicious URL indicators
        - Gmail read-only email metadata
        - CSV export of investigation results

        **Important:** URL flags are preliminary indicators, not proof of
        phishing or malicious activity. Review results before drawing conclusions.
        """
    )

st.divider()
st.caption("AI-Based Browser & Email Forensics Engine")

