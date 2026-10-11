import os
import base64
import importlib.util
import inspect
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlencode

import pandas as pd
import requests
import streamlit as st
import google.auth.transport.requests
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

st.set_page_config(page_title="Browser Forensics", page_icon="🌐", layout="wide",
                   initial_sidebar_state="expanded")


# ==========================================================
# APP CONFIGURATION
# ==========================================================

st.set_page_config(
    page_title="AI Browser & Email Forensics",
    page_icon="🔍",
    layout="wide",
)

ROOT_DIR = Path(__file__).resolve().parent
EMAIL_DIR = ROOT_DIR / "email_forensics_project"

if not (EMAIL_DIR / "main.py").exists():
    EMAIL_DIR = ROOT_DIR

BROWSER_SCRIPT = ROOT_DIR / "browser" / "suspicious_urls.py"

BROWSER_CSV_CANDIDATES = [
    ROOT_DIR / "suspicious_urls_v3.csv",
    ROOT_DIR / "browser" / "suspicious_urls_v3.csv",
    ROOT_DIR / "dataset" / "suspicious_urls_v3.csv",
    EMAIL_DIR / "suspicious_urls_v3.csv",
]

EMAIL_REPORT = EMAIL_DIR / "reports" / "forensic_report.txt"
EMAIL_FILE = EMAIL_DIR / "emails" / "gmail_message.eml"
PDF_PATH = EMAIL_DIR / "forensic_report.pdf"
PDF_MODULE = EMAIL_DIR / "reports" / "report" / "pdf_generator.py"

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


# ==========================================================
# BROWSER AND CHROME EXTENSION CONFIGURATION
# ==========================================================

APP_DIR = str(ROOT_DIR)
BROWSER_DIR = os.path.join(APP_DIR, "browser")
BROWSER_ANALYSIS_FILE = os.path.join(
    BROWSER_DIR, "browser_analysis.py"
)
HISTORY_FILE = os.path.join(BROWSER_DIR, "history.csv")
RESULT_FILE_BROWSER = os.path.join(
    BROWSER_DIR, "suspicious_urls_v3.csv"
)
RESULT_FILE_ROOT = os.path.join(
    APP_DIR, "suspicious_urls_v3.csv"
)

EXTENSION_API_URL = os.getenv(
    "EXTENSION_API_URL", "http://127.0.0.1:8000"
).rstrip("/")
EXTENSION_API_TOKEN = os.getenv("EXTENSION_API_TOKEN", "")


# ==========================================================
# SESSION STATE
# ==========================================================

DEFAULTS = {
    "gmail_token": None,
    "gmail_messages": [],
    "gmail_service": None,
    "email_report_text": "",
    "oauth_state": None,
    "oauth_url": None,
    "oauth_error": None,
    "analysis_complete": False,
    "browser_results": None,
    "analysis_start_date": None,
    "analysis_end_date": None,
    "extension_investigation": None,
    "extension_fetch_error": None,
}

for key, value in DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = value


# ==========================================================
# GOOGLE OAUTH CONFIGURATION
# ==========================================================


def get_oauth_settings():
    try:
        auth = st.secrets["auth"]

        client_id = auth["client_id"]
        client_secret = auth["client_secret"]
        redirect_uri = auth["redirect_uri"].strip()

        if not redirect_uri.startswith("https://"):
            st.error(
                "The Google OAuth redirect_uri must use HTTPS."
            )
            return None

        return client_id, client_secret, redirect_uri

    except Exception:
        st.error(
            "Google OAuth settings are missing. Check the "
            "[auth] section in Streamlit Secrets. It must contain "
            "client_id, client_secret, and redirect_uri."
        )
        return None
def create_oauth_flow(state=None):
    settings = get_oauth_settings()

    if not settings:
        return None

    client_id, client_secret, redirect_uri = settings

    client_config = {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [redirect_uri],
        }
    }

    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        state=state,
    )
    flow.redirect_uri = redirect_uri

    return flow


def clear_oauth_query_params():
    try:
        st.query_params.clear()
    except Exception:
        pass


def get_gmail_service():
    token_data = st.session_state.get("gmail_token")

    if not token_data:
        return None

    try:
        credentials = Credentials.from_authorized_user_info(
            token_data,
            SCOPES,
        )

        if credentials.expired and credentials.refresh_token:
            credentials.refresh(
                google.auth.transport.requests.Request()
            )

            st.session_state.gmail_token = {
                "token": credentials.token,
                "refresh_token": credentials.refresh_token,
                "token_uri": credentials.token_uri,
                "client_id": credentials.client_id,
                "client_secret": credentials.client_secret,
                "scopes": SCOPES,
            }

        if not credentials.valid:
            st.session_state.gmail_token = None
            st.session_state.gmail_service = None
            return None

        service = build(
            "gmail",
            "v1",
            credentials=credentials,
            cache_discovery=False,
        )

        # Verify Gmail access with a lightweight API request.
        service.users().getProfile(userId="me").execute()

        st.session_state.gmail_service = service
        return service

    except Exception:
        st.session_state.gmail_token = None
        st.session_state.gmail_service = None
        st.session_state.oauth_error = (
            "Gmail credentials could not be loaded or Gmail access "
            "was rejected. Please connect your Google account again "
            "and approve Gmail read-only access."
        )
        return None


def handle_oauth_callback():
    """Process the authorization response from Google."""

    params = st.query_params
    code = params.get("code")
    returned_state = params.get("state")
    oauth_error = params.get("error")

    if oauth_error:
        st.session_state.oauth_error = (
            "Google authorization was not completed: "
            + str(oauth_error)
        )
        st.session_state.oauth_url = None
        st.session_state.oauth_state = None
        clear_oauth_query_params()
        return

    if not code:
        return

    expected_state = st.session_state.get("oauth_state")

    # State must match the value saved before redirecting to Google.
    if not expected_state or not returned_state:
        st.session_state.oauth_error = (
            "Google returned to the app, but the saved sign-in state "
            "is missing. Please try connecting again in the same tab."
        )
        st.session_state.oauth_url = None
        st.session_state.oauth_state = None
        clear_oauth_query_params()
        return

    if returned_state != expected_state:
        st.session_state.oauth_error = (
            "Google sign-in state did not match. Please connect again."
        )
        st.session_state.oauth_url = None
        st.session_state.oauth_state = None
        clear_oauth_query_params()
        return

    settings = get_oauth_settings()
    if not settings:
        return

    try:
        flow = create_oauth_flow(state=expected_state)

        if flow is None:
            return

        # Exchange the authorization code directly.
        # State is checked above; this avoids rebuilding a callback URL.
        flow.fetch_token(code=code)

        credentials = flow.credentials

        if not credentials or not credentials.token:
            raise RuntimeError(
                "Google did not return an access token."
            )

        st.session_state.gmail_token = {
            "token": credentials.token,
            "refresh_token": credentials.refresh_token,
            "token_uri": credentials.token_uri,
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "scopes": SCOPES,
        }

        st.session_state.gmail_service = None
        st.session_state.gmail_messages = []
        st.session_state.oauth_state = None
        st.session_state.oauth_url = None
        st.session_state.oauth_error = None

        clear_oauth_query_params()
        st.rerun()

    except Exception as error:
        # Avoid displaying credentials or token contents.
        st.session_state.oauth_error = (
            "Google login could not be completed. Check that the "
            "redirect_uri in Streamlit Secrets exactly matches the "
            "Authorized redirect URI in Google Cloud. "
            f"Error type: {type(error).__name__}"
        )
        st.session_state.oauth_url = None
        st.session_state.oauth_state = None
        clear_oauth_query_params()


def gmail_login_ui():
    handle_oauth_callback()

    if st.session_state.oauth_error:
        st.error(st.session_state.oauth_error)

    service = get_gmail_service()

    if service:
        st.success("Gmail connected successfully.")

        if st.button(
            "Disconnect Gmail",
            key="disconnect_gmail",
        ):
            st.session_state.gmail_token = None
            st.session_state.gmail_service = None
            st.session_state.gmail_messages = []
            st.session_state.oauth_state = None
            st.session_state.oauth_url = None
            st.session_state.oauth_error = None
            st.rerun()

        return service

    st.info("Connect your Google account to search Gmail.")

    if st.button(
        "Connect to Gmail",
        key="connect_gmail",
    ):
        flow = create_oauth_flow()

        if flow is not None:
            try:
                authorization_url, state = flow.authorization_url(
                    access_type="offline",
                    include_granted_scopes="true",
                    prompt="consent",
                )

                st.session_state.oauth_state = state
                st.session_state.oauth_url = authorization_url
                st.session_state.oauth_error = None

            except Exception as error:
                st.session_state.oauth_error = (
                    "Could not start Google login. "
                    f"Error type: {type(error).__name__}"
                )

    if st.session_state.oauth_url:
        safe_url = st.session_state.oauth_url.replace("&", "&amp;")

        st.markdown(
            f'<a href="{safe_url}" target="_self" '
            'style="display:inline-block;padding:0.6em 1em;'
            'background:#ff4b4b;color:white;border-radius:0.5em;'
            'text-decoration:none;font-weight:600;">'
            "Continue to Google login</a>",
            unsafe_allow_html=True,
        )

        st.caption(
            "Complete Google sign-in and return to this same tab."
        )

    return None


# ==========================================================
# GMAIL SEARCH AND EMAIL HELPERS
# ==========================================================

def search_gmail(service, sender, start_date, end_date):
    start_text = start_date.strftime("%Y/%m/%d")
    end_text = (end_date + timedelta(days=1)).strftime("%Y/%m/%d")

    query = (
        f"from:{sender} "
        f"after:{start_text} "
        f"before:{end_text}"
    )

    results = service.users().messages().list(
        userId="me",
        q=query,
        maxResults=20,
    ).execute()

    return results.get("messages", [])


def _header_value(headers, name):
    for header in headers or []:
        if header.get("name", "").lower() == name.lower():
            return header.get("value", "")
    return ""


def get_email_details(service, message_id):
    message = service.users().messages().get(
        userId="me",
        id=message_id,
        format="full",
    ).execute()

    payload = message.get("payload", {})
    headers = payload.get("headers", [])

    return {
        "From": _header_value(headers, "From") or "Unknown sender",
        "To": _header_value(headers, "To") or "Unknown recipient",
        "Subject": _header_value(headers, "Subject") or "",
        "Date": _header_value(headers, "Date") or "Unknown date",
        "Snippet": message.get("snippet", ""),
    }


def save_selected_email(service, message_id):
    response = service.users().messages().get(
        userId="me",
        id=message_id,
        format="raw",
    ).execute()

    raw_data = response.get("raw", "")

    email_bytes = base64.urlsafe_b64decode(
        raw_data + "=" * (-len(raw_data) % 4)
    )

    EMAIL_FILE.parent.mkdir(parents=True, exist_ok=True)
    EMAIL_FILE.write_bytes(email_bytes)


# ==========================================================
# BROWSER FORENSICS
# ==========================================================

def find_browser_csv():
    for path in BROWSER_CSV_CANDIDATES:
        if path.exists():
            return path

    try:
        matches = list(ROOT_DIR.glob("**/suspicious_urls_v3.csv"))
        if matches:
            return matches[0]
    except Exception:
        pass

    return None


def run_browser_analysis():
    if not BROWSER_SCRIPT.exists():
        st.error(f"Browser analysis script not found: {BROWSER_SCRIPT}")
        return False

    try:
        with st.spinner("Running browser analysis..."):
            result = subprocess.run(
                [sys.executable, str(BROWSER_SCRIPT)],
                cwd=str(ROOT_DIR),
                capture_output=True,
                text=True,
                timeout=180,
            )

        if result.returncode != 0:
            st.error("Browser analysis failed.")
            st.code(
                (result.stderr or result.stdout or "No error output.")[-12000:]
            )
            return False

        st.success("Browser analysis completed.")

        if result.stdout:
            with st.expander("Browser analysis output"):
                st.text(result.stdout)

        if find_browser_csv() is None:
            st.warning("Analysis finished, but suspicious_urls_v3.csv was not found.")
            return False

        return True

    except subprocess.TimeoutExpired:
        st.error("Browser analysis took too long and was stopped.")
    except Exception as error:
        st.error(f"Browser analysis failed: {error}")

    return False


def load_browser_results():
    csv_path = find_browser_csv()

    if csv_path is None:
        return None

    try:
        return pd.read_csv(csv_path)
    except Exception as error:
        st.error(f"Could not read browser results: {error}")
        return None


def browser_metrics(df):
    if df is None:
        return 0, 0, 0, "UNKNOWN"

    if "Status" not in df.columns:
        return len(df), 0, 0, "UNKNOWN"

    statuses = df["Status"].astype(str).str.strip().str.upper()

    total = len(df)
    phishing = int((statuses == "PHISHING").sum())
    benign = int((statuses == "BENIGN").sum())

    risk = (
        "LOW" if phishing == 0
        else "MEDIUM" if phishing <= 3
        else "HIGH"
    )

    return total, phishing, benign, risk


def show_browser_results():
    df = load_browser_results()

    if df is None:
        st.warning("Browser results CSV not found. Click Run Browser Analysis first.")
        return 0, 0, 0, "UNKNOWN"

    if "Status" not in df.columns:
        st.error("The results CSV does not contain a 'Status' column.")
        st.dataframe(df, use_container_width=True)
        return len(df), 0, 0, "UNKNOWN"

    total, phishing, benign, risk = browser_metrics(df)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total URLs", total)
    c2.metric("🔴 Phishing URLs", phishing)
    c3.metric("🟢 Benign URLs", benign)
    c4.metric("⚠️ Risk Level", risk)

    choice = st.selectbox(
        "Filter results",
        ["All", "PHISHING", "BENIGN"],
        key="browser_filter",
    )

    statuses = df["Status"].astype(str).str.strip().str.upper()
    shown = df if choice == "All" else df[statuses == choice]

    st.dataframe(shown, use_container_width=True, hide_index=True)

    st.download_button(
        "Download browser results CSV",
        data=shown.to_csv(index=False).encode("utf-8"),
        file_name="browser_forensics_results.csv",
        mime="text/csv",
    )

    return total, phishing, benign, risk


# ==========================================================
# EMAIL FORENSICS
# ==========================================================

def run_email_analysis():
    if not EMAIL_FILE.exists():
        st.error("Selected email was not saved. Select an email and analyze it first.")
        return

    main_script = EMAIL_DIR / "main.py"

    if not main_script.exists():
        st.error(f"Email forensic main.py not found in {EMAIL_DIR}")
        return

    try:
        with st.spinner("Running email forensics..."):
            result = subprocess.run(
                [sys.executable, str(main_script)],
                cwd=str(EMAIL_DIR),
                capture_output=True,
                text=True,
                timeout=300,
            )

        if result.returncode != 0:
            st.error("Email forensics failed.")
            st.code(
                (result.stderr or result.stdout or "No error output.")[-12000:]
            )
            return

        st.success("Email forensic analysis completed.")

        if EMAIL_REPORT.exists():
            report = EMAIL_REPORT.read_text(
                encoding="utf-8",
                errors="replace",
            )

            st.session_state.email_report_text = report

            st.text_area(
                "Forensic report preview",
                report[:10000],
                height=400,
                key="email_report_preview",
            )

        else:
            st.warning(f"Analysis finished, but report not found at {EMAIL_REPORT}")

        if result.stdout:
            with st.expander("Email forensic console output"):
                st.text(result.stdout)

    except subprocess.TimeoutExpired:
        st.error("Email analysis took too long and was stopped.")
    except Exception as error:
        st.error(f"Email analysis failed: {error}")


# ==========================================================
# PDF REPORT
# ==========================================================

def generate_pdf(total, phishing, benign, risk_level, email_report):
    if not PDF_MODULE.exists():
        raise FileNotFoundError(f"PDF generator not found: {PDF_MODULE}")

    spec = importlib.util.spec_from_file_location(
        "pdf_generator",
        str(PDF_MODULE),
    )

    if spec is None or spec.loader is None:
        raise ImportError("Could not load PDF generator module.")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    create_pdf_report = getattr(module, "create_pdf_report", None)

    if create_pdf_report is None:
        raise AttributeError("pdf_generator.py does not define create_pdf_report().")

    PDF_PATH.parent.mkdir(parents=True, exist_ok=True)

    available_values = {
        "output_path": str(PDF_PATH),
        "pdf_path": str(PDF_PATH),
        "total_urls": total,
        "phishing_urls": phishing,
        "benign_urls": benign,
        "risk_level": risk_level,
        "email_report": email_report,
        "report_text": email_report,
    }

    signature = inspect.signature(create_pdf_report)

    kwargs = {
        name: available_values[name]
        for name, parameter in signature.parameters.items()
        if name in available_values
        and parameter.kind not in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.VAR_POSITIONAL,
        )
    }

    create_pdf_report(**kwargs)

    if not PDF_PATH.exists():
        raise FileNotFoundError(
            f"PDF generator ran, but no PDF was created at {PDF_PATH}."
        )


# ==========================================================
# MAIN USER INTERFACE
# ==========================================================

st.title("🔍 AI-Based Browser & Email Forensics Engine")

browser_tab, email_tab = st.tabs(
    ["🌐 Browser Forensics", "📧 Email Forensics"]
)


with browser_tab:
    st.subheader("Browser Forensics")

    if st.button("🔍 Run Browser Analysis", key="run_browser_analysis"):
        run_browser_analysis()

    show_browser_results()


with email_tab:
    st.subheader("Gmail Email Forensics")

    st.write(
        "Connect Gmail, search by sender and date range, "
        "select an email, and run forensic analysis."
    )

    service = gmail_login_ui()

    sender = st.text_input(
        "Sender email address",
        placeholder="example@gmail.com",
    )

    col1, col2 = st.columns(2)

    with col1:
        start_date = st.date_input(
            "Start date",
            value=datetime.now().date() - timedelta(days=30),
        )

    with col2:
        end_date = st.date_input(
            "End date",
            value=datetime.now().date(),
        )

    if st.button("🔎 Search Gmail", key="search_gmail"):
        if not service:
            st.error("Connect Gmail first.")
        elif not sender.strip():
            st.error("Enter a sender email address.")
        elif start_date > end_date:
            st.error("Start date cannot be after end date.")
        else:
            try:
                with st.spinner("Searching Gmail..."):
                    st.session_state.gmail_messages = search_gmail(
                        service,
                        sender.strip(),
                        start_date,
                        end_date,
                    )

                if st.session_state.gmail_messages:
                    st.success(
                        f"{len(st.session_state.gmail_messages)} matching email(s) found."
                    )
                else:
                    st.warning("No matching emails found.")

            except HttpError as error:
                st.error(f"Gmail API error: {error}")
            except Exception as error:
                st.error(f"Gmail search failed: {error}")

    messages = st.session_state.gmail_messages

    if service and messages:
        options = []
        details_map = {}

        with st.spinner("Loading email details..."):
            for message in messages:
                try:
                    details = get_email_details(service, message["id"])

                    label = (
                        f"{details['Date']} | "
                        f"{details['Subject'] or '(No Subject)'} | "
                        f"{details['From']}"
                    )

                    options.append(label)
                    details_map[label] = (message["id"], details)

                except Exception:
                    continue

        if options:
            selected_label = st.selectbox(
                "Select an email",
                options,
                key="selected_email",
            )

            selected_id, details = details_map[selected_label]

            st.markdown("#### Selected email")
            st.write(f"**From:** {details['From']}")
            st.write(f"**To:** {details['To']}")
            st.write(f"**Subject:** {details['Subject'] or '(No Subject)'}")
            st.write(f"**Date:** {details['Date']}")

            if details.get("Snippet"):
                st.write(f"**Preview:** {details['Snippet']}")

            if st.button("🔍 Analyze Selected Email", key="analyze_selected_email"):
                try:
                    with st.spinner("Saving selected email..."):
                        save_selected_email(service, selected_id)

                    st.success("Selected email saved.")
                    run_email_analysis()

                except HttpError as error:
                    st.error(f"Could not download email: {error}")
                except Exception as error:
                    st.error(f"Email analysis failed: {error}")

        else:
            st.warning("Could not load details for returned messages. Try searching again.")

    elif messages and not service:
        st.warning("Reconnect Gmail to view and analyze your search results.")


# ==========================================================
# PDF DOWNLOAD
# ==========================================================

st.divider()
st.subheader("📄 Generate Forensic Report")

if st.button("📄 Generate PDF Report", key="generate_pdf_report"):
    try:
        df = load_browser_results()
        pdf_total, pdf_phishing, pdf_benign, pdf_risk = browser_metrics(df)

        generate_pdf(
            pdf_total,
            pdf_phishing,
            pdf_benign,
            pdf_risk,
            st.session_state.email_report_text,
        )

        st.success("PDF report generated successfully.")

        st.download_button(
            "⬇️ Download PDF Report",
            data=PDF_PATH.read_bytes(),
            file_name="AI_Forensics_Report.pdf",
            mime="application/pdf",
        )

    except Exception as error:
        st.error(f"PDF generation failed: {error}")


st.caption("AI-Based Browser & Email Forensics Engine")

if not logged_in:
    st.title("🔐 Browser Forensics")
    st.markdown("## Sign in required\n\nThis Browser Forensics application requires Google authentication.")
    st.button("🔵 Sign in with Google", on_click=st.login, use_container_width=True)
    st.info("Sign in with your Google account to continue.")
    st.stop()

with st.sidebar:
    st.success("✅ Google account authenticated")
    user_name = getattr(st.user, "name", "Google User")
    user_email = getattr(st.user, "email", "")
    st.markdown(f"### 👤 {user_name}")
    if user_email:
        st.caption(user_email)
    st.divider()
    st.button("🚪 Sign out", on_click=st.logout, use_container_width=True)
    st.divider()
    st.caption("AI-Based Browser Forensics")
    st.caption("Browser history + phishing URL analysis")

st.title("🌐 Browser Forensics")
st.write("Extract browser history and analyze visited URLs for phishing and suspicious activity.")


def find_result_file():
    for file_path in (RESULT_FILE_BROWSER, RESULT_FILE_ROOT):
        if os.path.isfile(file_path):
            return file_path
    return None


def normalize_status_column(df):
    df = df.copy()
    if "Status" not in df.columns:
        for column in ["Prediction", "Result", "Label", "Classification", "Risk", "Verdict"]:
            if column in df.columns:
                df["Status"] = df[column].astype(str).str.strip().str.upper()
                break
    if "Status" not in df.columns:
        df["Status"] = "UNKNOWN"
    df["Status"] = df["Status"].astype(str).str.strip().str.upper()
    return df.replace({"Status": {
        "NOT SAFE": "PHISHING", "UNSAFE": "PHISHING", "MALICIOUS": "PHISHING",
        "MALWARE": "PHISHING", "PHISH": "PHISHING", "SAFE": "BENIGN",
        "LEGITIMATE": "BENIGN", "NORMAL": "BENIGN", "RISKY": "SUSPICIOUS",
        "WARNING": "SUSPICIOUS",
    }})


def local_url_analysis(history_df):
    df = history_df.copy()
    if "URL" not in df.columns:
        return pd.DataFrame()
    results = []
    suspicious_words = [
        "login", "verify", "verification", "account", "secure", "security",
        "update", "password", "signin", "sign-in", "wallet", "bank",
        "confirm", "credential", "unlock", "suspended", "recover", "payment",
    ]
    suspicious_domains = [".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz",
                          ".click", ".work", ".zip", ".mov"]
    for _, row in df.iterrows():
        url = str(row.get("URL", "")).strip()
        lower_url = url.lower()
        score, reasons = 0, []
        if lower_url.startswith("http://"):
            score += 15
            reasons.append("Uses HTTP instead of HTTPS")
        if "://" in lower_url:
            host_part = lower_url.split("://", 1)[1].split("/", 1)[0]
            host_only = host_part.split(":")[0]
            parts = host_only.split(".")
            if len(parts) == 4 and all(part.isdigit() for part in parts):
                score += 30
                reasons.append("Uses an IP address instead of a domain")
        found_words = [word for word in suspicious_words if word in lower_url]
        if found_words:
            score += min(30, len(found_words) * 8)
            reasons.append("Contains security/account-related keywords: " + ", ".join(found_words[:5]))
        for tld in suspicious_domains:
            if tld in lower_url:
                score += 20
                reasons.append(f"Contains a higher-risk domain ending: {tld}")
                break
        if len(url) > 180:
            score += 15
            reasons.append("Unusually long URL")
        if "@" in lower_url:
            score += 25
            reasons.append("Contains @ symbol")
        if "://" in lower_url:
            host = lower_url.split("://", 1)[1].split("/", 1)[0].split(":")[0]
            if host.count(".") >= 4:
                score += 15
                reasons.append("Contains many subdomains")
        status = "PHISHING" if score >= 50 else "SUSPICIOUS" if score >= 20 else "BENIGN"
        result = row.to_dict()
        result["Status"] = status
        result["Risk Score"] = score
        result["Analysis"] = "; ".join(reasons) if reasons else "No significant URL risk indicators detected"
        results.append(result)
    return pd.DataFrame(results)


def calculate_statistics(df):
    if df.empty:
        return 0, 0, 0, 0, "LOW"
    status = df["Status"].astype(str).str.upper().str.strip()
    total = len(df)
    phishing = int((status == "PHISHING").sum())
    benign = int((status == "BENIGN").sum())
    suspicious = int(status.isin(["SUSPICIOUS", "UNKNOWN"]).sum())
    risk = "HIGH" if phishing >= 5 else "MEDIUM" if phishing >= 1 or suspicious >= 5 else "LOW"
    return total, phishing, benign, suspicious, risk


def run_browser_analysis(start_date, end_date):
    env = os.environ.copy()
    env["INVESTIGATION_START_DATE"] = str(start_date)
    env["INVESTIGATION_END_DATE"] = str(end_date)
    env["PYTHONUNBUFFERED"] = "1"
    return subprocess.run(
        [sys.executable, "-u", BROWSER_ANALYSIS_FILE],
        cwd=BROWSER_DIR, capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=env,
    )


def create_report(df, start_date, end_date, total, phishing, benign, suspicious, risk):
    report = [
        "============================================================",
        "             AI-BASED BROWSER FORENSIC REPORT",
        "============================================================", "",
        "INVESTIGATION INFORMATION", "------------------------------------------------------------",
        f"Investigation Start : {start_date}", f"Investigation End   : {end_date}", "",
        "BROWSER FORENSIC SUMMARY", "------------------------------------------------------------",
        f"Total URLs          : {total}", f"Phishing URLs       : {phishing}",
        f"Benign URLs         : {benign}", f"Suspicious URLs     : {suspicious}",
        f"Overall Risk        : {risk}", "", "URL ANALYSIS RESULTS",
        "------------------------------------------------------------",
    ]
    if df.empty:
        report.append("No browser records were found.")
    else:
        for index, row in df.iterrows():
            report.extend([
                f"Record              : {index + 1}",
                f"Browser             : {row.get('Browser', '')}",
                f"URL                 : {row.get('URL', '')}",
                f"Title               : {row.get('Title', '')}",
                f"Visit Time          : {row.get('Visit Time', '')}",
                f"Status              : {row.get('Status', '')}",
            ])
            for column, label in [("Confidence", "Confidence"), ("Risk Score", "Risk Score"), ("Analysis", "Analysis")]:
                if column in df.columns:
                    report.append(f"{label:<20}: {row.get(column, '')}")
            report.append("------------------------------------------------------------")
    report.extend(["", "End of Browser Forensic Report"])
    return "\n".join(report)


# Investigation period
st.divider()
st.header("📅 Investigation Period")
today = date.today()
default_start = today - timedelta(days=7)
col1, col2 = st.columns(2)
with col1:
    start_date = st.date_input("Start Date", value=default_start)
with col2:
    end_date = st.date_input("End Date", value=today)
if start_date > end_date:
    st.error("❌ Start Date cannot be after End Date.")
    st.stop()


# Local browser analysis
st.divider()
st.header("🔎 Browser Analysis")
if st.button("🔎 Run Browser Analysis", type="primary", use_container_width=True):
    st.session_state.analysis_complete = False
    st.session_state.browser_results = None
    st.session_state.analysis_start_date = start_date
    st.session_state.analysis_end_date = end_date
    if not os.path.isdir(BROWSER_DIR):
        st.error("❌ Browser folder was not found.")
        st.code(BROWSER_DIR)
        st.stop()
    if not os.path.isfile(BROWSER_ANALYSIS_FILE):
        st.error("❌ browser_analysis.py was not found.")
        st.code(BROWSER_ANALYSIS_FILE)
        st.stop()
    for old_result in (RESULT_FILE_BROWSER, RESULT_FILE_ROOT):
        if os.path.isfile(old_result):
            try:
                os.remove(old_result)
            except OSError:
                pass
    with st.spinner("🌐 Extracting browser history and analyzing URLs..."):
        result = run_browser_analysis(start_date, end_date)
    result_file = find_result_file()
    history_exists = os.path.isfile(HISTORY_FILE)
    if result.stdout:
        with st.expander("🌐 Browser Analysis Output", expanded=False):
            st.code(result.stdout)
    if result_file:
        try:
            result_df = normalize_status_column(pd.read_csv(result_file))
            st.session_state.browser_results = result_df
            st.session_state.analysis_complete = True
            st.session_state.analysis_start_date = start_date
            st.session_state.analysis_end_date = end_date
            if history_exists:
                st.success("✅ Browser history extraction completed.")
            st.success("✅ Browser URL analysis completed.")
        except Exception as error:
            st.error("❌ The analysis result was created but could not be read.")
            st.exception(error)
            st.stop()
    elif history_exists:
        try:
            history_df = pd.read_csv(HISTORY_FILE)
            if "Visit Time" in history_df.columns:
                history_df["Parsed Time"] = pd.to_datetime(history_df["Visit Time"], errors="coerce")
                start_timestamp = pd.Timestamp(start_date)
                end_timestamp = pd.Timestamp(end_date) + pd.Timedelta(days=1)
                filtered_df = history_df[
                    (history_df["Parsed Time"] >= start_timestamp)
                    & (history_df["Parsed Time"] < end_timestamp)
                ].copy()
                if filtered_df.empty:
                    filtered_df = history_df.copy()
            else:
                filtered_df = history_df.copy()
            fallback_df = local_url_analysis(filtered_df)
            if fallback_df.empty:
                st.error("❌ Browser history was found, but no URL records were available.")
                st.stop()
            fallback_df = normalize_status_column(fallback_df)
            fallback_df.to_csv(RESULT_FILE_BROWSER, index=False)
            st.session_state.browser_results = fallback_df
            st.session_state.analysis_complete = True
            st.session_state.analysis_start_date = start_date
            st.session_state.analysis_end_date = end_date
            st.success("✅ Browser history extracted and local URL-risk analysis completed.")
        except Exception as error:
            st.error("❌ Browser analysis could not be completed.")
            st.exception(error)
            if result.stderr:
                with st.expander("Technical Error Details", expanded=True):
                    st.code(result.stderr)
            st.stop()
    else:
        st.error("❌ Browser analysis failed and no history.csv was generated.")
        if result.stderr:
            with st.expander("Technical Error Details", expanded=True):
                st.code(result.stderr)
        st.stop()


# Display local results
if st.session_state.analysis_complete:
    df = st.session_state.browser_results
    if df is None:
        st.warning("No analysis results available.")
        st.stop()
    df = normalize_status_column(df.copy())
    total, phishing, benign, suspicious, risk = calculate_statistics(df)
    st.divider()
    st.header("📊 Browser Forensic Summary")
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("🌐 Total URLs", total)
    c2.metric("🔴 Phishing", phishing)
    c3.metric("🟢 Benign", benign)
    c4.metric("🟠 Suspicious", suspicious)
    c5.metric("⚠️ Risk", risk)
    st.info(f"📅 Investigation period: {st.session_state.analysis_start_date} → {st.session_state.analysis_end_date}")
    if risk == "HIGH":
        st.error("🔴 HIGH RISK: Multiple URLs were flagged. Review the evidence before drawing conclusions.")
    elif risk == "MEDIUM":
        st.warning("🟠 MEDIUM RISK: Potential URL risk indicators were detected.")
    else:
        st.success("🟢 LOW RISK: No significant risk indicators were detected.")
    st.warning("Automated classifications are indicators for review, not proof that a website is malicious. Validate model predictions before relying on these results.")
    phishing_df = df[df["Status"].astype(str).str.upper().str.strip() == "PHISHING"]
    st.divider()
    st.header("🔴 Detected Phishing URLs")
    if phishing_df.empty:
        st.success("No phishing URLs detected.")
    else:
        st.dataframe(phishing_df, use_container_width=True, hide_index=True)
    suspicious_df = df[df["Status"].astype(str).str.upper().str.strip().isin(["SUSPICIOUS", "UNKNOWN"])]
    st.divider()
    st.header("🟠 Suspicious URLs")
    if suspicious_df.empty:
        st.success("No suspicious URLs detected.")
    else:
        st.dataframe(suspicious_df, use_container_width=True, hide_index=True)
    st.divider()
    st.header("📥 Download Results")
    st.download_button("⬇️ Download Browser Analysis CSV", data=df.to_csv(index=False),
                       file_name="browser_forensic_results.csv", mime="text/csv",
                       use_container_width=True)
    st.divider()
    st.header("📄 Browser Forensic Report")
    report_text = create_report(df, st.session_state.analysis_start_date,
                                st.session_state.analysis_end_date, total,
                                phishing, benign, suspicious, risk)
    st.text_area("Forensic Report", report_text, height=500)
    st.download_button("⬇️ Download Browser Forensic Report", data=report_text,
                       file_name="browser_forensic_report.txt", mime="text/plain",
                       use_container_width=True)



# Chrome extension investigation
st.divider()
st.header("🧩 Chrome Extension Investigation")
st.write(
    "The latest investigation is fetched automatically when this "
    "dashboard section loads. The FastAPI backend must be running."
)

if "extension_investigation" not in st.session_state:
    st.session_state.extension_investigation = None

if "extension_fetch_error" not in st.session_state:
    st.session_state.extension_fetch_error = None


def fetch_latest_extension_investigation():
    if not EXTENSION_API_TOKEN:
        st.session_state.extension_fetch_error = (
            "API token is empty. Configure EXTENSION_API_TOKEN for Streamlit."
        )
        return

    try:
        response = requests.get(
            f"{EXTENSION_API_URL.rstrip('/')}/api/history/latest",
            headers={
                "Authorization": f"Bearer {EXTENSION_API_TOKEN}"
            },
            timeout=15,
        )

        if response.status_code == 404:
            st.session_state.extension_investigation = None
            st.session_state.extension_fetch_error = None
            return

        response.raise_for_status()
        data = response.json()

        if not isinstance(data, dict):
            raise ValueError("Backend response was not a JSON object.")

        st.session_state.extension_investigation = data
        st.session_state.extension_fetch_error = None

    except requests.RequestException as error:
        st.session_state.extension_fetch_error = (
            f"Could not contact {EXTENSION_API_URL}. "
            f"Confirm FastAPI is running. Details: {error}"
        )
    except ValueError as error:
        st.session_state.extension_fetch_error = str(error)


# Automatically fetch once per Streamlit session.
if not st.session_state.get("extension_auto_fetch_done", False):
    fetch_latest_extension_investigation()
    st.session_state.extension_auto_fetch_done = True

if st.button("🔄 Refresh Latest Investigation", type="primary"):
    fetch_latest_extension_investigation()

if st.session_state.extension_fetch_error:
    st.error(st.session_state.extension_fetch_error)

extension_investigation = st.session_state.extension_investigation

if not extension_investigation:
    st.info(
        "No investigation is available. Submit one through the Chrome "
        "extension, then click Refresh Latest Investigation."
    )
else:
    st.subheader("Extension Investigation Summary")

    st.write(
        f"**Investigation ID:** "
        f"{extension_investigation.get('investigation_id', 'Unknown')}"
    )
    st.write(
        f"**Status:** {extension_investigation.get('status', 'unknown')}"
    )
    st.write(
        f"**Date range:** "
        f"{extension_investigation.get('start_date', '')} to "
        f"{extension_investigation.get('end_date', '')}"
    )
    st.write(
        f"**Records received:** "
        f"{extension_investigation.get('record_count', 0)}"
    )

    extension_status = extension_investigation.get("status")
    extension_results = extension_investigation.get("analysis", [])

    if extension_status == "analysis_failed":
        st.error(
            "AI analysis failed: "
            + str(
                extension_investigation.get(
                    "analysis_error", "Unknown error"
                )
            )
        )

    elif extension_status == "analyzed":
        if not isinstance(extension_results, list) or not extension_results:
            st.info("Analysis completed, but no result rows were returned.")
        else:
            extension_df = pd.DataFrame(extension_results)

            # Normalize common field names returned by different analyzers.
            aliases = {
                "url": ["url", "URL", "visited_url", "website"],
                "title": ["title", "page_title", "website_title"],
                "status": [
                    "status", "prediction", "label",
                    "classification", "result"
                ],
            }

            display_df = pd.DataFrame(index=extension_df.index)

            for output_column, possible_names in aliases.items():
                for name in possible_names:
                    if name in extension_df.columns:
                        display_df[output_column] = extension_df[name]
                        break

            # Preserve any additional analysis fields.
            for column in extension_df.columns:
                if column not in display_df.columns:
                    display_df[column] = extension_df[column]

            if "status" in display_df.columns:
                statuses = (
                    display_df["status"]
                    .fillna("")
                    .astype(str)
                    .str.strip()
                    .str.upper()
                )
                phishing_total = int(
                    statuses.isin(["PHISHING", "MALICIOUS", "SUSPICIOUS"]).sum()
                )
                benign_total = int(
                    statuses.isin(["BENIGN", "SAFE", "LEGITIMATE"]).sum()
                )
            else:
                phishing_total = 0
                benign_total = 0

            col1, col2, col3 = st.columns(3)
            col1.metric("Analyzed Records", len(display_df))
            col2.metric("Flagged Phishing", phishing_total)
            col3.metric("Flagged Benign", benign_total)

            st.warning(
                "Automated model predictions are not proof of malicious "
                "activity. Verify suspicious results independently."
            )

            st.subheader("Analyzed Browser History")
            st.dataframe(
                display_df,
                use_container_width=True,
                hide_index=True,
            )

            st.download_button(
                "⬇️ Download Extension Analysis CSV",
                data=display_df.to_csv(index=False),
                file_name="extension_forensic_results.csv",
                mime="text/csv",
            )
    else:
        st.info("No completed analysis results are available yet.")
