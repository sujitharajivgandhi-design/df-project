import base64
import importlib.util
import inspect
import secrets
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlencode

import pandas as pd
import streamlit as st
import google.auth.transport.requests
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


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
# SESSION STATE
# ==========================================================

DEFAULTS = {
    "gmail_token": None,
    "gmail_messages": [],
    "gmail_service": None,
    "email_report_text": "",
    "oauth_state": None,
    "oauth_url": None,
    "oauth_code_verifier": None,
    "oauth_error": None,
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
        return (
            auth["client_id"],
            auth["client_secret"],
            auth["redirect_uri"],
        )
    except Exception:
        st.error(
            "Google OAuth settings are missing. Check the [auth] "
            "section in Streamlit Cloud Secrets."
        )
        return None


def create_oauth_flow(state=None, code_verifier=None):
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

    kwargs = {
        "client_config": client_config,
        "scopes": SCOPES,
        "state": state,
    }

    # Reuse the same PKCE verifier when handling the callback.
    if code_verifier:
        kwargs["code_verifier"] = code_verifier

    flow = Flow.from_client_config(**kwargs)
    flow.redirect_uri = redirect_uri
    return flow


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

        st.session_state.gmail_service = service
        return service

    except Exception as error:
        st.session_state.gmail_token = None
        st.session_state.gmail_service = None
        st.session_state.oauth_error = (
            "Gmail credentials could not be loaded. "
            "Please connect Gmail again. "
            f"Details: {error}"
        )
        return None


def clear_oauth_session():
    st.session_state.oauth_state = None
    st.session_state.oauth_url = None
    st.session_state.oauth_code_verifier = None


def handle_oauth_callback():
    """Handle Google's redirect after Gmail access is approved."""

    params = st.query_params
    code = params.get("code")
    returned_state = params.get("state")
    oauth_error = params.get("error")

    if oauth_error:
        st.session_state.oauth_error = str(oauth_error)
        clear_oauth_session()
        st.query_params.clear()
        return

    if not code:
        return

    expected_state = st.session_state.get("oauth_state")
    code_verifier = st.session_state.get("oauth_code_verifier")

    if not expected_state or returned_state != expected_state:
        st.session_state.oauth_error = (
            "Google sign-in state could not be verified. "
            "Please try connecting Gmail again."
        )
        clear_oauth_session()
        st.query_params.clear()
        return

    if not code_verifier:
        st.session_state.oauth_error = (
            "The OAuth code verifier is missing. "
            "Click Connect to Gmail and complete sign-in in "
            "the same browser session."
        )
        clear_oauth_session()
        st.query_params.clear()
        return

    settings = get_oauth_settings()
    if not settings:
        return

    _, _, redirect_uri = settings

    try:
        flow = create_oauth_flow(
            state=expected_state,
            code_verifier=code_verifier,
        )

        if flow is None:
            return

        callback_url = redirect_uri + "?" + urlencode({
            "code": code,
            "state": returned_state,
        })

        # Use the original verifier created before redirecting to Google.
        flow.fetch_token(authorization_response=callback_url)
        credentials = flow.credentials

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
        st.session_state.oauth_error = None

        clear_oauth_session()
        st.query_params.clear()
        st.rerun()

    except Exception as error:
        st.session_state.oauth_error = (
            "Google login failed. Verify the redirect URI and "
            "OAuth configuration in Google Cloud and Streamlit. "
            f"Details: {error}"
        )
        clear_oauth_session()
        st.query_params.clear()


def gmail_login_ui():
    handle_oauth_callback()

    if st.session_state.oauth_error:
        st.error(st.session_state.oauth_error)

    service = get_gmail_service()

    if service:
        st.success("Gmail connected successfully.")

        if st.button("Disconnect Gmail", key="disconnect_gmail"):
            st.session_state.gmail_token = None
            st.session_state.gmail_service = None
            st.session_state.gmail_messages = []
            st.session_state.oauth_error = None
            clear_oauth_session()
            st.rerun()

        return service

    st.info("Connect your Google account to search Gmail.")

    if st.button("Connect to Gmail", key="connect_gmail"):
        try:
            # Create and store the PKCE verifier before redirecting.
            code_verifier = secrets.token_urlsafe(64)

            flow = create_oauth_flow(
                code_verifier=code_verifier
            )

            if flow is not None:
                authorization_url, state = flow.authorization_url(
                    access_type="offline",
                    include_granted_scopes="true",
                    prompt="consent",
                )

                st.session_state.oauth_state = state
                st.session_state.oauth_url = authorization_url
                st.session_state.oauth_code_verifier = code_verifier
                st.session_state.oauth_error = None

        except Exception as error:
            st.session_state.oauth_error = (
                f"Could not start Google login: {error}"
            )
            clear_oauth_session()

    if st.session_state.oauth_url:
        st.link_button(
            "Continue to Google login",
            st.session_state.oauth_url,
            type="primary",
        )
        st.caption(
            "Complete Google sign-in in this same browser session."
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
                result.stderr or result.stdout or "No error output."
            )
            return False

        st.success("Browser analysis completed.")

        if result.stdout:
            with st.expander("Browser analysis output"):
                st.text(result.stdout)

        if find_browser_csv() is None:
            st.warning(
                "Analysis finished, but suspicious_urls_v3.csv "
                "was not found."
            )
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

    if phishing == 0:
        risk = "LOW"
    elif phishing <= 3:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    return total, phishing, benign, risk


def show_browser_results():
    df = load_browser_results()

    if df is None:
        st.warning(
            "Browser results CSV not found. "
            "Click Run Browser Analysis first."
        )
        return 0, 0, 0, "UNKNOWN"

    if "Status" not in df.columns:
        st.error("The results CSV does not contain a Status column.")
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

    st.dataframe(
        shown,
        use_container_width=True,
        hide_index=True,
    )

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
        st.error(
            "Selected email was not saved. Select an email and "
            "click Analyze Selected Email first."
        )
        return

    main_script = EMAIL_DIR / "main.py"

    if not main_script.exists():
        st.error(f"Email forensic main.py not found: {EMAIL_DIR}")
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
            st.code(result.stderr or result.stdout or "No error output.")
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

            if len(report) > 10000:
                st.info("The complete report will be used for the PDF.")
        else:
            st.warning(f"Report not found at {EMAIL_REPORT}")

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
        raise FileNotFoundError(
            f"PDF generator not found: {PDF_MODULE}"
        )

    spec = importlib.util.spec_from_file_location(
        "pdf_generator",
        str(PDF_MODULE),
    )

    if spec is None or spec.loader is None:
        raise ImportError("Could not load the PDF generator module.")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    create_pdf_report = getattr(module, "create_pdf_report", None)

    if create_pdf_report is None:
        raise AttributeError(
            "pdf_generator.py does not define create_pdf_report()."
        )

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
            f"PDF generator ran, but the PDF was not created: {PDF_PATH}"
        )


# ==========================================================
# MAIN USER INTERFACE
# ==========================================================

st.title("🔍 AI-Based Browser & Email Forensics Engine")

browser_tab, email_tab = st.tabs(
    ["🌐 Browser Forensics", "📧 Email Forensics"]
)


# ==========================================================
# BROWSER TAB
# ==========================================================

with browser_tab:
    st.subheader("Browser Forensics")

    if st.button(
        "🔍 Run Browser Analysis",
        key="run_browser_analysis",
    ):
        run_browser_analysis()

    show_browser_results()


# ==========================================================
# EMAIL TAB
# ==========================================================

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
                        f"{len(st.session_state.gmail_messages)} "
                        "matching email(s) found."
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
                    details = get_email_details(
                        service,
                        message["id"],
                    )

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
            st.write(
                f"**Subject:** {details['Subject'] or '(No Subject)'}"
            )
            st.write(f"**Date:** {details['Date']}")

            if details.get("Snippet"):
                st.write(f"**Preview:** {details['Snippet']}")

            if st.button(
                "🔍 Analyze Selected Email",
                key="analyze_selected_email",
            ):
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
            st.warning(
                "Could not load details for the returned messages. "
                "Try searching again."
            )

    elif messages and not service:
        st.warning(
            "Reconnect Gmail to view and analyze your search results."
        )


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



