import os
import sys

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import hstack
from urllib.parse import urlparse


print("======================================")
print("   AI PHISHING URL ANALYSIS - V3")
print("======================================")


# ==========================================================
# PATHS
# ==========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

MODEL_PATH = os.path.join(
    BASE_DIR, "models", "phishing_url_model_v3.joblib"
)

VECTORIZER_PATH = os.path.join(
    BASE_DIR, "models", "phishing_url_vectorizer_v3.joblib"
)

HISTORY_PATH = os.path.join(
    BASE_DIR, "history.csv"
)

OUTPUT_PATH = os.path.join(
    BASE_DIR, "suspicious_urls_v3.csv"
)


# ==========================================================
# URL STRUCTURAL FEATURES
# Must match the feature format used during model training.
# ==========================================================

def extract_url_features(url):
    url = str(url)

    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query

        return [
            len(url),
            len(domain),
            len(path),
            len(query),
            domain.count("."),
            domain.count("-"),
            domain.count("_"),
            url.count("/"),
            url.count("?"),
            url.count("="),
            url.count("&"),
            url.count("%"),
            sum(c.isdigit() for c in url),
            sum(c.isalpha() for c in url),
            int(url.startswith("https://")),
            int(url.startswith("http://")),
            int("@" in url),
            int("://" in url),
            len(set(domain)),
        ]

    except Exception:
        return [0] * 19


# ==========================================================
# CHECK REQUIRED FILES
# ==========================================================

for file_path, description in [
    (MODEL_PATH, "V3 AI model"),
    (VECTORIZER_PATH, "V3 vectorizer"),
    (HISTORY_PATH, "Browser history CSV"),
]:
    if not os.path.exists(file_path):
        print(f"\nERROR: {description} not found:")
        print(file_path)
        raise SystemExit(1)


# ==========================================================
# LOAD MODEL AND HISTORY
# ==========================================================

print("\nLoading V3 AI phishing model...")

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

print("V3 AI model loaded successfully.")

print("\nLoading browser history...")

df = pd.read_csv(HISTORY_PATH)

if "URL" not in df.columns:
    print("ERROR: URL column not found in history.csv")
    print("Available columns:", df.columns.tolist())
    raise SystemExit(1)

df = df.dropna(subset=["URL"]).copy()
df["URL"] = df["URL"].astype(str).str.strip()
df = df[df["URL"] != ""]

unique_urls = df["URL"].drop_duplicates().tolist()

print(f"\nTotal unique URLs to analyze: {len(unique_urls)}")

if not unique_urls:
    empty_df = pd.DataFrame(
        columns=[
            "Browser",
            "URL",
            "Status",
            "Confidence",
            "Visit Time",
        ]
    )
    empty_df.to_csv(OUTPUT_PATH, index=False)
    print("No URLs available for analysis.")
    print("Empty results saved to:", OUTPUT_PATH)
    raise SystemExit(0)


# ==========================================================
# FEATURE EXTRACTION
# ==========================================================

print("\nCreating TF-IDF features...")

url_tfidf = vectorizer.transform(unique_urls)

print("Creating structural URL features...")

url_structural = np.asarray(
    [extract_url_features(url) for url in unique_urls],
    dtype=float,
)

print("Combining AI features...")

# The V3 model must have been trained with TF-IDF + these
# same 19 structural features. Otherwise, use its matching
# training pipeline rather than combining incompatible inputs.
url_features = hstack(
    [url_tfidf, url_structural],
    format="csr",
)


# ==========================================================
# PREDICTION
# ==========================================================

print("\nRunning AI predictions...")

predictions = model.predict(url_features)
probabilities = model.predict_proba(url_features)

classes = list(model.classes_)

# Treat class 1 as phishing only if that label exists.
phishing_label = 1 if 1 in classes else None

if phishing_label is None:
    print(
        "WARNING: Model has no class labelled 1. "
        "Check the model's training labels."
    )

phishing_index = (
    classes.index(phishing_label)
    if phishing_label in classes
    else None
)

results = []

for url, prediction, probability in zip(
    unique_urls,
    predictions,
    probabilities,
):
    is_phishing = (
        phishing_index is not None
        and prediction == phishing_label
    )

    status = "PHISHING" if is_phishing else "BENIGN"

    confidence_index = classes.index(prediction)
    confidence = float(probability[confidence_index]) * 100

    matching_rows = df[df["URL"] == url]

    browsers = (
        matching_rows["Browser"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
        if "Browser" in matching_rows.columns
        else []
    )

    visit_times = (
        matching_rows["Visit Time"]
        .dropna()
        .astype(str)
        .tolist()
        if "Visit Time" in matching_rows.columns
        else []
    )

    results.append(
        {
            "Browser": ", ".join(browsers) or "Unknown",
            "URL": url,
            "Status": status,
            "Confidence": round(confidence, 2),
            "Visit Time": visit_times[0] if visit_times else "",
        }
    )


# ==========================================================
# SAVE RESULTS
# ==========================================================

result_df = pd.DataFrame(results)
result_df.to_csv(OUTPUT_PATH, index=False)

total = len(result_df)
phishing = int((result_df["Status"] == "PHISHING").sum())
benign = int((result_df["Status"] == "BENIGN").sum())

if phishing == 0:
    risk_level = "LOW"
elif phishing <= 3:
    risk_level = "MEDIUM"
else:
    risk_level = "HIGH"

print("\n======================================")
print("V3 ANALYSIS SUMMARY")
print("======================================")
print(f"Total URLs analyzed: {total}")
print(f"Phishing URLs: {phishing}")
print(f"Benign URLs: {benign}")
print(f"Overall Browser Risk Level: {risk_level}")

print("\nResults preview:")
print(result_df.head(20).to_string(index=False))

print("\nResults saved to:")
print(OUTPUT_PATH)

print("\nBROWSER ANALYSIS COMPLETED")
print("======================================")

