
import csv
from pathlib import Path

from models.history_analyzer_v3 import analyze_history_v3

dataset_path = Path("dataset/benign_urls.csv")

# Read 10 URLs already labelled 0 in the local dataset.
with dataset_path.open("r", encoding="utf-8", newline="") as f:
    reader = csv.DictReader(f)
    records = []

    for row in reader:
        url = (row.get("text") or row.get("url") or "").strip()
        if url.startswith(("http://", "https://")):
            records.append({"url": url, "title": ""})
        if len(records) == 10:
            break

results = analyze_history_v3(records)

print("\nV3 results for the 10 locally labelled benign URLs")
for result in results:
    print(
        f"{result['url']} | "
        f"predicted_label={result['predicted_label']} | "
        f"class_probabilities={result['class_probabilities']}"
    )

print("\nNote: local label 0 is not yet proven to match V3 class 0.")
