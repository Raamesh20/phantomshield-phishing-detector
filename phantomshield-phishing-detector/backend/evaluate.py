import csv
from detector import analyze_url

CSV_PATH = "test_urls.csv"

total = 0
correct = 0
tp = fp = tn = fn = 0

print("\nDetailed Results:")
print("-" * 80)

with open(CSV_PATH, newline="", encoding="utf-8-sig") as f:
    reader = csv.DictReader(f)
    for row in reader:
        url = row["url"].strip()
        label = row["label"].strip().lower()

        result = analyze_url(url)
        verdict = result.get("verdict", "")
        score = result.get("risk_score", 0)

        predicted_phishing = verdict in [
            "High Confidence Phishing",
            "Likely Phishing",
            "Suspicious",
        ]
        actual_phishing = label == "phishing"

        total += 1

        if predicted_phishing == actual_phishing:
            correct += 1

        if predicted_phishing and actual_phishing:
            tp += 1
        elif predicted_phishing and not actual_phishing:
            fp += 1
        elif not predicted_phishing and not actual_phishing:
            tn += 1
        elif not predicted_phishing and actual_phishing:
            fn += 1

        print(f"URL: {url}")
        print(f"Actual: {label} | Predicted: {verdict} | Score: {score}")
        print("-" * 80)

accuracy = correct / total if total else 0
precision = tp / (tp + fp) if (tp + fp) else 0
recall = tp / (tp + fn) if (tp + fn) else 0
f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0

print("\nSummary:")
print(f"Total: {total}")
print(f"Accuracy: {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall: {recall:.4f}")
print(f"F1-score: {f1:.4f}")
print(f"TP={tp}, FP={fp}, TN={tn}, FN={fn}")