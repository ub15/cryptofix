"""
Ground truth annotation CLI.
Usage: python src/annotator.py
"""
import json
import os
from src.detector import MisuseDetector

GROUND_TRUTH_PATH = "results/ground_truth.json"

def load_existing():
    if os.path.exists(GROUND_TRUTH_PATH):
        with open(GROUND_TRUTH_PATH) as f:
            return json.load(f)
    return {}

def save(data):
    with open(GROUND_TRUTH_PATH, "w") as f:
        json.dump(data, f, indent=2)

def print_stats(ground_truth):
    all_labels = [m for v in ground_truth.values() for m in v]
    if not all_labels:
        print("No labels yet.")
        return
    tp = sum(1 for m in all_labels if m["label"] == 1)
    fp = sum(1 for m in all_labels if m["label"] == 0)
    precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
    print(f"\n{'='*40}")
    print(f"ANNOTATION SUMMARY")
    print(f"Files annotated: {len(ground_truth)}")
    print(f"Total misuses labeled: {len(all_labels)}")
    print(f"True positives: {tp}")
    print(f"False positives: {fp}")
    print(f"Detector precision: {precision:.1f}%")
    from collections import defaultdict
    by_rule = defaultdict(lambda: {"tp": 0, "fp": 0})
    for m in all_labels:
        by_rule[m["rule_id"]]["tp" if m["label"]==1 else "fp"] += 1
    print(f"\nBy rule:")
    for rule, counts in sorted(by_rule.items()):
        t, f = counts["tp"], counts["fp"]
        p = t/(t+f)*100 if (t+f) > 0 else 0
        print(f"  {rule}: {t} TP, {f} FP, precision={p:.0f}%")

def annotate(data_dir):
    detector = MisuseDetector()
    ground_truth = load_existing()

    all_files = sorted([
        os.path.join(data_dir, f)
        for f in os.listdir(data_dir)
        if f.endswith(".py") and not f.startswith("_")
    ])

    total_labeled = sum(len(v) for v in ground_truth.values())
    print(f"Resuming. Already labeled: {total_labeled} misuses across {len(ground_truth)} files.")
    print("Commands: 1=True Positive  0=False Positive  s=Skip file  q=Quit\n")

    for filepath in all_files:
        filename = filepath.split("/")[-1]
        if filename in ground_truth:
            continue

        result = detector.analyze_file(filepath)
        if result.get("error") or result["total"] == 0:
            continue

        try:
            source = open(filepath, encoding="utf-8", errors="ignore").read()
        except:
            continue

        print(f"\n{'='*60}")
        print(f"FILE: {filename}  ({len(source)} chars)")

        file_labels = []
        skip = False

        for i, misuse in enumerate(result["misuses"]):
            print(f"\n  Misuse {i+1}/{result['total']}:")
            print(f"    Rule:     [{misuse['rule_id']}] {misuse['rule']['description']}")
            print(f"    Line {misuse['lineno']}: {misuse.get('evidence','')}")
            lines = source.split("\n")
            start = max(0, misuse["lineno"] - 3)
            end = min(len(lines), misuse["lineno"] + 2)
            print(f"    Context:")
            for j, line in enumerate(lines[start:end], start=start+1):
                marker = ">>>" if j == misuse["lineno"] else "   "
                print(f"      {marker} {j:4d}: {line}")

            while True:
                ans = input(f"\n  Label (1=TP, 0=FP, s=skip, q=quit): ").strip().lower()
                if ans in ("1", "0"):
                    file_labels.append({
                        "rule_id": misuse["rule_id"],
                        "lineno": misuse["lineno"],
                        "evidence": misuse.get("evidence", ""),
                        "label": int(ans),
                        "label_str": "TP" if ans == "1" else "FP"
                    })
                    break
                elif ans == "s":
                    skip = True
                    break
                elif ans == "q":
                    save(ground_truth)
                    print_stats(ground_truth)
                    return
                else:
                    print("  Invalid. Use 1, 0, s, or q.")

            if skip:
                break

        if not skip and file_labels:
            ground_truth[filename] = file_labels
            save(ground_truth)
            print(f"  Saved. Total labeled: {sum(len(v) for v in ground_truth.values())}")

    save(ground_truth)
    print_stats(ground_truth)

if __name__ == "__main__":
    annotate("data/github_expanded")
