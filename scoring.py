import json
import argparse
import math


# -----------------------------
# FLATTEN FEATURES
# -----------------------------
def flatten_features(process_data):
    flat = {}

    for section, values in process_data.items():
        if isinstance(values, dict):
            for k, v in values.items():
                if isinstance(v, (int, float)):
                    flat[f"{section}.{k}"] = v

    return flat


# -----------------------------
# LOAD JSON
# -----------------------------
def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


# -----------------------------
# COMPUTE BASELINE STATS
# -----------------------------
def compute_stats(baseline):
    stats = {}

    for pid, proc in baseline["processes"].items():
        features = flatten_features(proc)

        for key, val in features.items():
            stats.setdefault(key, []).append(val)

    # compute mean & std
    final_stats = {}
    for key, values in stats.items():
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std = math.sqrt(variance)

        final_stats[key] = {"mean": mean, "std": std}

    return final_stats


# -----------------------------
# SCORING
# -----------------------------
def score_snapshots(baseline, current):
    stats = compute_stats(baseline)
    results = []

    for pid, proc in current["processes"].items():
        features = flatten_features(proc)

        score = 0
        details = {}

        for key, val in features.items():
            if key in stats:
                mean = stats[key]["mean"]
                std = stats[key]["std"]

                if std > 0:
                    z = abs((val - mean) / std)
                else:
                    z = 0

                details[key] = z
                score += z

        results.append({
            "pid": pid,
            "score": score,
            "feature_scores": details
        })

    return results


# -----------------------------
# MAIN
# -----------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--current", required=True)
    parser.add_argument("--out", required=True)

    args = parser.parse_args()

    baseline = load_json(args.baseline)
    current = load_json(args.current)

    results = score_snapshots(baseline, current)

    with open(args.out, "w") as f:
        json.dump(results, f, indent=4)

    print(f"[+] Scoring complete. Output: {args.out}")


if __name__ == "__main__":
    main()