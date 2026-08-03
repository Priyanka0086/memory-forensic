#!/usr/bin/env python3
"""
==========================================
COMBINED HOST ASSESSMENT PIPELINE
==========================================
Merges two original modules, unchanged logic:
  1. Host Compromise Assessment (threat_intel_output.json -> final_assessment.json)
  2. Combined Threat + Anomaly Fusion Scoring (threat_intel_output.json + anomaly_scores.json -> final_fusion_score.json)

Run from terminal:
    python3 host_assessment_pipeline.py
"""

import json
from pathlib import Path

# ==========================================
# MODULE 1: HOST COMPROMISE ASSESSMENT
# ==========================================

# ------------------------------------------
#  LOAD ENRICHED DATA
# ------------------------------------------

def load_data(file_path):
    with open(file_path, "r") as f:
        return json.load(f)

# ------------------------------------------
#  SCORING FUNCTION
# ------------------------------------------

def score_ioc(ioc_data):

    score = 0

    for entry in ioc_data["enrichment"]:

        source = entry.get("source")

        # ------------------------
        # VirusTotal
        # ------------------------
        if source == "VirusTotal":

            malicious = entry.get("malicious", 0)
            suspicious = entry.get("suspicious", 0)

            if malicious >= 10:
                score += 40
            elif malicious >= 5:
                score += 25

            if suspicious >= 5:
                score += 10

        # ------------------------
        # AbuseIPDB
        # ------------------------
        elif source == "AbuseIPDB":

            abuse_score = entry.get("abuse_score", 0)

            if abuse_score >= 80:
                score += 30
            elif abuse_score >= 50:
                score += 20
            elif abuse_score >= 20:
                score += 10

        # ------------------------
        # MalwareBazaar
        # ------------------------
        elif source == "MalwareBazaar":

            if entry.get("malware_family"):
                score += 35

    return score

# ------------------------------------------
#  ASSESSMENT ENGINE
# ------------------------------------------

def assess_host(enriched_data):

    total_score = 0
    detailed_results = []

    for ioc in enriched_data:

        ioc_score = score_ioc(ioc)
        total_score += ioc_score

        detailed_results.append({
            "ioc": ioc["ioc"],
            "type": ioc["type"],
            "score": ioc_score
        })

    # ------------------------
    # FINAL VERDICT
    # ------------------------
    if total_score >= 70:
        verdict = "COMPROMISED"
    elif total_score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "total_score": total_score,
        "verdict": verdict,
        "details": detailed_results
    }

# ------------------------------------------
#  SAVE OUTPUT
# ------------------------------------------

def save_output(data, file_path):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)

# ------------------------------------------
# RUN MODULE
# ------------------------------------------

def run_host_assessment_module():

    INPUT_FILE = "/content//drive/MyDrive/dataset/threat_intel_output.json"
    OUTPUT_FILE = "/content/drive/MyDrive/dataset/final_assessment.json"

    data = load_data(INPUT_FILE)

    result = assess_host(data)

    save_output(result, OUTPUT_FILE)

    print("🔥 Host Compromise Assessment Completed")
    print(f"📊 Total Score: {result['total_score']}")
    print(f"🚨 Verdict: {result['verdict']}")


# ==========================================
# MODULE 2: COMBINED THREAT + ANOMALY FUSION SCORING
# ==========================================

# ------------------------------------------
# LOAD JSON
# ------------------------------------------

def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

# ------------------------------------------
# NORMALIZE ANOMALY SCORE
# ------------------------------------------

def normalize_anomaly(anomaly_results):
    """
    Convert raw z-score sum into 0-100 scale
    """
    if not anomaly_results:
        return 0

    scores = [r["score"] for r in anomaly_results]

    max_score = max(scores)
    if max_score == 0:
        return 0

    # Take top suspicious process
    top_score = scores[0]

    normalized = (top_score / max_score) * 100
    return normalized

# ------------------------------------------
# THREAT SCORE (reuse your logic)
# ------------------------------------------

def compute_threat_score(threat_data):
    total = 0

    for ioc in threat_data:

        for entry in ioc["enrichment"]:
            source = entry.get("source")

            if source == "VirusTotal":
                malicious = entry.get("malicious", 0)
                suspicious = entry.get("suspicious", 0)

                if malicious >= 10:
                    total += 40
                elif malicious >= 5:
                    total += 25

                if suspicious >= 5:
                    total += 10

            elif source == "AbuseIPDB":
                abuse = entry.get("abuse_score", 0)

                if abuse >= 80:
                    total += 30
                elif abuse >= 50:
                    total += 20
                elif abuse >= 20:
                    total += 10

            elif source == "MalwareBazaar":
                if entry.get("malware_family"):
                    total += 35

    return total

# ------------------------------------------
# COMBINED SCORING
# ------------------------------------------

def combined_assessment(threat_data, anomaly_results):

    threat_score = compute_threat_score(threat_data)
    anomaly_score = normalize_anomaly(anomaly_results)

    # 🔥 WEIGHTS (tunable)
    W_THREAT = 0.6
    W_ANOMALY = 0.4

    final_score = (threat_score * W_THREAT) + (anomaly_score * W_ANOMALY)

    # ==================================
    # FINAL VERDICT
    # ==================================
    if final_score >= 70:
        verdict = "🔥 COMPROMISED"
    elif final_score >= 40:
        verdict = "⚠️ SUSPICIOUS"
    else:
        verdict = "✅ CLEAN"

    return {
        "threat_score": threat_score,
        "anomaly_score": anomaly_score,
        "final_score": final_score,
        "verdict": verdict
    }

# ------------------------------------------
# RUN MODULE (COLAB)
# ------------------------------------------

def run_fusion_module():

    # 🔹 INPUT FILES
    threat_file = "/content/drive/MyDrive/dataset/threat_intel_output.json"
    anomaly_file = "/content/drive/MyDrive/dataset/anomaly_scores.json"

    # 🔹 OUTPUT
    output_file = "/content/drive/MyDrive/dataset/final_fusion_score.json"

    print("[+] Loading data...")
    threat_data = load_json(threat_file)
    anomaly_data = load_json(anomaly_file)

    print("[+] Running combined scoring...")
    result = combined_assessment(threat_data, anomaly_data)

    Path(output_file).write_text(json.dumps(result, indent=4), encoding="utf-8")

    print("\n🔥 FINAL HOST ASSESSMENT")
    print(f"Threat Score   : {result['threat_score']}")
    print(f"Anomaly Score  : {result['anomaly_score']:.2f}")
    print(f"Final Score    : {result['final_score']:.2f}")
    print(f"Verdict        : {result['verdict']}")

    print(f"\n[✓] Saved to: {output_file}")


# ==========================================
# MAIN
# ==========================================

def main():
    print("========== MODULE 1: HOST COMPROMISE ASSESSMENT ==========")
    run_host_assessment_module()

    print("\n========== MODULE 2: THREAT + ANOMALY FUSION SCORING ==========")
    run_fusion_module()


if __name__ == "__main__":
    main()
