#!/usr/bin/env python3
"""
======================================================================
MODULE 13: LLM REASONING ENGINE
======================================================================

Purpose:
    Final analytical stage before report generation. Takes the outputs
    of every upstream module -- correlated evidence, baseline
    deviations, threat intelligence, and the fused host-compromise
    score -- and asks an LLM (Google Gemini) to reason over all of it
    and produce an analyst-grade narrative.

Pipeline position:

    evidence.json (Module 9/10)  ---
    baseline_comparison.json      ---
    threat_intel_output.json      ---> LLM Reasoning Engine  --> llm_reasoning_output.json --> Module 14 (Report)
    final_fusion_score.json       ---/  (this script)
    (Module 12 host compromise)  ---/

Inputs (per architecture diagram, Module 13):
    - Timeline             (built here from correlated evidence)
    - Evidence Graph        (post_evidence.json -- during/incident snapshot)
    - Baseline Evidence Graph (pre_evidence.json -- pre/known-good snapshot, optional)
    - Threat Intelligence   (threat_intel_output.json)
    - Host Score            (final_fusion_score.json / final_assessment.json)

The baseline (pre_evidence.json) evidence graph is included so the LLM can
reason about what is genuinely NEW/anomalous in the incident snapshot versus
what was already present (and presumably benign) at baseline, rather than
treating every flagged feature as equally suspicious.

Outputs (per architecture diagram, Module 13):
    - attack_narrative
    - what_happened
    - why
    - recommendations
    - attribution

======================================================================
"""

import json
import os
import sys
from pathlib import Path

try:
    from google import genai
    from google.genai import types
except ImportError:
    print("[!] Missing dependency. Install it with:")
    print("    pip install google-genai")
    sys.exit(1)


# ================================================================
# CONFIG
# ================================================================

# Reads from environment by default -- do NOT hardcode real keys in
# a notebook that you might share/commit.
# It's recommended to store your API key securely, e.g., in Colab Secrets or environment variables.
# For demonstration, you can uncomment the line below and replace 'YOUR_API_KEY' with your actual key.
# os.environ['GEMINI_API_KEY'] = 'YOUR_API_KEY' # <--- ADD YOUR API KEY HERE
# Removed GEMINI_API_KEY global variable declaration here to ensure main() picks it up dynamically

MODEL = "gemini-3.5-flash"   # swap for a "pro"-tier Gemini model if you want deeper reasoning over speed/cost
MAX_TOKENS = 12000           # raised from 4000 -- large incidents were getting truncated mid-JSON

# Caps on how much upstream data gets sent to the model per run.
# Keeps the prompt (and therefore the required output) within budget
# even on very large incidents. Raise/lower as needed.
MAX_TIMELINE_EVENTS = 150
MAX_EVIDENCE_PROCESSES = 30
MAX_BASELINE_PROCESSES = 30

# 🔹 INPUT FILES (outputs of earlier modules)
EVIDENCE_FILE = "/content/drive/MyDrive/dataset/Asynrat/evidence.json"          # Module 9/10 (during/incident snapshot)
PRE_EVIDENCE_FILE = "/content/drive/MyDrive/dataset/Asynrat/preevidence.json"       # Module 9/10 (pre/baseline snapshot, optional)
BASELINE_FILE = "/content/drive/MyDrive/dataset/Asynrat/baseline_comparison.json"    # Module 9 (optional)
THREAT_INTEL_FILE = "/content/drive/MyDrive/dataset/Asynrat/threat_intel_output.json"  # Module 11
HOST_SCORE_FILE = "/content/drive/MyDrive/dataset/Asynrat/final_fusion_score.json"   # Module 12

# 🔹 OUTPUT FILE
OUTPUT_FILE = "/content/drive/MyDrive/dataset/llm_reasoning_output.json"


# ================================================================
# LOAD HELPERS
# ================================================================

def load_json(path, default=None):
    """Load a JSON file, tolerating missing upstream modules."""
    p = Path(path)
    if not p.exists():
        print(f"[!] Not found, skipping: {path}")
        return default if default is not None else {}
    return json.loads(p.read_text(encoding="utf-8"))


# ================================================================
# BUILD TIMELINE
# ================================================================

def build_timeline(evidence_data):
    """
    Flattens per-process evidence into a chronologically-agnostic,
    severity-ordered timeline of events. Real timestamps (if present
    on evidence items) are used when available; otherwise events are
    ordered by severity so the most significant activity leads.
    """

    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    events = []

    processes = evidence_data.get("processes", evidence_data)

    if not isinstance(processes, dict):
        return events

    for pid, proc in processes.items():
        process_name = proc.get("process_name", pid)

        for item in proc.get("evidence", []):
            events.append({
                "pid": pid,
                "process": process_name,
                "feature": item.get("feature"),
                "severity": item.get("severity", "INFO"),
                "reason": item.get("reason"),
                "mitre": item.get("mitre"),
                "timestamp": item.get("timestamp"),  # may be None
            })

    events.sort(key=lambda e: (
        e["timestamp"] is None,
        e["timestamp"] or "",
        severity_rank.get(e["severity"], 5),
    ))

    return events


# ================================================================
# BUILD EVIDENCE GRAPH (compact summary, not raw dump)
# ================================================================

def build_evidence_graph(evidence_data):
    """
    Summarizes evidence.json into a compact per-process graph node:
    risk, confidence, score, and top evidence -- so the prompt stays
    within a reasonable token budget even on large incidents.
    """

    processes = evidence_data.get("processes", evidence_data)

    graph = []

    if not isinstance(processes, dict):
        return graph

    for pid, proc in processes.items():
        graph.append({
            "pid": pid,
            "process_name": proc.get("process_name", pid),
            "risk": proc.get("risk") or proc.get("risk_level"),
            "confidence": proc.get("confidence"),
            "score": proc.get("score") or proc.get("risk_score"),
            "top_evidence": [
                {
                    "feature": e.get("feature"),
                    "severity": e.get("severity"),
                    "mitre": e.get("mitre"),
                }
                for e in proc.get("evidence", [])[:8]
            ],
        })

    # Most suspicious processes first
    graph.sort(key=lambda g: g.get("score") or 0, reverse=True)

    return graph


# ================================================================
# SUMMARIZE THREAT INTEL (compact)
# ================================================================

def summarize_threat_intel(threat_data):
    if not threat_data:
        return []

    summary = []
    for ioc in threat_data if isinstance(threat_data, list) else threat_data.get("iocs", []):
        entry = {
            "ioc": ioc.get("ioc"),
            "type": ioc.get("type"),
            "enrichment": [],
        }
        for e in ioc.get("enrichment", []):
            entry["enrichment"].append({
                "source": e.get("source"),
                "malicious": e.get("malicious"),
                "abuse_score": e.get("abuse_score"),
                "malware_family": e.get("malware_family"),
                "reputation": e.get("reputation"),
            })
        summary.append(entry)

    return summary


# ================================================================
# PROMPT CONSTRUCTION
# ================================================================

SYSTEM_PROMPT = """You are the LLM Reasoning Engine stage of an automated memory-forensics
pipeline (Sysmon-triggered, Volatility/Velociraptor-based). You receive
already-computed, structured outputs from upstream modules: a
severity-ordered timeline, a per-process evidence graph for the
incident ("during") snapshot, an optional evidence graph for the
pre-incident ("baseline") snapshot of the same host, threat-intel
enrichment for observed IoCs, and a fused host-compromise score.

Your job is NOT to re-detect anomalies -- that has already happened.
Your job is to reason over what has already been detected, connect it
into a coherent story, and produce an analyst-grade explanation that a
Tier-2/Tier-3 SOC analyst could act on without re-reading raw logs.

REASONING APPROACH (do this before you write the final JSON):
1. Establish the kill-chain / attack-lifecycle position of each notable
   process (initial access, execution, persistence, privilege
   escalation, defense evasion, credential access, discovery, lateral
   movement, collection, C2, exfiltration, impact). Use MITRE ATT&CK
   tactic/technique IDs already present in the evidence where possible;
   do not fabricate IDs that aren't supported by the data or well-known
   technique definitions.
2. Build the causal chain between processes: which process likely
   spawned, injected into, or handed off to which other process/PID,
   and in what order, using timestamps where present and severity/logic
   otherwise.
3. Cross-reference the incident evidence graph against the baseline
   evidence graph (if provided): flag anything NEW, ESCALATED (higher
   severity/score than at baseline), or MISSING-BUT-EXPECTED. Treat
   baseline-consistent, unescalated evidence as low-signal noise rather
   than an indicator of compromise.
4. Cross-reference threat intelligence: tie any malicious/verified IOC
   directly to the specific process/PID or evidence item it came from,
   and note reputation/abuse scores or malware family attributions
   supplied. If an IOC is present but enrichment is inconclusive or
   benign, say so rather than treating its mere presence as malicious.
5. Weigh the fused host-compromise score against your own read of the
   evidence. If your narrative and the host score disagree, call that
   out explicitly and explain the discrepancy instead of silently
   picking one.
6. Actively consider alternative, benign explanations (admin tooling,
   software updates, backup jobs, known-noisy EDR/AV behavior) before
   settling on a malicious interpretation, and note when evidence is
   too sparse/ambiguous to distinguish between them.

When a baseline evidence graph is provided, use it as ground truth for
"normal" on this host: evidence/processes that also appear in the
baseline are less significant on their own, while evidence that is new
in the incident snapshot (or has escalated in severity/score versus
baseline) should be weighted more heavily and called out explicitly.
If no baseline evidence graph is provided (empty list), reason from the
incident evidence graph alone and say so.

IMPORTANT LENGTH CONSTRAINT: Be concise but information-dense. Every
sentence should carry a specific fact (a PID, process name, technique
ID, IOC, or score) rather than generic filler. "attack_narrative"
should be at most 6-8 sentences and should read as a chronological
story with named actors (processes/PIDs). "what_happened" should be at
most 4-5 sentences of confirmed, evidence-grounded observations only
(no speculation). "why" should be at most 5-6 sentences explaining the
reasoning chain from evidence to verdict. Recommendations should be
short, specific, prioritized, actionable bullet-style strings (one
sentence each, ideally naming the specific PID/process/IOC/host
artifact to act on), no more than 6-8 of them, ordered from most to
least urgent. This is a fixed-size JSON report field, not a full
incident report -- prioritize the most important, highest-confidence,
most specific points over exhaustive or generic detail.

Respond with ONLY a single JSON object (no markdown fences, no prose
outside the JSON) with exactly these keys:

{
  "attack_narrative": "<a chronological, plain-English narrative of how the incident likely unfolded, referencing specific processes/PIDs, techniques, and (if present) IOCs/timestamps, in the order events likely occurred>",
  "what_happened": "<concise factual summary of the confirmed observations, grounded only in the provided data>",
  "why": "<explanation of why these observations indicate compromise (or don't), reasoning explicitly from evidence to conclusion, including how baseline comparison and threat intel influenced the verdict>",
  "key_evidence": [
    {
      "pid": "<pid or null>",
      "process": "<process name or null>",
      "signal": "<the specific feature/technique/IOC that matters>",
      "significance": "<one sentence on why this specific item is the strongest support for the verdict>",
      "new_or_baseline": "new|escalated|baseline_consistent|unknown"
    }
  ],
  "severity_assessment": {
    "overall_verdict": "Benign|Suspicious|Likely Compromised|Confirmed Compromised",
    "host_score_agreement": "agrees|disagrees|partial",
    "rationale": "<1-2 sentences reconciling your verdict with the fused host-compromise score>"
  },
  "alternative_explanations": "<1-3 sentences on plausible benign explanations you considered and why you ruled them in/out, or 'None considered plausible given the evidence' if truly none>",
  "recommendations": ["<action item 1, ideally naming a specific PID/process/host artifact>", "<action item 2>", "..."],
  "attribution": {
    "likely_technique_ids": ["T####", "..."],
    "kill_chain_stages": ["<e.g. Initial Access, Execution, Persistence, ...>"],
    "possible_actor_or_family": "<name if threat intel supports it, else 'Unknown'>",
    "confidence": "Low|Medium|High",
    "rationale": "<1-3 sentences tying attribution back to specific evidence, IOCs, or technique IDs actually present in the input>"
  }
}

Rules:
- Ground every claim in the provided data. Do not invent PIDs, IPs, hashes, technique IDs, or timestamps not present in (or directly inferable from) the input.
- If evidence is weak, sparse, or contradictory, say so explicitly in "why" and "alternative_explanations", and lower your confidence rather than overstating certainty.
- If the host score / verdict indicates the host is clean, "attack_narrative", "severity_assessment", and "attribution" should reflect that plainly rather than manufacturing an incident.
- Distinguish evidence that is new/escalated versus baseline from evidence that was already present at baseline; do not treat baseline-consistent findings as strong indicators of compromise.
- Prefer specificity over hedging: name the PID/process/IOC responsible for each claim rather than referring to "some processes" or "certain activity."
- Keep the JSON valid and parseable. Always finish the JSON object completely -- never truncate mid-field. If you are close to the token limit, shorten prose fields (not by dropping keys) so the JSON still closes cleanly.
"""


def build_user_prompt(timeline, evidence_graph, baseline_evidence_graph, threat_intel, host_score):
    payload = {
        "timeline": timeline,
        "evidence_graph": evidence_graph,
        "baseline_evidence_graph": baseline_evidence_graph,
        "threat_intelligence": threat_intel,
        "host_score": host_score,
    }
    return (
        "Here is the structured forensic data for this incident.\n\n"
        "SECTION GUIDE:\n"
        "- timeline: severity/time-ordered list of individual evidence events "
        "across all processes (fields: pid, process, feature, severity, reason, mitre, timestamp).\n"
        "- evidence_graph: per-process summary for the INCIDENT snapshot, sorted "
        "most-suspicious first (fields: pid, process_name, risk, confidence, score, top_evidence).\n"
        "- baseline_evidence_graph: same shape as evidence_graph but for the "
        "PRE-INCIDENT snapshot of this host -- use it to tell new/escalated "
        "activity apart from pre-existing, presumably benign activity. Empty "
        "list means no baseline was available.\n"
        "- threat_intelligence: enrichment for observed IOCs (fields: ioc, type, "
        "enrichment[].source/malicious/abuse_score/malware_family/reputation).\n"
        "- host_score: the fused host-compromise score/verdict from the upstream "
        "scoring module (and baseline_deviations if present), to be reconciled "
        "with your own read of the evidence in severity_assessment.\n\n"
        "DATA:\n"
        + json.dumps(payload, indent=2, default=str)
        + "\n\nProduce the JSON object described in your instructions."
    )


# ================================================================
# LLM CALL
# ================================================================

def run_llm_reasoning(client, timeline, evidence_graph, baseline_evidence_graph, threat_intel, host_score):
    user_prompt = build_user_prompt(timeline, evidence_graph, baseline_evidence_graph, threat_intel, host_score)

    response = client.models.generate_content(
        model=MODEL,
        contents=user_prompt,
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            max_output_tokens=MAX_TOKENS,
            response_mime_type="application/json",
        ),
    )

    # Diagnostic: log why generation stopped. If this prints something
    # other than STOP (e.g. MAX_TOKENS), the response was cut off and
    # you need to raise MAX_TOKENS and/or trim the input further.
    try:
        finish_reason = response.candidates[0].finish_reason
        print(f"[debug] finish_reason: {finish_reason}")
    except Exception:
        pass

    text = (response.text or "").strip()
    print(f"[debug] response length: {len(text)} chars")

    # Strip accidental markdown fences, just in case
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:].strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        print(f"[!] Model did not return valid JSON. Error: {e}")
        return {
            "attack_narrative": None,
            "what_happened": None,
            "why": None,
            "recommendations": [],
            "attribution": None,
            "raw_response": text,
        }


# ================================================================
# MAIN
# ================================================================

def main():
    # Get GEMINI_API_KEY directly from environment just before use
    api_key = os.environ.get("GEMINI_API_KEY", "AQ.Ab8RN6KFwnB9mn19NtaT-6OcUOsHmp8cJyzkU9O9DDkJrSUXDg")

    if not api_key:
        print("[!] GEMINI_API_KEY is not set. Set it with:")
        print("    export GEMINI_API_KEY=AIza...")
        print("    (or, in Colab: os.environ['GEMINI_API_KEY'] = '...')")
        print("    Get a key at https://aistudio.google.com/apikey")
        sys.exit(1)

    client = genai.Client(api_key=api_key)

    print("[+] Loading upstream module outputs...")
    evidence_data = load_json(EVIDENCE_FILE, default={})
    pre_evidence_data = load_json(PRE_EVIDENCE_FILE, default={})
    baseline_data = load_json(BASELINE_FILE, default={})
    threat_data = load_json(THREAT_INTEL_FILE, default=[])
    host_score = load_json(HOST_SCORE_FILE, default={})

    print("[+] Building timeline from correlated evidence...")
    timeline = build_timeline(evidence_data)

    print("[+] Building incident evidence graph...")
    evidence_graph = build_evidence_graph(evidence_data)

    print("[+] Building baseline (pre_evidence) evidence graph...")
    baseline_evidence_graph = build_evidence_graph(pre_evidence_data) if pre_evidence_data else []

    print("[+] Summarizing threat intelligence...")
    threat_intel = summarize_threat_intel(threat_data)

    if baseline_data:
        host_score = {**host_score, "baseline_deviations": baseline_data}

    # --- Trim to keep the prompt (and required output) within budget ---
    original_counts = (len(timeline), len(evidence_graph), len(baseline_evidence_graph))
    timeline = timeline[:MAX_TIMELINE_EVENTS]
    evidence_graph = evidence_graph[:MAX_EVIDENCE_PROCESSES]          # already sorted by score, most suspicious first
    baseline_evidence_graph = baseline_evidence_graph[:MAX_BASELINE_PROCESSES]

    print(f"[+] Trimmed input: timeline {original_counts[0]}->{len(timeline)}, "
          f"evidence_graph {original_counts[1]}->{len(evidence_graph)}, "
          f"baseline_evidence_graph {original_counts[2]}->{len(baseline_evidence_graph)}")

    print(f"[+] Sending {len(timeline)} timeline events / "
          f"{len(evidence_graph)} incident processes / "
          f"{len(baseline_evidence_graph)} baseline processes to {MODEL} for reasoning...")

    result = run_llm_reasoning(
        client, timeline, evidence_graph, baseline_evidence_graph, threat_intel, host_score
    )

    Path(OUTPUT_FILE).write_text(json.dumps(result, indent=2), encoding="utf-8")

    print("\n🧠 LLM REASONING COMPLETE")
    print(f"What Happened : {result.get('what_happened')}")
    attribution = result.get("attribution") or {}
    if isinstance(attribution, dict):
        print(f"Attribution   : {attribution.get('possible_actor_or_family')} "
              f"(confidence: {attribution.get('confidence')})")
    print(f"\n[✓] Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
