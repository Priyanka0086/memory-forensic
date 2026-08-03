#!/usr/bin/env python3
"""
baseline_compare.py

Third stage of the pipeline:

    merge_memory_artifacts.py  -->  extract_features.py  -->  baseline_compare.py

Compares a "pre" (baseline / known-good) snapshot against a "during"
(incident / suspect) snapshot -- both already run through extract_features.py
-- and computes everything that single-snapshot extraction explicitly could
NOT compute on its own, most importantly:

    - handle_count_spike           (needs prior snapshot)
    - driver_count_per_snapshot    (needs a baseline to mean "spike")
    - any "new since baseline" entity: new mutex, new dll, new process,
      new listening port, new foreign IP, a risk flag flipping
      False/None -> True, etc.

USAGE
-----
    python baseline_compare.py \
        --baseline-features features_pre.json \
        --current-features  features_during.json \
        --baseline-merged   merged_pre.json \
        --current-merged    merged_during.json \
        --out baseline_comparison.json

--baseline-merged / --current-merged are OPTIONAL but recommended:
extract_features.py's output does not retain the process image name (only
derived features like process_name_entropy), so without the merged files
this script can only match processes that happen to share the exact same
PID across both snapshots. With the merged files, it also matches processes
by image name, which is what you want when comparing two separate captures
(PIDs are not stable across reboots / re-launches).

MATCHING STRATEGY
------------------
    1. Exact PID match (same PID present in both snapshots) -> highest
       confidence match, used first.
    2. For everything left over, group remaining processes by image name
       (from the merged pslist record) and pair them up in sorted-PID
       order. If a name has more instances in "current" than "baseline",
       the extra instances are reported as new_processes (a name existing
       at baseline doesn't make a *new instance* of it benign). If it has
       fewer, the missing ones are reported as terminated_processes.
    3. Names that exist only in "current" -> new_processes (high signal).
    4. Names that exist only in "baseline" -> terminated_processes.

WHAT COUNTS AS AN ANOMALY
---------------------------
For every matched process, every leaf value in the *_features blocks is
diffed generically (this script doesn't hardcode a feature list, same
philosophy as the two upstream scripts -- it walks whatever keys are
actually present):

    - bool False/None -> True                => "risk_flag_activated"
    - numeric field changed                  => "count_change"
        - flagged as a "spike" if current >= baseline * --spike-multiplier
          (or baseline was 0 and current >= --spike-min-delta)
    - list-valued entity fields (mutex names, dll names) are diffed as
      sets to surface brand-new entities, independent of count deltas.

Everything is schema-agnostic in the same way as merge_memory_artifacts.py
and extract_features.py: if your extractor's field names differ, nothing
needs to change here -- this script only ever reads keys that already
exist in features.json's output.
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Generic helpers (mirrors the style of the upstream scripts)
# ---------------------------------------------------------------------------

NAME_CANDIDATES = ["ImageFileName", "Name", "ProcessName"]


def get_field(record, candidates, default=None):
    if not isinstance(record, dict):
        return default
    for key in candidates:
        if key in record and record[key] not in (None, "", "-"):
            return record[key]
    lower_map = {k.lower(): v for k, v in record.items()}
    for key in candidates:
        v = lower_map.get(key.lower())
        if v not in (None, "", "-"):
            return v
    return default


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Identity resolution (PID -> process name), using the merged file if given
# ---------------------------------------------------------------------------

def build_pid_to_name(merged_data):
    """pid_str -> image name, or None if no merged file / no pslist record."""
    if not merged_data:
        return {}
    out = {}
    for pid, proc in merged_data.get("processes", {}).items():
        pslist = proc.get("pslist")
        name = get_field(pslist, NAME_CANDIDATES) if pslist else None
        if name:
            out[pid] = str(name).strip()
    return out


def build_pid_to_ppid(merged_data):
    if not merged_data:
        return {}
    out = {}
    for pid, proc in merged_data.get("processes", {}).items():
        pslist = proc.get("pslist")
        ppid = get_field(pslist, ["Ppid", "PPID", "ParentPid"]) if pslist else None
        if ppid is not None:
            out[pid] = str(ppid)
    return out


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def match_processes(base_features, cur_features, base_names, cur_names):
    """Returns (matched_pairs, new_pids, terminated_pids)
    matched_pairs: list of (base_pid, cur_pid, match_type, name)
    new_pids: list of cur_pid present only in "current"
    terminated_pids: list of base_pid present only in "baseline"
    """
    base_pids = set(base_features.get("processes", {}).keys())
    cur_pids = set(cur_features.get("processes", {}).keys())

    matched = []
    exact = base_pids & cur_pids
    for pid in exact:
        matched.append((pid, pid, "pid_exact", base_names.get(pid) or cur_names.get(pid) or f"<pid:{pid}>"))

    remaining_base = base_pids - exact
    remaining_cur = cur_pids - exact

    # group remaining by name (only possible where merged files were given)
    base_by_name = defaultdict(list)
    for pid in sorted(remaining_base, key=lambda p: (int(p) if p.isdigit() else 0)):
        base_by_name[base_names.get(pid, f"<unknown:{pid}>")].append(pid)

    cur_by_name = defaultdict(list)
    for pid in sorted(remaining_cur, key=lambda p: (int(p) if p.isdigit() else 0)):
        cur_by_name[cur_names.get(pid, f"<unknown:{pid}>")].append(pid)

    new_pids = []
    terminated_pids = []

    all_names = set(base_by_name) | set(cur_by_name)
    for name in all_names:
        b_list = base_by_name.get(name, [])
        c_list = cur_by_name.get(name, [])
        paired = min(len(b_list), len(c_list))
        for i in range(paired):
            matched.append((b_list[i], c_list[i], "name_paired", name))
        # extra current instances beyond what baseline had = new instances
        for pid in c_list[paired:]:
            new_pids.append(pid)
        # extra baseline instances beyond what current has = terminated
        for pid in b_list[paired:]:
            terminated_pids.append(pid)

    return matched, new_pids, terminated_pids


# ---------------------------------------------------------------------------
# Generic feature-tree diff
# ---------------------------------------------------------------------------

LIST_ENTITY_NAME_KEY = {
    "mutexes": "mutex_name",
    "dlls": "name",
    "drivers": "name",
}


def diff_leaf_tree(base_block, cur_block, path=""):
    """Recursively diffs two feature dicts (e.g. one process's
    'handle_features' block against its counterpart). Skips list-valued
    keys -- those are diffed separately as named-entity sets."""
    result = {"risk_flags_activated": [], "risk_flags_deactivated": [],
              "count_changes": [], "value_changes": []}
    if not isinstance(base_block, dict):
        base_block = {}
    if not isinstance(cur_block, dict):
        cur_block = {}

    keys = set(base_block.keys()) | set(cur_block.keys())
    for k in keys:
        bv = base_block.get(k)
        cv = cur_block.get(k)
        full_key = f"{path}.{k}" if path else k

        if isinstance(bv, list) or isinstance(cv, list):
            continue  # handled by diff_named_entities

        if isinstance(bv, dict) or isinstance(cv, dict):
            sub = diff_leaf_tree(bv if isinstance(bv, dict) else {},
                                  cv if isinstance(cv, dict) else {}, full_key)
            for kk in result:
                result[kk].extend(sub[kk])
            continue

        if isinstance(bv, bool) or isinstance(cv, bool):
            bv_b, cv_b = bool(bv), bool(cv)
            if not bv_b and cv_b:
                result["risk_flags_activated"].append(full_key)
            elif bv_b and not cv_b:
                result["risk_flags_deactivated"].append(full_key)
            continue

        if isinstance(bv, (int, float)) or isinstance(cv, (int, float)):
            b_num = bv if isinstance(bv, (int, float)) else 0
            c_num = cv if isinstance(cv, (int, float)) else 0
            if b_num != c_num:
                result["count_changes"].append({
                    "field": full_key, "baseline": b_num, "current": c_num,
                    "delta": c_num - b_num,
                })
            continue

        if bv != cv:
            result["value_changes"].append({"field": full_key, "baseline": bv, "current": cv})

    return result


def diff_named_entities(base_proc_features, cur_proc_features):
    """For mutexes/dlls/drivers (list of dicts with a name-like key),
    return the set of entities that appear in 'current' but not in
    'baseline', keyed by category. Only compares by name -- not full
    record equality -- since load order / minor fields will differ
    between snapshots even for an unchanged entity."""
    new_entities = {}
    category_map = {
        "mutex_features": ("mutexes", "mutex_name"),
        "dll_features": ("dlls", "name"),
    }
    for feat_key, (list_key, name_key) in category_map.items():
        base_list = (base_proc_features.get(feat_key) or {}).get(list_key, []) or []
        cur_list = (cur_proc_features.get(feat_key) or {}).get(list_key, []) or []
        base_names = {str(e.get(name_key, "")) for e in base_list if isinstance(e, dict)}
        cur_by_name = {str(e.get(name_key, "")): e for e in cur_list if isinstance(e, dict)}
        new_names = set(cur_by_name) - base_names
        if new_names:
            new_entities[feat_key] = [cur_by_name[n] for n in sorted(new_names) if n]
    return new_entities


SPIKE_FIELDS_SUFFIX = "_count"  # any numeric field ending in _count is a spike candidate


def mark_spikes(count_changes, multiplier, min_delta):
    for c in count_changes:
        b, cnew, delta = c["baseline"], c["current"], c["delta"]
        is_count_field = c["field"].split(".")[-1].endswith(SPIKE_FIELDS_SUFFIX)
        spike = False
        if is_count_field and delta > 0:
            if b <= 0:
                spike = cnew >= min_delta
            else:
                spike = (cnew >= b * multiplier) and (delta >= min_delta)
        c["spike"] = spike
    return count_changes


# ---------------------------------------------------------------------------
# Per-process comparison
# ---------------------------------------------------------------------------

FEATURE_BLOCK_KEYS = [
    "mutex_features", "thread_features", "handle_features",
    "impersonation_features", "dll_features", "procinfo_features",
    "netstat_features", "pslist_features", "vad_features",
]


def score_diff(diff, new_entities, ppid_changed):
    score = 0
    score += 3 * len(diff["risk_flags_activated"])
    score += 5 * sum(1 for c in diff["count_changes"] if c.get("spike"))
    score += 1 * sum(1 for c in diff["count_changes"] if not c.get("spike") and c["delta"] > 0)
    for feat_key, entities in new_entities.items():
        weight = 4
        if feat_key == "mutex_features":
            for e in entities:
                if e.get("known_malware_mutex"):
                    weight += 6
                if e.get("guid_shaped_mutex"):
                    weight += 1
        if feat_key == "dll_features":
            for e in entities:
                if e.get("unsigned_dll") or e.get("dll_from_temp_appdata") or e.get("dll_name_spoof_suspect"):
                    weight += 3
        score += weight * len(entities)
    if ppid_changed:
        score += 3
    return score


def compare_process(base_proc, cur_proc, base_ppid, cur_ppid):
    diff = {"risk_flags_activated": [], "risk_flags_deactivated": [],
            "count_changes": [], "value_changes": []}
    for block in FEATURE_BLOCK_KEYS:
        sub = diff_leaf_tree(base_proc.get(block), cur_proc.get(block), path=block)
        for k in diff:
            diff[k].extend(sub[k])

    new_entities = diff_named_entities(base_proc, cur_proc)
    ppid_changed = bool(base_ppid and cur_ppid and base_ppid != cur_ppid)

    return diff, new_entities, ppid_changed


def summarize_new_process(cur_proc):
    """A brand-new process has no baseline to diff against -- surface
    whatever intrinsic risk flags/entities it already carries."""
    flags = []
    for block in FEATURE_BLOCK_KEYS:
        b = cur_proc.get(block) or {}
        for k, v in b.items():
            if isinstance(v, bool) and v:
                flags.append(f"{block}.{k}")
    suspicious_mutexes = [m for m in (cur_proc.get("mutex_features") or {}).get("mutexes", [])
                           if m.get("known_malware_mutex")]
    suspicious_dlls = [d for d in (cur_proc.get("dll_features") or {}).get("dlls", [])
                        if d.get("unsigned_dll") or d.get("dll_from_temp_appdata")]
    return flags, suspicious_mutexes, suspicious_dlls


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Compare a baseline (pre) and current (during) features.json to surface deviations.")
    ap.add_argument("--baseline-features", required=True)
    ap.add_argument("--current-features", required=True)
    ap.add_argument("--baseline-merged", help="merged_processes.json for the baseline snapshot (enables name-based matching)")
    ap.add_argument("--current-merged", help="merged_processes.json for the current snapshot (enables name-based matching)")
    ap.add_argument("--out", default="baseline_comparison.json")
    ap.add_argument("--spike-multiplier", type=float, default=2.0,
                     help="current >= baseline * multiplier to flag a count spike (default 2.0)")
    ap.add_argument("--spike-min-delta", type=float, default=5,
                     help="minimum absolute increase required to flag a spike, avoids noise on tiny counts (default 5)")
    ap.add_argument("--top", type=int, default=15, help="how many top-scoring processes to print to stdout")
    args = ap.parse_args()

    base_features = load_json(args.baseline_features)
    cur_features = load_json(args.current_features)
    base_merged = load_json(args.baseline_merged) if args.baseline_merged else None
    cur_merged = load_json(args.current_merged) if args.current_merged else None

    if not base_merged or not cur_merged:
        print("[!] No merged_processes.json supplied for one or both sides -- "
              "process matching will be PID-exact only (no name-based pairing).", file=sys.stderr)

    base_names = build_pid_to_name(base_merged)
    cur_names = build_pid_to_name(cur_merged)
    base_ppids = build_pid_to_ppid(base_merged)
    cur_ppids = build_pid_to_ppid(cur_merged)

    matched, new_pids, terminated_pids = match_processes(base_features, cur_features, base_names, cur_names)

    process_results = []
    for base_pid, cur_pid, match_type, name in matched:
        base_proc = base_features["processes"][base_pid]
        cur_proc = cur_features["processes"][cur_pid]
        diff, new_entities, ppid_changed = compare_process(
            base_proc, cur_proc, base_ppids.get(base_pid), cur_ppids.get(cur_pid))
        mark_spikes(diff["count_changes"], args.spike_multiplier, args.spike_min_delta)
        score = score_diff(diff, new_entities, ppid_changed)
        process_results.append({
            "name": name,
            "baseline_pid": base_pid,
            "current_pid": cur_pid,
            "match_type": match_type,
            "ppid_changed": ppid_changed,
            "anomaly_score": score,
            "risk_flags_activated": diff["risk_flags_activated"],
            "risk_flags_deactivated": diff["risk_flags_deactivated"],
            "count_changes": [c for c in diff["count_changes"] if c["delta"] != 0],
            "value_changes": diff["value_changes"],
            "new_entities": new_entities,
        })

    new_process_results = []
    for pid in new_pids:
        cur_proc = cur_features["processes"][pid]
        flags, sus_mutex, sus_dll = summarize_new_process(cur_proc)
        score = 10 + 3 * len(flags) + 6 * len(sus_mutex) + 3 * len(sus_dll)
        new_process_results.append({
            "name": cur_names.get(pid, f"<unknown:{pid}>"),
            "current_pid": pid,
            "anomaly_score": score,
            "intrinsic_risk_flags": flags,
            "known_malware_mutex_hits": sus_mutex,
            "suspicious_dlls": sus_dll,
        })

    terminated_process_results = [
        {"name": base_names.get(pid, f"<unknown:{pid}>"), "baseline_pid": pid}
        for pid in terminated_pids
    ]

    # Global (system-wide) driver comparison -- fills in driver_count_per_snapshot's
    # "needs a baseline" gap from extract_features.py.
    base_drv = (base_features.get("global") or {}).get("driver_features") or {}
    cur_drv = (cur_features.get("global") or {}).get("driver_features") or {}
    driver_diff = diff_leaf_tree(base_drv, cur_drv, path="driver_features")
    mark_spikes(driver_diff["count_changes"], args.spike_multiplier, args.spike_min_delta)
    base_driver_names = {d.get("name", "") for d in base_drv.get("drivers", []) if isinstance(d, dict)}
    cur_driver_by_name = {d.get("name", ""): d for d in cur_drv.get("drivers", []) if isinstance(d, dict)}
    new_driver_names = set(cur_driver_by_name) - base_driver_names
    new_drivers = [cur_driver_by_name[n] for n in sorted(new_driver_names) if n]

    all_scored = sorted(process_results + new_process_results, key=lambda r: r["anomaly_score"], reverse=True)

    output = {
        "summary": {
            "baseline_process_count": len(base_features.get("processes", {})),
            "current_process_count": len(cur_features.get("processes", {})),
            "matched_process_count": len(process_results),
            "new_process_count": len(new_process_results),
            "terminated_process_count": len(terminated_process_results),
            "driver_count_baseline": base_drv.get("driver_count_per_snapshot"),
            "driver_count_current": cur_drv.get("driver_count_per_snapshot"),
            "new_driver_count": len(new_drivers),
        },
        "matched_processes": process_results,
        "new_processes": new_process_results,
        "terminated_processes": terminated_process_results,
        "driver_baseline_delta": {
            "count_changes": driver_diff["count_changes"],
            "risk_flags_activated": driver_diff["risk_flags_activated"],
            "new_drivers": new_drivers,
        },
    }

    Path(args.out).write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
    print(f"[\u2713] Wrote baseline comparison -> {args.out}")
    print(f"    baseline processes: {output['summary']['baseline_process_count']}  "
          f"current processes: {output['summary']['current_process_count']}")
    print(f"    matched: {output['summary']['matched_process_count']}  "
          f"new: {output['summary']['new_process_count']}  "
          f"terminated: {output['summary']['terminated_process_count']}")

    print(f"\n[Top {args.top} by anomaly score]")
    for r in all_scored[:args.top]:
        pid_label = r.get("current_pid") or r.get("baseline_pid")
        print(f"    score={r['anomaly_score']:>4}  pid={pid_label:<8} name={r['name']}")


if __name__ == "__main__":
    main()
