#!/usr/bin/env python3

import argparse
import csv
import json
import sys
import os
from collections import defaultdict
from pathlib import Path

# ---------------- CONFIG ---------------- #

PID_KEY_CANDIDATES = [
    "pid", "Pid", "PID", "ProcessId", "process_id", "Process_Id",
    "EPROCESS_Pid", "process_pid", "Owner_Pid", "OwnerPid",
]

PPID_KEY_CANDIDATES = [
    "ppid", "Ppid", "PPID", "ParentPid", "parent_pid", "Parent_Pid",
]

MULTI_RECORD_CATEGORIES = {
    "mutex", "vad", "threads", "handles", "dlls",
    "netstat", "drivers", "impersonation",
}

SINGLE_RECORD_CATEGORIES = {"pslist", "procinfo"}

ALL_CATEGORIES = MULTI_RECORD_CATEGORIES | SINGLE_RECORD_CATEGORIES

# Map Velociraptor filenames → category
ARTIFACT_MAP = {
    "Windows.System.Pslist": "pslist",
    "Windows.Network.Netstat": "netstat",
    "Windows.System.Threads": "threads",
    "Windows.System.Handle": "handles",
    "Windows.System.DLL": "dlls",
    "Windows.System.Drivers": "drivers",
    "Windows.Memory.ProcessInfo": "procinfo",
    "Windows.Memory.VAD": "vad",
    "Windows.Detection.Mutant": "mutex",
    "Windows.Detection.Impersonation": "impersonation",
}

# ---------------- FILE LOADER ---------------- #

def sniff_and_load(path: str):
    p = Path(path)
    raw = p.read_text(encoding="utf-8-sig", errors="replace").strip()
    if not raw:
        return []

    if raw.startswith("["):
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return data
        except:
            pass

    if raw.startswith("{"):
        lines = [ln for ln in raw.splitlines() if ln.strip()]
        if len(lines) == 1:
            try:
                obj = json.loads(raw)
                return [obj]
            except:
                pass

        records = []
        for line in lines:
            try:
                records.append(json.loads(line.strip().rstrip(",")))
            except:
                return []
        return records

    try:
        with p.open(newline="", encoding="utf-8-sig") as f:
            return list(csv.DictReader(f))
    except:
        return []

# ---------------- HELPERS ---------------- #

def extract_key(record, candidates):
    for key in candidates:
        if key in record and record[key] not in (None, "", "-"):
            try:
                return str(int(str(record[key]).strip()))
            except:
                return str(record[key]).strip()
    return None

# ---------------- AUTO DISCOVERY ---------------- #

def discover_files(input_folder):
    category_files = {cat: [] for cat in ALL_CATEGORIES}

    for root, dirs, files in os.walk(input_folder):
        for file in files:
            for artifact_name, category in ARTIFACT_MAP.items():
                if artifact_name in file and file.endswith(".json"):
                    full_path = os.path.join(root, file)
                    category_files[category].append(full_path)

    print("\n[+] Artifact Discovery Summary:")
    for cat, files in category_files.items():
        print(f"    {cat}: {len(files)} file(s)")

    return category_files

# ---------------- MERGE ---------------- #

def merge(category_files, out_path):
    processes = defaultdict(lambda: {
        "pid": None,
        "ppid": None,
        "pslist": None,
        "procinfo": None,
        "impersonation": [],
        "mutex": [],
        "vad": [],
        "threads": [],
        "handles": [],
        "dlls": [],
        "netstat": [],
        "drivers": [],
    })

    unattributed = defaultdict(list)

    for category, paths in category_files.items():
        for path in paths:
            records = sniff_and_load(path)
            print(f"[+] {category}: {len(records)} records from {path}")

            for rec in records:
                pid = extract_key(rec, PID_KEY_CANDIDATES)

                if pid is None:
                    unattributed[category].append(rec)
                    continue

                proc = processes[pid]
                proc["pid"] = pid

                ppid = extract_key(rec, PPID_KEY_CANDIDATES)
                if ppid and not proc["ppid"]:
                    proc["ppid"] = ppid

                if category in MULTI_RECORD_CATEGORIES:
                    proc[category].append(rec)
                else:
                    proc[category] = rec

    result = {
        "processes": dict(sorted(processes.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 0)),
        "unattributed": unattributed,
    }

    Path(out_path).write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(f"\n[✓] Merged {len(processes)} processes → {out_path}")

# ---------------- MAIN ---------------- #

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Root results folder containing all snapshots")
    ap.add_argument("--out", default="merged_processes.json")

    args = ap.parse_args()

    category_files = discover_files(args.input)

    if not any(category_files.values()):
        ap.error("No artifact files found!")

    merge(category_files, args.out)

if __name__ == "__main__":
    main()