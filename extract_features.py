#!/usr/bin/env python3
"""
extract_features.py

Computes the per-plugin detection FEATURES (mutex_name_entropy,
rwx_execution, aslr_disabled, ...) described in your feature-set doc,
for every process. This is the stage AFTER merge_memory_artifacts.py --
it reads that script's merged_processes.json and adds a "features" block
per category, per process.

USAGE
-----
    python extract_features.py --merged merged_processes.json --out features.json

    # optional reference lists (see "CUSTOM REFERENCE DATA" below)
    python extract_features.py --merged merged_processes.json --out features.json \
        --known-malware-mutex known_mutex.txt \
        --known-dll-baseline known_dlls.txt

WHAT THIS DOES NOT DO
----------------------
A handful of features in your doc are inherently RELATIVE (need a
baseline/history to mean anything), not computable from a single
snapshot:

    - handle_count_spike / driver_count_per_snapshot  -> need prior
      snapshot(s) or a fleet baseline to define "spike".
    - known_malware_mutex / dll_not_in_the_known_list  -> need a
      reference list. Small starter lists are included below and can be
      overridden with --known-malware-mutex / --known-dll-baseline
      (one entry per line).
    - foreign_ip_count "multiple_foreign_countries"     -> needs GeoIP,
      which isn't wired up here (no offline GeoIP DB available). The
      script computes foreign_ip_count (distinct non-local remote IPs)
      and leaves country-level grouping as None -- plug in a GeoIP
      lookup if you have a DB file.

Everywhere a feature can't be computed from a single snapshot / without
external data, the script still emits the key with value None (or the
raw count it CAN compute) rather than silently omitting it, so the
output shape is always the same 90-ish keys per category.

FIELD NAME NOTE (same approach as the combiner script)
--------------------------------------------------------
Velociraptor/Volatility field names vary by artifact version. Every
lookup here goes through get_field(record, [candidate names]) using the
FIELD_MAP tables below. If a category's features come back all-None,
that almost always means none of the candidate names matched -- add the
real field name to the relevant list.
"""

import argparse
import ipaddress
import json
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def get_field(record: dict, candidates, default=None):
    """Case-sensitive-first, then case-insensitive lookup across a list of
    candidate key names. Returns `default` if none match or value is empty."""
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


def as_bool(val, default=None):
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s in ("1", "true", "yes", "y", "flagged"):
        return True
    if s in ("0", "false", "no", "n"):
        return False
    return default


def as_int(val, default=None):
    try:
        return int(float(val))
    except (TypeError, ValueError):
        return default


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


GUID_RE = re.compile(
    r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$"
)
BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
URL_RE = re.compile(r"https?://|ftp://", re.IGNORECASE)
TEMP_PATH_RE = re.compile(r"\\(temp|tmp|appdata\\local\\temp)\\", re.IGNORECASE)
APPDATA_RE = re.compile(r"\\appdata\\", re.IGNORECASE)


def is_temp_or_appdata(path: str) -> bool:
    if not path:
        return False
    return bool(TEMP_PATH_RE.search(path) or APPDATA_RE.search(path))


def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Reference / baseline data (starter lists -- extend or override via CLI)
# ---------------------------------------------------------------------------

DEFAULT_KNOWN_MALWARE_MUTEX_SUBSTRINGS = [
    "MSSE-", "postex_", "_HYDRA_", "Global\\I98B37C7C", "RDPWInst",
    "ASHRSHDU", "Global\\WSAGENT", "AnyDeskMutex",  # examples -- replace with real IOC feed
]

DEFAULT_KNOWN_SYSTEM_DLLS = {
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "gdi32.dll",
    "advapi32.dll", "msvcrt.dll", "sechost.dll", "rpcrt4.dll", "ole32.dll",
    "combase.dll", "ucrtbase.dll", "shell32.dll", "shlwapi.dll", "ws2_32.dll",
    "win32u.dll", "gdi32full.dll", "bcrypt.dll", "crypt32.dll", "oleaut32.dll",
}

SUSPICIOUS_PORTS = {4444, 1337, 8080, 9050, 9150}
# Note: 80/443/53 are flagged in the doc as *possible* non-standard-C2
# channels ONLY when used by an unexpected process -- handled contextually
# below rather than as an always-suspicious port set.
COMMON_WEB_DNS_PORTS = {80, 443, 53}

EXPECTED_PARENTS = {
    # child_image.lower() -> allowed parent image name(s), lowercase
    "svchost.exe": {"services.exe"},
    "services.exe": {"wininit.exe"},
    "lsass.exe": {"wininit.exe"},
    "csrss.exe": {"smss.exe"},
    "wininit.exe": {"smss.exe"},
    "winlogon.exe": {"smss.exe"},
    "explorer.exe": {"userinit.exe"},
}


# ---------------------------------------------------------------------------
# Field-name candidate tables (adjust once you have real export samples)
# ---------------------------------------------------------------------------

F = {
    "mutex_name": ["Name", "MutexName", "mutex_name", "ObjectName"],
    "thread_tid": ["Tid", "ThreadId", "tid"],
    "thread_state": ["State", "ThreadState"],
    "thread_start_addr": ["StartAddress", "Start", "ThreadStartAddress"],
    "thread_module": ["Module", "StartAddressModule", "OwningModule"],
    "thread_suspend_count": ["SuspendCount", "Suspended"],
    "thread_priority": ["Priority", "ThreadPriority"],
    "thread_create_time": ["CreateTime", "StartTime"],
    "thread_exit_time": ["ExitTime"],
    "thread_owning_pid": ["Pid", "OwningPid", "ProcessId"],
    "thread_protection": ["Protection", "MemoryProtection"],

    "handle_type": ["HandleType", "Type"],
    "handle_name": ["HandleName", "Name", "Details"],
    "handle_value": ["HandleValue", "Handle"],
    "handle_granted_access": ["GrantedAccess", "Access"],
    "handle_creator_pid": ["Pid", "ProcessId"],
    "handle_source_pid": ["SourcePid", "CrossPid", "OriginPid"],

    "token_type": ["TokenType", "Type"],
    "token_integrity": ["IntegrityLevel", "Integrity"],
    "token_sid": ["Sid", "TokenSid"],
    "process_sid": ["ProcessSid"],
    "token_user": ["User", "TokenUser"],
    "token_privileges": ["Privileges", "PrivilegeList"],
    "token_source": ["TokenSource", "Source"],
    "token_logon_type": ["LogonType"],
    "token_duplicated": ["Duplicated", "IsDuplicate"],
    "impersonated_account": ["ImpersonatedAccount", "TargetUser"],
    "parent_integrity": ["ParentIntegrityLevel"],

    "dll_name": ["Name", "BaseDllName", "ModuleName"],
    "dll_path": ["Path", "FullDllName", "ImagePathName"],
    "dll_signed": ["Signed", "SignatureStatus", "IsSigned"],
    "dll_in_peb": ["InPEB", "InLoad", "InInit"],
    "dll_load_time": ["LoadTime", "TimeDateStamp"],
    "dll_size": ["SizeOfImage", "Size"],

    "proc_integrity": ["IntegrityLevel", "Integrity"],
    "proc_wow64": ["Wow64", "IsWow64"],
    "proc_debugger": ["HasAttachedDebugger", "Debugged", "BeingDebugged"],
    "proc_peb_mismatch": ["PebDllMismatch", "PebMismatch"],
    "proc_image_path": ["ImagePathName", "Path", "ImageFileName"],
    "proc_command_line": ["CommandLine", "Cmdline"],
    "proc_aslr": ["ASLR", "AslrEnabled"],
    "proc_dep": ["DEP", "NXCompat", "DepEnabled"],
    "proc_env": ["Environment", "EnvironmentVariables"],

    "net_pid": ["Pid", "OwningPid"],
    "net_local_addr": ["LocalAddr", "LocalAddress", "LAddr"],
    "net_local_port": ["LocalPort", "LPort"],
    "net_remote_addr": ["RemoteAddr", "ForeignAddr", "RAddr"],
    "net_remote_port": ["RemotePort", "ForeignPort", "RPort"],
    "net_state": ["State", "SocketState"],
    "net_proto": ["Protocol", "Proto"],
    "net_created": ["Created", "CreateTime"],

    "ps_pid": ["Pid", "PID"],
    "ps_ppid": ["Ppid", "PPID", "ParentPid"],
    "ps_name": ["ImageFileName", "Name", "ProcessName"],
    "ps_create_time": ["CreateTime", "ProcessCreateTime"],
    "ps_command_line": ["CommandLine", "Cmdline"],
    "ps_path": ["Path", "ImagePathName"],

    "drv_name": ["Name", "DriverName"],
    "drv_path": ["Path", "FullDllName", "DriverPath"],
    "drv_signed": ["Signed", "IsSigned", "SignatureStatus"],
    "drv_size": ["Size", "SizeOfImage"],
    "drv_hidden": ["Hidden", "IsHidden"],
    "drv_section_protection": ["Protection", "SectionProtection"],

    "vad_start": ["Start", "StartVpn", "BaseAddress"],
    "vad_end": ["End", "EndVpn"],
    "vad_protection": ["Protection"],
    "vad_tag": ["Tag"],
    "vad_file": ["Filename", "File", "MappedFile"],
    "vad_private": ["PrivateMemory", "Private"],
}


# ---------------------------------------------------------------------------
# 1. MUTEX -- Windows.detection.mutant
# ---------------------------------------------------------------------------

def extract_mutex(pid, records, ctx):
    names = [str(get_field(r, F["mutex_name"], "")) for r in records]
    names = [n for n in names if n is not None]
    global_counts = ctx["mutex_name_global_counts"]
    pid_sets_per_name = ctx["mutex_name_pid_sets"]

    per_mutex = []
    for n in names:
        clean = n.strip()
        entropy = shannon_entropy(clean)
        per_mutex.append({
            "mutex_name": clean,
            "mutex_name_length": len(clean),
            "empty_mutex_name": clean == "",
            "global_mutex_flag": clean.lower().startswith("global\\"),
            "mutex_name_entropy": round(entropy, 3),
            "guid_shaped_mutex": bool(GUID_RE.match(clean.split("\\")[-1])) if clean else False,
            "known_malware_mutex": any(sub.lower() in clean.lower() for sub in ctx["known_malware_mutex"]),
            "duplicate_mutex_across_pids": len(pid_sets_per_name.get(clean, set())) > 1,
            "rare_mutex_name": global_counts.get(clean, 0) <= 1,  # seen once across whole snapshot
        })

    return {
        "mutex_count": len(names),
        "mutexes": per_mutex,
    }


# ---------------------------------------------------------------------------
# 2. THREADS -- windows.system.threads
# ---------------------------------------------------------------------------

def extract_threads(pid, records, ctx):
    thread_count = len(records)
    anonymous_memory = 0
    foreign_process = 0
    start_addr_anomaly = 0
    suspended = 0
    priority_anomaly = 0
    no_module = 0
    remote_thread = 0
    rwx = 0
    lifetimes = []

    for r in records:
        module = get_field(r, F["thread_module"])
        if not module:
            no_module += 1
            anonymous_memory += 1  # no backing module -> anonymous/fileless region

        owning_pid = get_field(r, F["thread_owning_pid"])
        if owning_pid is not None and str(owning_pid) != str(pid):
            foreign_process += 1
            remote_thread += 1

        state = str(get_field(r, F["thread_state"], "")).lower()
        if "suspend" in state:
            suspended += 1

        suspend_ct = as_int(get_field(r, F["thread_suspend_count"]))
        if suspend_ct and suspend_ct > 0:
            suspended += 1

        priority = as_int(get_field(r, F["thread_priority"]))
        if priority is not None and priority >= 13:  # THREAD_PRIORITY_TIME_CRITICAL-ish
            priority_anomaly += 1

        protection = str(get_field(r, F["thread_protection"], "")).upper()
        if "RWX" in protection or ("READWRITE" in protection and "EXECUTE" in protection):
            rwx += 1

        start_addr = get_field(r, F["thread_start_addr"])
        if start_addr and not module:
            # start address with no owning module = heap/stack/injected exec
            start_addr_anomaly += 1

        ct = get_field(r, F["thread_create_time"])
        et = get_field(r, F["thread_exit_time"])
        if ct and et:
            lifetimes.append((ct, et))  # raw timestamps; compute duration downstream if parseable

    return {
        "thread_count": thread_count,
        "anonymous_memory_thread_count": anonymous_memory,
        "thread_in_foreign_process": foreign_process > 0,
        "thread_start_address_anomaly_count": start_addr_anomaly,
        "suspended_thread_count": suspended,
        "thread_priority_anomaly_count": priority_anomaly,
        "thread_with_no_module_count": no_module,
        "remote_thread_flag": remote_thread > 0,
        "rwx_execution_count": rwx,
        "thread_created_at_runtime": None,  # needs process start time vs thread create time delta
        "thread_lifetime_pairs": lifetimes,  # raw (create, exit) pairs -- compute durations once timestamp format is known
    }


# ---------------------------------------------------------------------------
# 3. HANDLES -- windows.system.handle
# ---------------------------------------------------------------------------

SENSITIVE_HANDLE_NAMES = ["lsass", "sam", "security", "system"]
SENSITIVE_REGISTRY_HIVES = ["sam", "security", "las"]


def extract_handles(pid, records, ctx):
    handle_count = len(records)
    type_dist = Counter()
    sensitive_access = 0
    open_lsass = False
    invalid_handles = 0
    cross_process = 0
    file_in_temp = 0
    handle_to_system = 0
    sensitive_registry = 0
    named_pipes = 0
    session_handles = 0
    event_handles = 0
    token_handles = 0

    for r in records:
        htype = str(get_field(r, F["handle_type"], "")).strip()
        type_dist[htype] += 1
        hname = str(get_field(r, F["handle_name"], "")).lower()

        if any(s in hname for s in SENSITIVE_HANDLE_NAMES):
            sensitive_access += 1
        if "lsass" in hname:
            open_lsass = True
        if get_field(r, F["handle_value"]) in (None, "", "0x0", "0"):
            invalid_handles += 1

        src_pid = get_field(r, F["handle_source_pid"])
        if src_pid is not None and str(src_pid) != str(pid):
            cross_process += 1

        if htype.lower() == "file" and is_temp_or_appdata(hname):
            file_in_temp += 1

        if "wininit" in hname or hname.strip() == "system":
            handle_to_system += 1

        if any(hive in hname for hive in SENSITIVE_REGISTRY_HIVES) and "registry" in htype.lower():
            sensitive_registry += 1

        if htype.lower() in ("file",) and hname.startswith("\\pipe\\"):
            named_pipes += 1
        elif "\\pipe\\" in hname:
            named_pipes += 1

        if htype.lower() == "section" or "session" in htype.lower():
            session_handles += 1
        if htype.lower() == "event":
            event_handles += 1
        if htype.lower() == "token":
            token_handles += 1

    return {
        "handle_count": handle_count,
        "handle_count_spike": None,  # needs prior-snapshot baseline to compute a spike
        "sensitive_handle_access_count": sensitive_access,
        "handle_type_distribution": dict(type_dist),
        "invalid_handle_reference_count": invalid_handles,
        "open_lsass_handle": open_lsass,
        "cross_process_handle_count": cross_process,
        "file_handle_in_temp_count": file_in_temp,
        "handle_to_system_count": handle_to_system,
        "sensitive_registry_files_count": sensitive_registry,
        "named_pipe_count": named_pipes,
        "session_handle_count": session_handles,
        "event_handle_count": event_handles,
        "token_handle_count": token_handles,
        "system_handle_anomaly": None,  # needs "other user's desktop" session context, not present in handle dump alone
    }


# ---------------------------------------------------------------------------
# 4. IMPERSONATION -- Windows.detection.impersonation
# ---------------------------------------------------------------------------

PRIVILEGE_FLAGS = {
    "has_debug_privilege": "SeDebugPrivilege",
    "has_take_ownership": "SeTakeOwnershipPrivilege",
    "has_tcb_privilege": "SeTcbPrivilege",
    "has_restore_privilege": "SeRestorePrivilege",
    "has_load_driver_privilege": "SeLoadDriverPrivilege",
}


def extract_impersonation(pid, records, ctx):
    if not records:
        return {
            "token_type": None, "integrity_level_impersonation": None, "sid_mismatch": None,
            "impersonated_account": None, "token_duplication": None,
            **{k: None for k in PRIVILEGE_FLAGS}, "token_user_mismatch": None,
            "token_source_anomaly": None, "network_logon_token": None,
        }

    out_records = []
    for r in records:
        privileges = get_field(r, F["token_privileges"], [])
        if isinstance(privileges, str):
            priv_list = [p.strip() for p in re.split(r"[;,]", privileges)]
        elif isinstance(privileges, list):
            priv_list = privileges
        else:
            priv_list = []

        token_type = str(get_field(r, F["token_type"], "")).lower()
        integrity = get_field(r, F["token_integrity"])
        parent_integrity = get_field(r, F["parent_integrity"])
        token_sid = get_field(r, F["token_sid"])
        process_sid = get_field(r, F["process_sid"])
        logon_type = str(get_field(r, F["token_logon_type"], "")).lower()

        rec_out = {
            "token_type": token_type or None,
            "integrity_level_impersonation": (
                integrity is not None and parent_integrity is not None and integrity != parent_integrity
            ) if (integrity is not None and parent_integrity is not None) else None,
            "sid_mismatch": (token_sid != process_sid) if (token_sid and process_sid) else None,
            "impersonated_account": get_field(r, F["impersonated_account"]),
            "token_duplication": as_bool(get_field(r, F["token_duplicated"])),
            "token_user_mismatch": None,  # needs expected-owner context per process, not derivable generically
            "token_source_anomaly": None,  # needs baseline of expected token source per process type
            "network_logon_token": "network" in logon_type if logon_type else None,
        }
        for feat_key, priv_name in PRIVILEGE_FLAGS.items():
            rec_out[feat_key] = any(priv_name.lower() in str(p).lower() for p in priv_list)
        out_records.append(rec_out)

    # Collapse to "any token on this process shows X" -- adjust if you want per-token granularity
    collapsed = {"tokens": out_records}
    for key in ("token_type", "impersonated_account"):
        collapsed[key] = out_records[0][key]
    for key in list(PRIVILEGE_FLAGS.keys()) + [
        "integrity_level_impersonation", "sid_mismatch", "token_duplication",
        "token_user_mismatch", "token_source_anomaly", "network_logon_token",
    ]:
        vals = [t[key] for t in out_records if t[key] is not None]
        collapsed[key] = any(vals) if vals else None
    return collapsed


# ---------------------------------------------------------------------------
# 5. DLLS -- Windows.system.dll
# ---------------------------------------------------------------------------

def homoglyph_suspect(name: str) -> bool:
    """crude check for lookalike-substitution spoofing, e.g. l -> 1, O -> 0."""
    return bool(re.search(r"[0-9](?=[a-zA-Z])|(?<=[a-zA-Z])[0-9]", name)) and name.lower() not in DEFAULT_KNOWN_SYSTEM_DLLS


def extract_dlls(pid, records, ctx):
    dll_count = len(records)
    per_dll = []
    load_times = []

    for r in records:
        name = str(get_field(r, F["dll_name"], "")).strip()
        path = str(get_field(r, F["dll_path"], "")).strip()
        signed = as_bool(get_field(r, F["dll_signed"]))
        in_peb = as_bool(get_field(r, F["dll_in_peb"]))
        load_time = get_field(r, F["dll_load_time"])
        if load_time:
            load_times.append(load_time)

        per_dll.append({
            "name": name,
            "unsigned_dll": (signed is False),
            "dll_path_entropy": round(shannon_entropy(path), 3) if path else None,
            "dll_from_temp_appdata": is_temp_or_appdata(path),
            "missing_from_peb_reflective_indicator": (in_peb is False),
            "dll_not_in_known_list": name.lower() not in ctx["known_dll_baseline"] if name else None,
            "dll_name_spoof_suspect": homoglyph_suspect(name) if name else False,
            "dll_zero_time_stamp": load_time in (0, "0", None, ""),
        })

    return {
        "dll_count": dll_count,
        "dll_loaded_before_system": None,  # needs load-order index; not reliably derivable from timestamps alone
        "dlls": per_dll,
    }


# ---------------------------------------------------------------------------
# 6. PROCESS MEMORY INFO -- Windows.memory.processinfo
# ---------------------------------------------------------------------------

def extract_procinfo(pid, record, ctx):
    if not record:
        return {k: None for k in (
            "integrity_level", "is_wow64", "has_attached_debugger", "peb_dll_mismatch",
            "loading_from_temp_or_appdata", "image_path_command_line_mismatch",
            "aslr_disabled", "dep_disabled", "environment_variable_abuse",
        )}

    image_path = str(get_field(record, F["proc_image_path"], ""))
    cmdline = str(get_field(record, F["proc_command_line"], ""))
    aslr = as_bool(get_field(record, F["proc_aslr"]))
    dep = as_bool(get_field(record, F["proc_dep"]))

    return {
        "integrity_level": get_field(record, F["proc_integrity"]),
        "is_wow64": as_bool(get_field(record, F["proc_wow64"])),
        "has_attached_debugger": as_bool(get_field(record, F["proc_debugger"])),
        "peb_dll_mismatch": as_bool(get_field(record, F["proc_peb_mismatch"])),
        "loading_from_temp_or_appdata": is_temp_or_appdata(image_path),
        "image_path_command_line_mismatch": (
            bool(image_path) and bool(cmdline) and image_path.lower() not in cmdline.lower()
        ) if image_path and cmdline else None,
        "aslr_disabled": (aslr is False) if aslr is not None else None,
        "dep_disabled": (dep is False) if dep is not None else None,
        "environment_variable_abuse": None,  # needs allow-listed env-var baseline to flag "abuse" vs normal
    }


# ---------------------------------------------------------------------------
# 7. NETSTAT -- Windows.network.netstat
# ---------------------------------------------------------------------------

def extract_netstat(pid, records, ctx):
    conn_count = len(records)
    listening = 0
    suspicious_port_hits = []
    ephemeral_listener = 0
    foreign_ips = set()
    loopback = 0
    state_dist = Counter()
    dns_nonstandard = 0

    for r in records:
        state = str(get_field(r, F["net_state"], "")).upper()
        state_dist[state] += 1
        if "LISTEN" in state:
            listening += 1

        lport = as_int(get_field(r, F["net_local_port"]))
        rport = as_int(get_field(r, F["net_remote_port"]))
        raddr = str(get_field(r, F["net_remote_addr"], ""))
        laddr = str(get_field(r, F["net_local_addr"], ""))

        for p in (lport, rport):
            if p in SUSPICIOUS_PORTS:
                suspicious_port_hits.append(p)

        if "LISTEN" in state and lport and lport > 49152:
            ephemeral_listener += 1

        if raddr and not is_private_ip(raddr):
            foreign_ips.add(raddr)

        if raddr.startswith("127.") or laddr.startswith("127."):
            loopback += 1

        proc_name = str(get_field(r, ["ProcessName", "Owner"], "")).lower()
        if rport == 53 and proc_name and "dns" not in proc_name and "svchost" not in proc_name:
            dns_nonstandard += 1

    return {
        "has_network_connection": conn_count > 0,
        "connection_count": conn_count,
        "listening_port_count": listening,
        "suspicious_port_flag": len(suspicious_port_hits) > 0,
        "suspicious_ports_hit": sorted(set(suspicious_port_hits)),
        "ephemeral_listener_count": ephemeral_listener,
        "foreign_ip_count": len(foreign_ips),
        "multiple_foreign_countries": None,  # needs GeoIP DB, not wired up
        "loopback_connection_count": loopback,
        "state_distribution": dict(state_dist),
        "dns_over_nonstandard_count": dns_nonstandard,
        "connection_duration": None,  # needs connection start/end timestamps; add once field name is confirmed
    }


# ---------------------------------------------------------------------------
# 8. PSLIST -- Windows.system.pslist
# ---------------------------------------------------------------------------

def extract_pslist(pid, record, ctx):
    if not record:
        return {k: None for k in (
            "process_name_entropy", "parent_child_mismatch", "orphan_process_flag",
            "process_age_seconds", "process_depth", "commandline_empty",
            "commandline_has_base64", "commandline_has_url", "commandline_length",
        )}

    name = str(get_field(record, F["ps_name"], ""))
    ppid = get_field(record, F["ps_ppid"])
    cmdline = str(get_field(record, F["ps_command_line"], ""))

    parent_name = None
    if ppid is not None:
        parent_proc = ctx["all_processes"].get(str(ppid))
        if parent_proc and parent_proc.get("pslist"):
            parent_name = str(get_field(parent_proc["pslist"], F["ps_name"], "")).lower()

    expected_parents = EXPECTED_PARENTS.get(name.lower())
    parent_child_mismatch = None
    if expected_parents is not None and parent_name is not None:
        parent_child_mismatch = parent_name not in expected_parents

    orphan = None
    if ppid is not None:
        orphan = str(ppid) not in ctx["all_processes"] and str(pid) != "4"  # PID 4 (System) has no parent by design

    return {
        "process_name_entropy": round(shannon_entropy(name), 3) if name else None,
        "parent_child_mismatch": parent_child_mismatch,
        "orphan_process_flag": orphan,
        "process_age_seconds": None,  # needs snapshot time - CreateTime delta; add once CreateTime format is confirmed
        "process_depth": ctx["depth_map"].get(str(pid)),
        "commandline_empty": (cmdline.strip() == ""),
        "commandline_has_base64": bool(BASE64_RE.search(cmdline)) if cmdline else False,
        "commandline_has_url": bool(URL_RE.search(cmdline)) if cmdline else False,
        "commandline_length": len(cmdline),
    }


def compute_depth_map(all_processes: dict) -> dict:
    """PID -> distance from a root (ppid missing/absent from the process set)."""
    ppid_of = {}
    for pid_str, proc in all_processes.items():
        pslist = proc.get("pslist")
        ppid = get_field(pslist, F["ps_ppid"]) if pslist else None
        ppid_of[pid_str] = str(ppid) if ppid is not None else None

    depth = {}

    def resolve(pid_str, seen):
        if pid_str in depth:
            return depth[pid_str]
        if pid_str in seen:  # cycle guard
            return 0
        seen.add(pid_str)
        parent = ppid_of.get(pid_str)
        if parent is None or parent not in all_processes or parent == pid_str:
            depth[pid_str] = 0
        else:
            depth[pid_str] = resolve(parent, seen) + 1
        return depth[pid_str]

    for p in all_processes:
        resolve(p, set())
    return depth


# ---------------------------------------------------------------------------
# 9. DRIVERS -- Windows.system.drivers
# ---------------------------------------------------------------------------

def extract_drivers(records, ctx):
    """Drivers are typically system-wide (not per-PID), so this runs once
    over the 'unattributed' driver list plus any per-pid ones, and returns
    a single global block rather than per-process."""
    driver_count = len(records)
    unsigned = 0
    hidden = 0
    rwx_sections = 0
    per_driver = []
    sizes = []

    for r in records:
        name = str(get_field(r, F["drv_name"], ""))
        path = str(get_field(r, F["drv_path"], ""))
        signed = as_bool(get_field(r, F["drv_signed"]))
        hidden_flag = as_bool(get_field(r, F["drv_hidden"]))
        size = as_int(get_field(r, F["drv_size"]))
        protection = str(get_field(r, F["drv_section_protection"], "")).upper()

        if signed is False:
            unsigned += 1
        if hidden_flag:
            hidden += 1
        if "RWX" in protection or ("READWRITE" in protection and "EXECUTE" in protection):
            rwx_sections += 1
        if size:
            sizes.append(size)

        per_driver.append({
            "name": name,
            "unsigned_driver": (signed is False),
            "driver_path_anomaly": is_temp_or_appdata(path),
            "hidden_driver": bool(hidden_flag),
            "driver_name_anomaly": homoglyph_suspect(name) if name else False,
            "rwx_driver_section": "RWX" in protection or ("READWRITE" in protection and "EXECUTE" in protection),
            "driver_size_anomaly": None,  # needs a size baseline/z-score across known-good drivers
        })

    return {
        "driver_count_per_snapshot": driver_count,
        "unsigned_driver_count": unsigned,
        "hidden_driver_count": hidden,
        "rwx_driver_section_count": rwx_sections,
        "drivers": per_driver,
    }


# ---------------------------------------------------------------------------
# 10. VAD -- not in your feature doc; best-effort standard VAD features
#     (private RWX = classic injected-code signal). Flagged as an
#     assumption -- replace once you confirm the real artifact/fields.
# ---------------------------------------------------------------------------

def extract_vad(pid, records, ctx):
    vad_count = len(records)
    private_rwx = 0
    no_file_backing = 0
    per_vad = []

    for r in records:
        protection = str(get_field(r, F["vad_protection"], "")).upper()
        private_mem = as_bool(get_field(r, F["vad_private"]))
        filename = get_field(r, F["vad_file"])

        is_rwx = "RWX" in protection or ("EXECUTE_READWRITE" in protection)
        is_private_rwx = bool(is_rwx and private_mem)
        if is_private_rwx:
            private_rwx += 1
        if not filename:
            no_file_backing += 1

        per_vad.append({
            "start": get_field(r, F["vad_start"]),
            "end": get_field(r, F["vad_end"]),
            "protection": protection or None,
            "private_memory": private_mem,
            "file_backed": bool(filename),
            "private_rwx_region": is_private_rwx,  # classic malfind-style injection signal
        })

    return {
        "vad_count": vad_count,
        "private_rwx_region_count": private_rwx,
        "no_file_backing_count": no_file_backing,
        "vads": per_vad,
    }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def build_context(all_processes: dict, known_malware_mutex, known_dll_baseline):
    mutex_name_global_counts = Counter()
    mutex_name_pid_sets = defaultdict(set)

    for pid_str, proc in all_processes.items():
        for r in proc.get("mutex", []):
            name = str(get_field(r, F["mutex_name"], "")).strip()
            if not name:
                continue
            mutex_name_global_counts[name] += 1
            mutex_name_pid_sets[name].add(pid_str)

    depth_map = compute_depth_map(all_processes)

    return {
        "all_processes": all_processes,
        "mutex_name_global_counts": mutex_name_global_counts,
        "mutex_name_pid_sets": mutex_name_pid_sets,
        "depth_map": depth_map,
        "known_malware_mutex": known_malware_mutex,
        "known_dll_baseline": known_dll_baseline,
    }


def load_list_file(path, default):
    if not path:
        return default
    p = Path(path)
    if not p.exists():
        print(f"[!] Reference list not found: {path} -- using built-in default", file=sys.stderr)
        return default
    return [line.strip().lower() for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def main():
    ap = argparse.ArgumentParser(description="Extract per-plugin detection features from a merged_processes.json.")
    ap.add_argument("--merged", required=True, help="Output of merge_memory_artifacts.py")
    ap.add_argument("--out", default="features.json")
    ap.add_argument("--known-malware-mutex", help="Text file, one mutex-name substring per line")
    ap.add_argument("--known-dll-baseline", help="Text file, one known-good dll filename per line")
    args = ap.parse_args()

    merged = json.loads(Path(args.merged).read_text(encoding="utf-8"))
    all_processes = merged.get("processes", {})
    unattributed = merged.get("unattributed", {})

    known_malware_mutex = load_list_file(args.known_malware_mutex, DEFAULT_KNOWN_MALWARE_MUTEX_SUBSTRINGS)
    known_dll_baseline = set(load_list_file(args.known_dll_baseline, list(DEFAULT_KNOWN_SYSTEM_DLLS)))

    ctx = build_context(all_processes, known_malware_mutex, known_dll_baseline)

    output = {"processes": {}, "global": {}}

    for pid_str, proc in all_processes.items():
        output["processes"][pid_str] = {
            "pid": pid_str,
            "ppid": proc.get("ppid"),
            "mutex_features": extract_mutex(pid_str, proc.get("mutex", []), ctx),
            "thread_features": extract_threads(pid_str, proc.get("threads", []), ctx),
            "handle_features": extract_handles(pid_str, proc.get("handles", []), ctx),
            "impersonation_features": extract_impersonation(pid_str, proc.get("impersonation", []), ctx),
            "dll_features": extract_dlls(pid_str, proc.get("dlls", []), ctx),
            "procinfo_features": extract_procinfo(pid_str, proc.get("procinfo"), ctx),
            "netstat_features": extract_netstat(pid_str, proc.get("netstat", []), ctx),
            "pslist_features": extract_pslist(pid_str, proc.get("pslist"), ctx),
            "vad_features": extract_vad(pid_str, proc.get("vad", []), ctx),
        }

    # Drivers are system-wide -> one global block, combining attributed +
    # unattributed driver records rather than duplicating per PID.
    all_driver_records = list(unattributed.get("drivers", []))
    for proc in all_processes.values():
        all_driver_records.extend(proc.get("drivers", []))
    output["global"]["driver_features"] = extract_drivers(all_driver_records, ctx)

    Path(args.out).write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
    print(f"[\u2713] Wrote features for {len(all_processes)} process(es) -> {args.out}")


if __name__ == "__main__":
    main()
