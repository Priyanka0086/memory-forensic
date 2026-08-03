#!/usr/bin/env python3
"""
======================================================================
Evidence Builder
======================================================================

Author  : Vinay
Purpose :
    Converts extracted memory forensic features into structured,
    explainable evidence suitable for analysts and LLMs.

Pipeline

features.json
      │
      ▼
 Rule Engine
      │
      ▼
 Evidence Objects
      │
      ▼
 Correlation Engine
      │
      ▼
 Risk Assessment
      │
      ▼
 evidence.json

======================================================================
"""

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path


# ================================================================
# Risk Levels
# ================================================================

LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CRITICAL = "CRITICAL"


# ================================================================
# Severity Scores
# ================================================================

SEVERITY_SCORE = {

    "INFO": 0,

    "LOW": 5,

    "MEDIUM": 10,

    "HIGH": 20,

    "CRITICAL": 35

}


# ================================================================
# MITRE ATT&CK Mapping
# ================================================================

MITRE = {

    "PROCESS_INJECTION": {
        "id": "T1055",
        "name": "Process Injection"
    },

    "CREDENTIAL_DUMPING": {
        "id": "T1003",
        "name": "OS Credential Dumping"
    },

    "DLL_SIDELOADING": {
        "id": "T1574",
        "name": "DLL Side-Loading"
    },

    "COMMAND_AND_CONTROL": {
        "id": "T1071",
        "name": "Application Layer Protocol"
    },

    "REMOTE_SERVICES": {
        "id": "T1021",
        "name": "Remote Services"
    },

    "PERSISTENCE": {
        "id": "T1547",
        "name": "Boot or Logon Autostart"
    },

    "DEFENSE_EVASION": {
        "id": "T1562",
        "name": "Impair Defenses"
    }

}


# ================================================================
# Evidence Object
# ================================================================

class Evidence:

    def __init__(
        self,
        feature,
        severity,
        reason,
        why,
        mitre=None
    ):

        self.feature = feature

        self.severity = severity

        self.reason = reason

        self.why = why

        self.mitre = mitre

        self.score = SEVERITY_SCORE.get(
            severity,
            0
        )

    def to_dict(self):

        obj = {

            "feature": self.feature,

            "severity": self.severity,

            "reason": self.reason,

            "why_it_matters": self.why,

            "score": self.score

        }

        if self.mitre:

            obj["mitre"] = self.mitre

        return obj


# ================================================================
# Utility Functions
# ================================================================

def get(data, key, default=None):

    if data is None:
        return default

    return data.get(key, default)


def truthy(value):

    if isinstance(value, bool):
        return value

    if value is None:
        return False

    if isinstance(value, int):
        return value != 0

    if isinstance(value, str):

        return value.lower() in (
            "true",
            "yes",
            "1"
        )

    return bool(value)


def entropy(text):

    if not text:
        return 0

    freq = defaultdict(int)

    for c in text:
        freq[c] += 1

    length = len(text)

    e = 0

    for v in freq.values():

        p = v / length

        e -= p * math.log2(p)

    return round(e, 3)


# ================================================================
# Risk Calculation
# ================================================================

def risk_level(score):

    if score >= 80:
        return CRITICAL

    if score >= 50:
        return HIGH

    if score >= 20:
        return MEDIUM

    return LOW


def confidence(score):

    if score >= 80:
        return "Very High"

    if score >= 60:
        return "High"

    if score >= 30:
        return "Medium"

    return "Low"


# ================================================================
# Evidence Collector
# ================================================================

class EvidenceCollector:

    def __init__(self):

        self.items = []

        self.total_score = 0

    def add(self, evidence):

        self.items.append(evidence)

        self.total_score += evidence.score

    def extend(self, evidence_list):

        for e in evidence_list:
            self.add(e)

    def deduplicate(self):

        unique = {}

        for item in self.items:

            key = (
                item.feature,
                item.reason
            )

            unique[key] = item

        self.items = list(unique.values())

    def score(self):

        return self.total_score

    def risk(self):

        return risk_level(
            self.total_score
        )

    def confidence(self):

        return confidence(
            self.total_score
        )

    def json(self):

        return [
            e.to_dict()
            for e in self.items
        ]


# ================================================================
# Rule Engines
#
# Part 2 starts here
# ================================================================

# ================================================================
# Thread Rule Engine
# Matches extract_threads() from extract_features.py
# ================================================================

def analyze_threads(thread_features):

    collector = EvidenceCollector()

    if not thread_features:
        return collector

    thread_count = get(thread_features, "thread_count", 0)

    if thread_count > 100:

        collector.add(
            Evidence(
                feature="High Thread Count",
                severity="LOW",
                reason=f"The process created {thread_count} threads.",
                why="Processes with an unusually large number of threads may deserve further investigation."
            )
        )

    # ------------------------------------------------------------
    # Anonymous Memory Threads
    # ------------------------------------------------------------

    anonymous = get(
        thread_features,
        "anonymous_memory_thread_count",
        0
    )

    if anonymous > 0:

        collector.add(
            Evidence(
                feature="Anonymous Memory Thread",
                severity="HIGH",
                reason=f"{anonymous} thread(s) execute from anonymous memory.",
                why="Threads executing outside image-backed memory are commonly associated with injected code.",
                mitre=MITRE["PROCESS_INJECTION"]
            )
        )

    # ------------------------------------------------------------
    # Thread Start Address Anomaly
    # ------------------------------------------------------------

    anomaly = get(
        thread_features,
        "thread_start_address_anomaly_count",
        0
    )

    if anomaly > 0:

        collector.add(
            Evidence(
                feature="Thread Start Address Anomaly",
                severity="HIGH",
                reason=f"{anomaly} thread(s) have suspicious start addresses.",
                why="Thread start addresses that do not belong to loaded modules may indicate process injection.",
                mitre=MITRE["PROCESS_INJECTION"]
            )
        )

    # ------------------------------------------------------------
    # Threads without module
    # ------------------------------------------------------------

    no_module = get(
        thread_features,
        "thread_with_no_module_count",
        0
    )

    if no_module > 0:

        collector.add(
            Evidence(
                feature="Thread Without Module",
                severity="HIGH",
                reason=f"{no_module} thread(s) are not associated with any loaded module.",
                why="Execution outside a legitimate image is a common memory-injection indicator.",
                mitre=MITRE["PROCESS_INJECTION"]
            )
        )

    # ------------------------------------------------------------
    # Remote Thread
    # ------------------------------------------------------------

    if get(thread_features, "remote_thread_flag", False):

        collector.add(
            Evidence(
                feature="Remote Thread",
                severity="CRITICAL",
                reason="A remote thread was detected.",
                why="Remote thread creation is one of the most common techniques used during process injection.",
                mitre=MITRE["PROCESS_INJECTION"]
            )
        )

    # ------------------------------------------------------------
    # Foreign Process Thread
    # ------------------------------------------------------------

    if get(thread_features, "thread_in_foreign_process", False):

        collector.add(
            Evidence(
                feature="Foreign Process Thread",
                severity="HIGH",
                reason="The process owns thread(s) executing inside another process.",
                why="Threads executing in foreign processes may indicate code injection.",
                mitre=MITRE["PROCESS_INJECTION"]
            )
        )

    # ------------------------------------------------------------
    # RWX Execution
    # ------------------------------------------------------------

    rwx = get(
        thread_features,
        "rwx_execution_count",
        0
    )

    if rwx > 0:

        collector.add(
            Evidence(
                feature="RWX Thread Execution",
                severity="CRITICAL",
                reason=f"{rwx} executable read-write memory region(s) detected.",
                why="RWX memory is frequently used by shellcode and malware.",
                mitre=MITRE["PROCESS_INJECTION"]
            )
        )

    # ------------------------------------------------------------
    # Suspended Threads
    # ------------------------------------------------------------

    suspended = get(
        thread_features,
        "suspended_thread_count",
        0
    )

    if suspended > 5:

        collector.add(
            Evidence(
                feature="Suspended Threads",
                severity="LOW",
                reason=f"{suspended} suspended thread(s) detected.",
                why="Large numbers of suspended threads may indicate process manipulation."
            )
        )

    # ------------------------------------------------------------
    # Priority Anomaly
    # ------------------------------------------------------------

    priority = get(
        thread_features,
        "thread_priority_anomaly_count",
        0
    )

    if priority > 0:

        collector.add(
            Evidence(
                feature="Abnormal Thread Priority",
                severity="MEDIUM",
                reason=f"{priority} thread(s) use unusually high priorities.",
                why="Attackers sometimes increase thread priority to ensure malicious code executes promptly."
            )
        )

    return collector

# ================================================================
# DLL Rule Engine
# Matches extract_dlls() from extract_features.py
# ================================================================

def analyze_dlls(dll_features):

    collector = EvidenceCollector()

    if not dll_features:
        return collector

    dlls = get(dll_features, "dlls", [])

    if not dlls:
        return collector

    dll_count = get(dll_features, "dll_count", len(dlls))

    if dll_count > 250:

        collector.add(
            Evidence(
                feature="High DLL Count",
                severity="LOW",
                reason=f"The process loaded {dll_count} DLLs.",
                why="An unusually large number of loaded modules may indicate abnormal execution."
            )
        )

    # ------------------------------------------------------------
    # Analyse every DLL individually
    # ------------------------------------------------------------

    unsigned = []
    temp = []
    reflective = []
    spoofed = []
    unknown = []

    entropy_hits = []

    for dll in dlls:

        name = get(dll, "name", "Unknown")

        # ------------------------------------------

        if get(dll, "unsigned_dll", False):
            unsigned.append(name)

        # ------------------------------------------

        if get(dll, "dll_from_temp_appdata", False):
            temp.append(name)

        # ------------------------------------------

        if get(
            dll,
            "missing_from_peb_reflective_indicator",
            False
        ):
            reflective.append(name)

        # ------------------------------------------

        if get(
            dll,
            "dll_name_spoof_suspect",
            False
        ):
            spoofed.append(name)

        # ------------------------------------------

        if get(
            dll,
            "dll_not_in_known_list",
            False
        ):
            unknown.append(name)

        # ------------------------------------------

        entropy = get(
            dll,
            "dll_path_entropy"
        )

        if entropy is not None and entropy >= 4.5:

            entropy_hits.append(
                f"{name} ({entropy:.2f})"
            )

    # ------------------------------------------------------------
    # Unsigned DLLs
    # ------------------------------------------------------------

    if unsigned:

        collector.add(

            Evidence(

                feature="Unsigned DLL",

                severity="HIGH",

                reason=f"{len(unsigned)} unsigned DLL(s): "
                       + ", ".join(unsigned[:5]),

                why="Unsigned DLLs may indicate DLL sideloading or malicious modules.",

                mitre=MITRE["DLL_SIDELOADING"]

            )
        )

    # ------------------------------------------------------------
    # DLLs from Temp/AppData
    # ------------------------------------------------------------

    if temp:

        collector.add(

            Evidence(

                feature="DLL Loaded From Temp",

                severity="HIGH",

                reason=f"DLL(s) loaded from Temp/AppData: "
                       + ", ".join(temp[:5]),

                why="Legitimate software rarely loads executable modules from user-writable directories.",

                mitre=MITRE["DLL_SIDELOADING"]

            )
        )

    # ------------------------------------------------------------
    # Reflective DLL Loading
    # ------------------------------------------------------------

    if reflective:

        collector.add(

            Evidence(

                feature="Reflective DLL Loading",

                severity="CRITICAL",

                reason=f"{len(reflective)} DLL(s) missing from the PEB: "
                       + ", ".join(reflective[:5]),

                why="Modules absent from the Process Environment Block may have been reflectively loaded.",

                mitre=MITRE["PROCESS_INJECTION"]

            )
        )

    # ------------------------------------------------------------
    # DLL Name Spoofing
    # ------------------------------------------------------------

    if spoofed:

        collector.add(

            Evidence(

                feature="DLL Name Spoofing",

                severity="MEDIUM",

                reason="Suspicious DLL names: "
                       + ", ".join(spoofed[:5]),

                why="Malware often mimics legitimate DLL names to evade casual inspection."

            )
        )

    # ------------------------------------------------------------
    # Unknown DLLs
    # ------------------------------------------------------------

    if unknown:

        collector.add(

            Evidence(

                feature="Unknown DLL",

                severity="LOW",

                reason=f"{len(unknown)} DLL(s) not found in the baseline list.",

                why="Modules outside the known baseline deserve additional investigation."

            )
        )

    # ------------------------------------------------------------
    # High Entropy DLL Paths
    # ------------------------------------------------------------

    if entropy_hits:

        collector.add(

            Evidence(

                feature="High Entropy DLL Path",

                severity="LOW",

                reason=", ".join(entropy_hits[:5]),

                why="Randomized directory structures are sometimes used by malware."

            )
        )

    return collector

# ================================================================
# Handle Rule Engine
# Matches extract_handles()
# ================================================================

def analyze_handles(handle_features):

    collector = EvidenceCollector()

    if not handle_features:
        return collector

    # ------------------------------------------------------------
    # LSASS Handle
    # ------------------------------------------------------------

    if get(handle_features, "open_lsass_handle", False):

        collector.add(
            Evidence(
                feature="LSASS Handle",
                severity="CRITICAL",
                reason="The process opened a handle to LSASS.",
                why="Attackers frequently access LSASS during credential dumping.",
                mitre=MITRE["CREDENTIAL_DUMPING"]
            )
        )

    # ------------------------------------------------------------

    sensitive = get(
        handle_features,
        "sensitive_handle_access_count",
        0
    )

    if sensitive > 0:

        collector.add(
            Evidence(
                feature="Sensitive Handle Access",
                severity="HIGH",
                reason=f"{sensitive} sensitive object(s) accessed.",
                why="Accessing security-sensitive objects may indicate credential theft or privilege escalation."
            )
        )

    # ------------------------------------------------------------

    cross = get(
        handle_features,
        "cross_process_handle_count",
        0
    )

    if cross > 0:

        collector.add(
            Evidence(
                feature="Cross Process Handle",
                severity="HIGH",
                reason=f"{cross} cross-process handle(s) detected.",
                why="Processes normally do not access large numbers of handles belonging to other processes."
            )
        )

    # ------------------------------------------------------------

    invalid = get(
        handle_features,
        "invalid_handle_reference_count",
        0
    )

    if invalid > 10:

        collector.add(
            Evidence(
                feature="Invalid Handle References",
                severity="LOW",
                reason=f"{invalid} invalid handles detected.",
                why="Large numbers of invalid handles may indicate unstable or malicious process behavior."
            )
        )

    # ------------------------------------------------------------

    temp = get(
        handle_features,
        "file_handle_in_temp_count",
        0
    )

    if temp > 0:

        collector.add(
            Evidence(
                feature="Temp File Handle",
                severity="MEDIUM",
                reason=f"{temp} file handle(s) point to Temp/AppData.",
                why="Malware frequently stages payloads inside user-writable directories."
            )
        )

    # ------------------------------------------------------------

    registry = get(
        handle_features,
        "sensitive_registry_files_count",
        0
    )

    if registry > 0:

        collector.add(
            Evidence(
                feature="Sensitive Registry Access",
                severity="HIGH",
                reason=f"{registry} sensitive registry hive(s) accessed.",
                why="Registry hives such as SAM and SECURITY contain credential-related information.",
                mitre=MITRE["CREDENTIAL_DUMPING"]
            )
        )

    # ------------------------------------------------------------

    pipes = get(
        handle_features,
        "named_pipe_count",
        0
    )

    if pipes > 10:

        collector.add(
            Evidence(
                feature="Named Pipe Activity",
                severity="LOW",
                reason=f"{pipes} named pipes opened.",
                why="Named pipes can be used for inter-process communication, including malware communication."
            )
        )

    return collector


# ================================================================
# Token / Impersonation Rule Engine
# Matches extract_impersonation()
# ================================================================

def analyze_tokens(token_features):

    collector = EvidenceCollector()

    if not token_features:
        return collector

    # ------------------------------------------------------------

    if get(token_features, "sid_mismatch"):

        collector.add(
            Evidence(
                feature="SID Mismatch",
                severity="HIGH",
                reason="Token SID differs from Process SID.",
                why="SID mismatches may indicate impersonation or token manipulation."
            )
        )

    # ------------------------------------------------------------

    if get(token_features, "token_duplication"):

        collector.add(
            Evidence(
                feature="Duplicated Token",
                severity="HIGH",
                reason="Duplicated access token detected.",
                why="Duplicated tokens are frequently used during privilege escalation."
            )
        )

    # ------------------------------------------------------------

    if get(token_features, "network_logon_token"):

        collector.add(
            Evidence(
                feature="Network Logon Token",
                severity="MEDIUM",
                reason="A network logon token was observed.",
                why="Unexpected network logon tokens may indicate lateral movement."
            )
        )

    # ------------------------------------------------------------

    if get(token_features, "has_debug_privilege"):

        collector.add(
            Evidence(
                feature="SeDebugPrivilege",
                severity="CRITICAL",
                reason="Process possesses SeDebugPrivilege.",
                why="SeDebugPrivilege allows inspection and manipulation of other processes.",
                mitre=MITRE["CREDENTIAL_DUMPING"]
            )
        )

    # ------------------------------------------------------------

    if get(token_features, "has_take_ownership"):

        collector.add(
            Evidence(
                feature="Take Ownership Privilege",
                severity="HIGH",
                reason="SeTakeOwnershipPrivilege is enabled.",
                why="Allows ownership changes on protected objects."
            )
        )

    # ------------------------------------------------------------

    if get(token_features, "has_tcb_privilege"):

        collector.add(
            Evidence(
                feature="TCB Privilege",
                severity="CRITICAL",
                reason="SeTcbPrivilege detected.",
                why="This privilege is extremely powerful and rarely granted to ordinary processes."
            )
        )

    # ------------------------------------------------------------

    if get(token_features, "has_restore_privilege"):

        collector.add(
            Evidence(
                feature="Restore Privilege",
                severity="MEDIUM",
                reason="SeRestorePrivilege detected.",
                why="Allows restoration of protected files."
            )
        )

    # ------------------------------------------------------------

    if get(token_features, "has_load_driver_privilege"):

        collector.add(
            Evidence(
                feature="Load Driver Privilege",
                severity="CRITICAL",
                reason="SeLoadDriverPrivilege detected.",
                why="Allows loading kernel drivers and may enable kernel-level persistence.",
                mitre=MITRE["PERSISTENCE"]
            )
        )

    return collector

# ================================================================
# Netstat Rule Engine
# Matches extract_netstat()
# ================================================================

def analyze_netstat(netstat_features):

    collector = EvidenceCollector()

    if not netstat_features:
        return collector

    # ------------------------------------------------------------
    # Network Activity
    # ------------------------------------------------------------

    if get(netstat_features, "has_network_connection", False):

        collector.add(
            Evidence(
                feature="Network Activity",
                severity="INFO",
                reason="The process has active network connections.",
                why="Network communication is normal for many processes, but becomes significant when combined with other suspicious behaviors."
            )
        )

    # ------------------------------------------------------------

    conn_count = get(netstat_features, "connection_count", 0)

    if conn_count > 100:

        collector.add(
            Evidence(
                feature="High Connection Count",
                severity="MEDIUM",
                reason=f"{conn_count} active connections detected.",
                why="An unusually high number of network connections may indicate scanning, botnet activity, or malware."
            )
        )

    # ------------------------------------------------------------

    foreign = get(netstat_features, "foreign_ip_count", 0)

    if foreign > 0:

        collector.add(
            Evidence(
                feature="Foreign IP Communication",
                severity="MEDIUM",
                reason=f"Connections to {foreign} foreign IP address(es).",
                why="Communication with external IP addresses may represent command-and-control traffic.",
                mitre=MITRE["COMMAND_AND_CONTROL"]
            )
        )

    # ------------------------------------------------------------

    if get(netstat_features, "suspicious_port_flag", False):

        ports = get(netstat_features, "suspicious_ports_hit", [])

        collector.add(
            Evidence(
                feature="Suspicious Port Usage",
                severity="HIGH",
                reason=f"Observed ports: {', '.join(map(str, ports))}",
                why="Ports such as 4444, 1337, 9050, and similar are frequently associated with attacker tools.",
                mitre=MITRE["COMMAND_AND_CONTROL"]
            )
        )

    # ------------------------------------------------------------

    listeners = get(netstat_features, "ephemeral_listener_count", 0)

    if listeners > 0:

        collector.add(
            Evidence(
                feature="Ephemeral Listener",
                severity="MEDIUM",
                reason=f"{listeners} listener(s) on ephemeral ports.",
                why="Unexpected listeners on high-numbered ports may indicate backdoors."
            )
        )

    # ------------------------------------------------------------

    loopback = get(netstat_features, "loopback_connection_count", 0)

    if loopback > 20:

        collector.add(
            Evidence(
                feature="Heavy Loopback Communication",
                severity="LOW",
                reason=f"{loopback} loopback connections detected.",
                why="Large amounts of local IPC traffic may warrant investigation."
            )
        )

    # ------------------------------------------------------------

    dns = get(netstat_features, "dns_over_nonstandard_count", 0)

    if dns > 0:

        collector.add(
            Evidence(
                feature="Unexpected DNS Usage",
                severity="MEDIUM",
                reason=f"{dns} non-standard DNS connection(s).",
                why="DNS communication from unexpected processes can indicate tunneling or malware."
            )
        )

    return collector


# ================================================================
# Mutex Rule Engine
# Matches extract_mutex()
# ================================================================

def analyze_mutex(mutex_features):

    collector = EvidenceCollector()

    if not mutex_features:
        return collector

    mutexes = get(mutex_features, "mutexes", [])

    if not mutexes:
        return collector

    malware = []
    duplicate = []
    entropy = []
    global_mutex = []
    guid = []

    for mutex in mutexes:

        name = get(mutex, "mutex_name", "")

        if get(mutex, "known_malware_mutex", False):
            malware.append(name)

        if get(mutex, "duplicate_mutex_across_pids", False):
            duplicate.append(name)

        if get(mutex, "rare_mutex_name", False):
            entropy.append(name)

        if get(mutex, "global_mutex_flag", False):
            global_mutex.append(name)

        if get(mutex, "guid_shaped_mutex", False):
            guid.append(name)

    # ------------------------------------------------------------

    if malware:

        collector.add(
            Evidence(
                feature="Known Malware Mutex",
                severity="CRITICAL",
                reason=", ".join(malware[:5]),
                why="Mutex names match known malware indicators.",
                mitre=MITRE["PERSISTENCE"]
            )
        )

    # ------------------------------------------------------------

    if duplicate:

        collector.add(
            Evidence(
                feature="Duplicate Mutex",
                severity="MEDIUM",
                reason=f"{len(duplicate)} mutex(es) shared across processes.",
                why="Shared mutexes may indicate coordinated malware activity."
            )
        )

    # ------------------------------------------------------------

    if global_mutex:

        collector.add(
            Evidence(
                feature="Global Mutex",
                severity="LOW",
                reason=f"{len(global_mutex)} Global\\ mutex(es) detected.",
                why="Global mutexes are used for cross-session synchronization."
            )
        )

    # ------------------------------------------------------------

    if guid:

        collector.add(
            Evidence(
                feature="GUID-style Mutex",
                severity="LOW",
                reason=f"{len(guid)} GUID-like mutex name(s).",
                why="Random GUID mutexes are commonly used by malware families."
            )
        )

    # ------------------------------------------------------------

    if entropy:

        collector.add(
            Evidence(
                feature="Rare Mutex Name",
                severity="LOW",
                reason=f"{len(entropy)} rare mutex name(s).",
                why="Rare or unique mutex names can help identify suspicious software."
            )
        )

    return collector

# ================================================================
# Process Information Rule Engine
# Matches extract_procinfo()
# ================================================================

def analyze_procinfo(procinfo_features):

    collector = EvidenceCollector()

    if not procinfo_features:
        return collector

    if get(procinfo_features, "has_attached_debugger"):

        collector.add(
            Evidence(
                feature="Attached Debugger",
                severity="HIGH",
                reason="A debugger is attached to this process.",
                why="Debuggers are commonly used during malware execution or reverse engineering."
            )
        )

    if get(procinfo_features, "peb_dll_mismatch"):

        collector.add(
            Evidence(
                feature="PEB DLL Mismatch",
                severity="HIGH",
                reason="Loaded modules differ from the Process Environment Block.",
                why="PEB inconsistencies may indicate hidden or reflectively loaded modules.",
                mitre=MITRE["DEFENSE_EVASION"]
            )
        )

    if get(procinfo_features, "loading_from_temp_or_appdata"):

        collector.add(
            Evidence(
                feature="Executable in Temp/AppData",
                severity="HIGH",
                reason="Process image executed from Temp/AppData.",
                why="Legitimate system executables rarely execute from user-writable directories.",
                mitre=MITRE["PERSISTENCE"]
            )
        )

    if get(procinfo_features, "image_path_command_line_mismatch"):

        collector.add(
            Evidence(
                feature="Image Path Mismatch",
                severity="MEDIUM",
                reason="Image path differs from command line.",
                why="Attackers sometimes disguise executable locations."
            )
        )

    if get(procinfo_features, "aslr_disabled"):

        collector.add(
            Evidence(
                feature="ASLR Disabled",
                severity="MEDIUM",
                reason="Address Space Layout Randomization is disabled.",
                why="Disabling ASLR reduces exploit mitigation."
            )
        )

    if get(procinfo_features, "dep_disabled"):

        collector.add(
            Evidence(
                feature="DEP Disabled",
                severity="HIGH",
                reason="Data Execution Prevention is disabled.",
                why="DEP protects against code execution in writable memory."
            )
        )

    return collector


# ================================================================
# PSList Rule Engine
# Matches extract_pslist()
# ================================================================

def analyze_pslist(pslist_features):

    collector = EvidenceCollector()

    if not pslist_features:
        return collector

    if get(pslist_features, "parent_child_mismatch"):

        collector.add(
            Evidence(
                feature="Parent Process Mismatch",
                severity="HIGH",
                reason="Unexpected parent-child relationship detected.",
                why="Process lineage inconsistent with normal Windows behaviour."
            )
        )

    if get(pslist_features, "orphan_process_flag"):

        collector.add(
            Evidence(
                feature="Orphan Process",
                severity="MEDIUM",
                reason="Parent process is missing.",
                why="Orphan processes may result from process hollowing or terminated parents."
            )
        )

    if get(pslist_features, "commandline_empty"):

        collector.add(
            Evidence(
                feature="Empty Command Line",
                severity="LOW",
                reason="Process has an empty command line.",
                why="Legitimate applications usually retain command-line information."
            )
        )

    if get(pslist_features, "commandline_has_base64"):

        collector.add(
            Evidence(
                feature="Base64 Command Line",
                severity="HIGH",
                reason="Base64-encoded content detected in the command line.",
                why="PowerShell and malware frequently encode commands using Base64."
            )
        )

    if get(pslist_features, "commandline_has_url"):

        collector.add(
            Evidence(
                feature="URL in Command Line",
                severity="MEDIUM",
                reason="URL found in the command line.",
                why="Processes downloading payloads often contain URLs."
            )
        )

    entropy = get(pslist_features, "process_name_entropy")

    if entropy is not None and entropy > 3.5:

        collector.add(
            Evidence(
                feature="Random Process Name",
                severity="LOW",
                reason=f"Process name entropy = {entropy:.2f}.",
                why="Random-looking process names are common among malware."
            )
        )

    return collector


# ================================================================
# VAD Rule Engine
# Matches extract_vad()
# ================================================================

def analyze_vad(vad_features):

    collector = EvidenceCollector()

    if not vad_features:
        return collector

    rwx = get(vad_features, "private_rwx_region_count", 0)

    if rwx > 0:

        collector.add(
            Evidence(
                feature="Private RWX Memory",
                severity="CRITICAL",
                reason=f"{rwx} private RWX region(s) detected.",
                why="Private executable writable memory is a classic indicator of injected shellcode.",
                mitre=MITRE["PROCESS_INJECTION"]
            )
        )

    no_file = get(vad_features, "no_file_backing_count", 0)

    if no_file > 5:

        collector.add(
            Evidence(
                feature="Anonymous Memory Regions",
                severity="MEDIUM",
                reason=f"{no_file} memory region(s) without file backing.",
                why="Anonymous executable memory may contain unpacked malware."
            )
        )

    return collector


# ================================================================
# Driver Rule Engine
# Matches global.driver_features
# ================================================================

def analyze_drivers(driver_features):

    collector = EvidenceCollector()

    if not driver_features:
        return collector

    unsigned = get(driver_features, "unsigned_driver_count", 0)

    if unsigned > 0:

        collector.add(
            Evidence(
                feature="Unsigned Driver",
                severity="CRITICAL",
                reason=f"{unsigned} unsigned driver(s) detected.",
                why="Unsigned kernel drivers are commonly associated with rootkits.",
                mitre=MITRE["PERSISTENCE"]
            )
        )

    hidden = get(driver_features, "hidden_driver_count", 0)

    if hidden > 0:

        collector.add(
            Evidence(
                feature="Hidden Driver",
                severity="CRITICAL",
                reason=f"{hidden} hidden driver(s) detected.",
                why="Hidden kernel drivers strongly indicate kernel-level stealth."
            )
        )

    rwx = get(driver_features, "rwx_driver_section_count", 0)

    if rwx > 0:

        collector.add(
            Evidence(
                feature="RWX Driver Section",
                severity="CRITICAL",
                reason=f"{rwx} driver(s) contain RWX sections.",
                why="Kernel drivers should rarely expose executable writable sections."
            )
        )

    return collector

# ================================================================
# Correlation Engine
# ================================================================

def correlate_findings(process_features,
                       thread_ev,
                       dll_ev,
                       handle_ev,
                       token_ev,
                       net_ev,
                       mutex_ev,
                       proc_ev,
                       ps_ev,
                       vad_ev,
                       driver_ev):

    collector = EvidenceCollector()

    tf = process_features.get("thread_features", {})
    df = process_features.get("dll_features", {})
    hf = process_features.get("handle_features", {})
    inf = process_features.get("impersonation_features", {})
    nf = process_features.get("netstat_features", {})
    pf = process_features.get("procinfo_features", {})
    vf = process_features.get("vad_features", {})

    # ============================================================
    # PROCESS INJECTION
    # ============================================================

    injection_score = 0

    if get(tf, "remote_thread_flag"):
        injection_score += 2

    if get(vf, "private_rwx_region_count", 0) > 0:
        injection_score += 2

    if get(tf, "thread_start_address_anomaly_count", 0) > 0:
        injection_score += 1

    if get(pf, "peb_dll_mismatch"):
        injection_score += 1

    if injection_score >= 4:

        collector.add(
            Evidence(
                feature="Process Injection",
                severity="CRITICAL",
                reason="Multiple indicators strongly suggest process injection.",
                why="Remote threads, RWX memory and abnormal thread execution commonly occur together during code injection.",
                mitre=MITRE["PROCESS_INJECTION"]
            )
        )

    # ============================================================
    # REFLECTIVE DLL LOADING
    # ============================================================

    reflective = False

    for dll in get(df, "dlls", []):

        if get(dll, "missing_from_peb_reflective_indicator"):

            reflective = True
            break

    if reflective and get(vf, "private_rwx_region_count", 0) > 0:

        collector.add(
            Evidence(
                feature="Reflective DLL Injection",
                severity="CRITICAL",
                reason="DLL missing from PEB together with private executable memory.",
                why="Reflective DLL loading bypasses the Windows loader and commonly leaves these artifacts.",
                mitre=MITRE["PROCESS_INJECTION"]
            )
        )

    # ============================================================
    # CREDENTIAL DUMPING
    # ============================================================

    cred_score = 0

    if get(hf, "open_lsass_handle"):
        cred_score += 2

    if get(inf, "has_debug_privilege"):
        cred_score += 2

    if get(hf, "sensitive_registry_files_count", 0) > 0:
        cred_score += 1

    if cred_score >= 3:

        collector.add(
            Evidence(
                feature="Credential Dumping",
                severity="CRITICAL",
                reason="Multiple indicators of credential theft detected.",
                why="LSASS access combined with elevated privileges strongly suggests credential dumping.",
                mitre=MITRE["CREDENTIAL_DUMPING"]
            )
        )

    # ============================================================
    # COMMAND AND CONTROL
    # ============================================================

    c2_score = 0

    if get(nf, "foreign_ip_count", 0) > 0:
        c2_score += 1

    if get(nf, "suspicious_port_flag"):
        c2_score += 2

    if get(nf, "ephemeral_listener_count", 0) > 0:
        c2_score += 1

    if c2_score >= 3:

        collector.add(
            Evidence(
                feature="Possible Command and Control",
                severity="HIGH",
                reason="Suspicious external communication detected.",
                why="Unexpected foreign IPs and suspicious ports frequently indicate C2 activity.",
                mitre=MITRE["COMMAND_AND_CONTROL"]
            )
        )

    # ============================================================
    # PRIVILEGE ESCALATION
    # ============================================================

    escalation = 0

    if get(inf, "token_duplication"):
        escalation += 1

    if get(inf, "sid_mismatch"):
        escalation += 1

    if get(inf, "has_tcb_privilege"):
        escalation += 2

    if get(inf, "has_take_ownership"):
        escalation += 1

    if escalation >= 3:

        collector.add(
            Evidence(
                feature="Privilege Escalation",
                severity="HIGH",
                reason="Multiple token manipulation indicators detected.",
                why="Privilege escalation often involves duplicated tokens, SID changes and powerful privileges."
            )
        )

    # ============================================================
    # KERNEL ROOTKIT
    # ============================================================

    drv = process_features.get("global_driver_features", {})

    if drv:

        if (
            get(drv, "hidden_driver_count", 0) > 0 and
            get(drv, "unsigned_driver_count", 0) > 0
        ):

            collector.add(
                Evidence(
                    feature="Kernel Rootkit",
                    severity="CRITICAL",
                    reason="Hidden unsigned kernel driver detected.",
                    why="Kernel rootkits commonly hide unsigned drivers to evade detection.",
                    mitre=MITRE["PERSISTENCE"]
                )
            )

    return collector

# ================================================================
# Build Final Process Report
# ================================================================

def build_process_report(pid, process_features, global_driver_features):

    thread_ev = analyze_threads(
        process_features.get("thread_features", {})
    )

    dll_ev = analyze_dlls(
        process_features.get("dll_features", {})
    )

    handle_ev = analyze_handles(
        process_features.get("handle_features", {})
    )

    token_ev = analyze_tokens(
        process_features.get("impersonation_features", {})
    )

    net_ev = analyze_netstat(
        process_features.get("netstat_features", {})
    )

    mutex_ev = analyze_mutex(
        process_features.get("mutex_features", {})
    )

    proc_ev = analyze_procinfo(
        process_features.get("procinfo_features", {})
    )

    ps_ev = analyze_pslist(
        process_features.get("pslist_features", {})
    )

    vad_ev = analyze_vad(
        process_features.get("vad_features", {})
    )

    driver_ev = analyze_drivers(
        global_driver_features
    )

    process_features["global_driver_features"] = global_driver_features

    corr_ev = correlate_findings(
        process_features,
        thread_ev,
        dll_ev,
        handle_ev,
        token_ev,
        net_ev,
        mutex_ev,
        proc_ev,
        ps_ev,
        vad_ev,
        driver_ev
    )

    final = EvidenceCollector()

    for ev in [
        thread_ev,
        dll_ev,
        handle_ev,
        token_ev,
        net_ev,
        mutex_ev,
        proc_ev,
        ps_ev,
        vad_ev,
        driver_ev,
        corr_ev
    ]:
        final.extend(ev.items)

    final.deduplicate()

    return final

# ================================================================
# Analyst Summary
# ================================================================

def generate_summary(process_name, collector):

    score = collector.score()

    risk = collector.risk()

    features = [
        e.feature
        for e in collector.items[:5]
    ]

    if not features:

        return (
            f"{process_name} exhibited no significant malicious indicators."
        )

    feature_text = ", ".join(features)

    return (
        f"{process_name} generated "
        f"{len(collector.items)} evidence item(s). "
        f"Overall risk is {risk}. "
        f"Key observations include {feature_text}. "
        f"Total detection score: {score}."
    )

# ================================================================
# Convert Collector -> JSON
# ================================================================

def collector_to_json(
    pid,
    process_name,
    collector
):

    return {

        "pid": pid,

        "process_name": process_name,

        "risk": collector.risk(),

        "confidence": collector.confidence(),

        "score": collector.score(),

        "evidence_count": len(
            collector.items
        ),

        "summary": generate_summary(
            process_name,
            collector
        ),

        "evidence": [

            item.to_dict()

            for item in collector.items

        ]

    }

# ================================================================
# Build evidence.json
# ================================================================

def build_evidence(features_json):

    output = {

        "processes": {}

    }

    global_driver_features = (
        features_json
        .get("global", {})
        .get("driver_features", {})
    )

    for pid, proc in features_json["processes"].items():

        process_name = pid

        collector = build_process_report(
            pid,
            proc,
            global_driver_features
        )

        output["processes"][pid] = (
            collector_to_json(
                pid,
                process_name,
                collector
            )
        )

    return output

# ================================================================
# Main
# ================================================================

def main():

    parser = argparse.ArgumentParser(
        description="Evidence Builder"
    )

    parser.add_argument(
        "--features",
        required=True,
        help="features.json generated by extract_features.py"
    )

    parser.add_argument(
        "--output",
        default="evidence.json",
        help="Output evidence file"
    )

    args = parser.parse_args()

    with open(args.features, "r") as f:

        features = json.load(f)

    evidence = build_evidence(features)

    with open(args.output, "w") as f:

        json.dump(
            evidence,
            f,
            indent=4
        )

    print(
        f"[+] Evidence written to {args.output}"
    )


if __name__ == "__main__":
    main()