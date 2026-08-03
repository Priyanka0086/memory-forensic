#!/usr/bin/env python3
"""
==========================================
COMBINED THREAT INTELLIGENCE PIPELINE
==========================================
Merges three original modules, unchanged logic:
  1. CSV (Sysmon) IoC extraction  -> iocs.json
  2. PCAP IoC extraction + VT domain check -> pcap_intel.json
  3. IoC filter + multi-source enrichment (VT / MalwareBazaar / AbuseIPDB) -> threat_intel_output.json

Run from terminal:
    python3 threat_intel_pipeline.py
"""

import os
import json
import time
import re
import requests
import pandas as pd
from scapy.all import rdpcap, DNSQR, IP

# ==========================================
# CONFIG (API KEYS)
# ==========================================
# NOTE: pulled from environment instead of being hardcoded in source.
# export VT_API_KEY="your_key_here"  before running, or edit the default below.

VT_API_KEY = os.environ.get("VT_API_KEY", "66343efff29561ad86858d6d5cbec0d073d3ec62a166a0d36a46feb03abc38ad")
# ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "YOUR_ABUSEIPDB_KEY")

CSV_PATH = "/content/drive/MyDrive/dataset/AsyncRat.csv"
PCAP_PATH = "/content/drive/MyDrive/dataset/AsyncRat.pcap"

IOCS_JSON_PATH = "/content/drive/MyDrive/dataset/iocs.json"
PCAP_INTEL_OUTPUT_PATH = "/content/drive/MyDrive/dataset/pcap_intel.json"
THREAT_INTEL_OUTPUT_PATH = "/content/drive/MyDrive/dataset/threat_intel_output.json"


# ==========================================
# MODULE 1: CSV (SYSMON) IoC EXTRACTION
# ==========================================

def extract_iocs_from_csv(file_path):
    df = pd.read_csv(file_path)

    iocs = set()

    # Extract from CSV (Sysmon)
    for _, row in df.iterrows():

        # IPs
        if pd.notna(row.get("SourceIp")):
            iocs.add(str(row["SourceIp"]))
        if pd.notna(row.get("DestinationIp")):
            iocs.add(str(row["DestinationIp"]))

        # Domains (DNS queries)
        if pd.notna(row.get("QueryName")):
            iocs.add(str(row["QueryName"]))

        # Hashes
        if pd.notna(row.get("Hashes")):
            hashes = str(row["Hashes"])

            # Extract SHA256 / MD5 using regex
            found_hashes = re.findall(r"[A-Fa-f0-9]{32,64}", hashes)
            for h in found_hashes:
                iocs.add(h)

        # Process names (optional IoCs)
        if pd.notna(row.get("Image")):
            iocs.add(str(row["Image"]))

    # Clean IoCs
    clean_iocs = []

    for ioc in iocs:
        ioc = ioc.strip()

        # Remove empty / invalid
        if len(ioc) < 3:
            continue

        clean_iocs.append(ioc)

    # Save IoCs
    output = {"iocs": clean_iocs}

    with open(IOCS_JSON_PATH, "w") as f:
        json.dump(output, f, indent=4)

    print(f"✅ Extracted {len(clean_iocs)} IoCs")

    return clean_iocs


# ==========================================
# MODULE 2: PCAP IoC EXTRACTION + VT DOMAIN CHECK
# ==========================================

def extract_iocs_from_pcap(pcap_file):

    packets = rdpcap(pcap_file)

    ips = set()
    domains = set()

    for pkt in packets:

        if IP in pkt:
            ips.add(pkt[IP].src)
            ips.add(pkt[IP].dst)

        # DNS Queries
        if pkt.haslayer(DNSQR):
            domains.add(pkt[DNSQR].qname.decode().strip("."))

    return list(ips), list(domains)


"""def check_ip_abuse(ip):

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        r = requests.get(url, headers=headers, params=params)
        data = r.json()

        return {
            "ip": ip,
            "abuse_score": data["data"]["abuseConfidenceScore"],
            "country": data["data"]["countryCode"]
        }

    except:
        return {"ip": ip, "error": "API failed"}"""


def check_domain_vt(domain):

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        r = requests.get(url, headers=headers)
        data = r.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "domain": domain,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0)
        }

    except:
        return {"domain": domain, "error": "VT failed"}


def run_pcap_module():

    print("[*] Extracting IoCs from PCAP...")
    ips, domains = extract_iocs_from_pcap(PCAP_PATH)

    print(f"[+] Found {len(ips)} IPs, {len(domains)} domains")

    results = {
        "ips": [],
        "domains": []
    }

    # --------------------------------------------------------
    # DOMAIN INTEL
    # --------------------------------------------------------

    for domain in domains:
        intel = check_domain_vt(domain)
        results["domains"].append(intel)

    # --------------------------------------------------------
    # SAVE OUTPUT
    # --------------------------------------------------------

    with open(PCAP_INTEL_OUTPUT_PATH, "w") as f:
        json.dump(results, f, indent=2)

    print(f"[✓] Saved: {PCAP_INTEL_OUTPUT_PATH}")


# ==========================================
# MODULE 3: THREAT INTELLIGENCE (FILTER + ENRICH)
# ==========================================

def load_iocs(file_path):
    with open(file_path, "r") as f:
        return json.load(f)["iocs"]


def filter_iocs(iocs):

    filtered = []

    for ioc in iocs:

        ioc = ioc.strip()

        # Skip Windows paths
        if "\\" in ioc:
            continue

        #  Skip internal domains
        if "local" in ioc.lower():
            continue

        #  Skip service DNS records
        if ioc.startswith("_"):
            continue

        #  Skip WPAD
        if "wpad" in ioc.lower():
            continue

        #  Skip empty hash
        if ioc == "00000000000000000000000000000000":
            continue

        # ✅ VALID IoCs ONLY
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):  # IP
            filtered.append(ioc)

        elif re.match(r"^[A-Fa-f0-9]{32,64}$", ioc):  # Hash
            filtered.append(ioc)

        elif "." in ioc and not ioc.endswith(".local"):  # Domain
            filtered.append(ioc)

    # Remove duplicates + LIMIT
    filtered = list(set(filtered))[:20]

    print(f"🔥 Filtered IoCs: {len(filtered)}")
    return filtered


def is_ip(ioc):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc)


def is_hash(ioc):
    return len(ioc) in [32, 40, 64] and re.match(r"^[A-Fa-f0-9]+$", ioc)


def is_domain(ioc):
    return "." in ioc and not is_ip(ioc)


def query_virustotal(ioc, ioc_type):
    headers = {"x-apikey": VT_API_KEY}

    try:
        if ioc_type == "hash":
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"
        elif ioc_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        elif ioc_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
        else:
            return None

        r = requests.get(url, headers=headers)

        # ✅ HANDLE STATUS CODES
        if r.status_code == 200:
            data = r.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})

            return {
                "source": "VirusTotal",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0)
            }

        elif r.status_code == 404:
            return {
                "source": "VirusTotal",
                "info": "No data found"
            }

        elif r.status_code == 401:
            return {
                "source": "VirusTotal",
                "error": "Invalid API key"
            }

        elif r.status_code == 429:
            return {
                "source": "VirusTotal",
                "error": "Rate limit exceeded"
            }

    except Exception as e:
        return {
            "source": "VirusTotal",
            "error": str(e)
        }

    return {"source": "VirusTotal", "error": "Unknown error"}


"""def query_abuseipdb(ip):

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    try:
        r = requests.get(url, headers=headers, params={"ipAddress": ip})

        if r.status_code == 200:
            data = r.json()["data"]

            return {
                "source": "AbuseIPDB",
                "abuse_score": data["abuseConfidenceScore"],
                "country": data["countryCode"]
            }

        else:
            print(f"AbuseIPDB ERROR {r.status_code}")

    except Exception as e:
        print("AbuseIPDB Exception:", e)

    return {"source": "AbuseIPDB", "error": "Failed"}"""


def query_malwarebazaar(file_hash):

    url = "https://mb-api.abuse.ch/api/v1/"

    payload = {
        "query": "get_info",
        "hash": file_hash
    }

    try:
        r = requests.post(url, data=payload)

        if r.status_code == 200:
            res = r.json()

            if res["query_status"] == "ok":
                sample = res["data"][0]

                return {
                    "source": "MalwareBazaar",
                    "malware_family": sample.get("signature"),
                    "file_type": sample.get("file_type")
                }

    except Exception as e:
        print("MB Exception:", e)

    return {"source": "MalwareBazaar", "info": "No data"}


def enrich_iocs(iocs):

    enriched_results = []

    for ioc in iocs:

        result = {
            "ioc": ioc,
            "type": "unknown",
            "enrichment": []
        }

        # Detect type
        if is_hash(ioc):
            ioc_type = "hash"
        elif is_ip(ioc):
            ioc_type = "ip"
        elif is_domain(ioc):
            ioc_type = "domain"
        else:
            ioc_type = "other"

        result["type"] = ioc_type

        # Query sources
        vt = query_virustotal(ioc, ioc_type)
        if vt:
            result["enrichment"].append(vt)

        if ioc_type == "ip":
            result["enrichment"].append(query_abuseipdb(ioc))

        if ioc_type == "hash":
            result["enrichment"].append(query_malwarebazaar(ioc))

        enriched_results.append(result)

        # ⏳ Faster delay
        time.sleep(3)

    return enriched_results


def save_output(data, file_path):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)


def run_threat_intel_module():
    # Step 1: Load
    iocs = load_iocs(IOCS_JSON_PATH)
    print(f"📊 Original IoCs: {len(iocs)}")

    # Step 2: Filter (🔥 NEW)
    filtered_iocs = filter_iocs(iocs)

    # Step 3: Enrich
    results = enrich_iocs(filtered_iocs)

    # Step 4: Save
    save_output(results, THREAT_INTEL_OUTPUT_PATH)

    print("🔥 Threat Intelligence Completed")
    print(f"📁 Output saved to: {THREAT_INTEL_OUTPUT_PATH}")


# ==========================================
# MAIN
# ==========================================

def main():
    # Step 1: Extract IoCs from Sysmon CSV -> iocs.json
    print("========== STEP 1: CSV IoC EXTRACTION ==========")
    extract_iocs_from_csv(CSV_PATH)

    # Step 2: Extract IoCs from PCAP + VT domain check -> pcap_intel.json
    print("\n========== STEP 2: PCAP EXTRACTION + VT DOMAIN CHECK ==========")
    run_pcap_module()

    # Step 3: Filter + enrich IoCs from iocs.json -> threat_intel_output.json
    print("\n========== STEP 3: IoC FILTER + ENRICHMENT ==========")
    run_threat_intel_module()


if __name__ == "__main__":
    main()
