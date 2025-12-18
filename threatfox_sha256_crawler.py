#!/usr/bin/env python3
"""
ThreatFox SHA256 Hash Crawler

Source:
https://threatfox.abuse.ch/export/csv/sha256/recent/

- Fetches recent SHA256 hashes
- Parses ThreatFox CSV format
- Outputs clean CSV for CTI use
"""

import requests
import csv
import os
from datetime import datetime

THREATFOX_URL = "https://threatfox.abuse.ch/export/csv/sha256/recent/"
OUTPUT_DIR = "output"
OUTPUT_FILE = "ThreatFox_SHA256.csv"

os.makedirs(OUTPUT_DIR, exist_ok=True)

HEADERS = {
    "User-Agent": "ThreatIntel-Crawler/1.0"
}

def fetch_data():
    response = requests.get(THREATFOX_URL, headers=HEADERS, timeout=60)
    response.raise_for_status()
    return response.text.splitlines()

def parse_csv(lines):
    results = {}
    
    reader = csv.reader(line for line in lines if not line.startswith("#"))

    for row in reader:
        try:
            sha256 = row[2].strip()
            results[sha256] = {
                "sha256": sha256,
                "malware": row[5],
                "malware_family": row[6],
                "confidence": row[9],
                "first_seen": row[0],
                "last_seen": row[8],
                "reporter": row[13]
            }
        except IndexError:
            continue

    return list(results.values())

def write_csv(data):
    output_path = os.path.join(OUTPUT_DIR, OUTPUT_FILE)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "sha256",
                "malware",
                "malware_family",
                "confidence",
                "first_seen",
                "last_seen",
                "reporter"
            ]
        )
        writer.writeheader()
        writer.writerows(data)

    print(f"[+] Saved {len(data)} SHA256 hashes to {output_path}")

def main():
    print("[*] Fetching ThreatFox SHA256 data...")
    lines = fetch_data()

    print("[*] Parsing CSV...")
    parsed_data = parse_csv(lines)

    print("[*] Writing output...")
    write_csv(parsed_data)

    print("[✓] ThreatFox SHA256 crawler completed successfully")

if __name__ == "__main__":
    main()
