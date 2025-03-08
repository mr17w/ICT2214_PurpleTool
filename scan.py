#!/usr/bin/env python3
import argparse
import subprocess
import sys
import re
import logging
import requests
import textwrap
import threading
import os
from bs4 import BeautifulSoup
from tabulate import tabulate

# Set up logging.
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Ensure outputs directory exists.
OUTPUT_DIR = "outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ----- Nmap Scan Functions -----
def run_nmap_scan(target):
    command = ["nmap", "-sV", "--script", "vulners", "-v", target]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        sys.exit("Error running nmap: " + str(e))

def parse_nmap_output(content):
    lines = content.splitlines()
    host_info = ""
    ports_table = []
    vulners_block = []
    in_ports_table = False
    in_vulners_block = False

    for line in lines:
        line = line.rstrip("\n")
        if line.startswith("Nmap scan report for"):
            host_info = line.strip()
        if line.startswith("PORT"):
            header = re.split(r'\s+', line.strip(), maxsplit=3)
            ports_table.append(header)
            in_ports_table = True
            continue
        if in_ports_table:
            if line.strip() == "" or not re.match(r'^\d+\/\w+', line.strip()):
                in_ports_table = False
            else:
                row = re.split(r'\s+', line.strip(), maxsplit=3)
                ports_table.append(row)
                continue
        if "| vulners:" in line:
            in_vulners_block = True
            content_line = line.split("| vulners:")[-1].strip()
            if content_line:
                vulners_block.append(content_line)
            continue
        if in_vulners_block:
            if line.startswith("|"):
                content_line = line.lstrip("|").strip()
                vulners_block.append(content_line)
            else:
                in_vulners_block = False
    return host_info, ports_table, vulners_block

def parse_vulners_table(vulners_lines):
    cve_entries = []
    for line in vulners_lines:
        line = line.lstrip("-").strip()
        if not line:
            continue
        if line.lower().startswith("cpe:"):
            continue
        parts = re.split(r'\s+', line)
        if len(parts) >= 3:
            vuln_id = parts[0]
            if vuln_id == "_" or vuln_id.strip() == "_":
                continue
            rating = parts[1]
            url = parts[2]
            exploit = parts[3] if len(parts) > 3 else ""
            cve_entries.append([vuln_id, rating, url, exploit])
    return cve_entries

def format_output(host_info, ports_table, vulners_block):
    output_lines = []
    output_lines.append("=== Host Information ===")
    output_lines.append(host_info)
    output_lines.append("")
    output_lines.append("=== Ports Information ===")
    if ports_table:
        table = tabulate(ports_table[1:], headers=ports_table[0], tablefmt="pretty")
        output_lines.append(table)
    else:
        output_lines.append("No ports information found.")
    output_lines.append("")
    output_lines.append("=== Vuln Details Table ===")
    cve_entries = parse_vulners_table(vulners_block)
    if cve_entries:
        cve_table = tabulate(cve_entries, headers=["Identifier", "Rating", "URL", "Exploit"], tablefmt="pretty")
        output_lines.append(cve_table)
    else:
        output_lines.append("No Vuln details found.")
    return "\n".join(output_lines)

# ----- Vulnerability Details Functions -----
CVE_DETAILS_URL = "https://www.cvedetails.com/cve/"
SPLOITUS_URL = "https://sploitus.com/exploit?id="

PATTERN = re.compile(
    r'\b('
    r'CVE-\d{4}-\d{4,7}'
    r'|[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}'
    r'|PACKETSTORM:\d+'
    r'|1337DAY-ID-\d+'
    r'|SSV:\d+'
    r')\b'
)

def fetch_cve_details(cve_id: str) -> tuple:
    try:
        url = f"{CVE_DETAILS_URL}{cve_id}/"
        headers = {
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/120.0.0.0 Safari/537.36")
        }
        response = requests.get(url, headers=headers)
        response.encoding = "utf-8"
        if response.status_code != 200:
            logging.error(f"Failed to fetch data for {cve_id} (HTTP {response.status_code})")
            return (cve_id, "CVE", url, f"No data available (HTTP {response.status_code})")
        soup = BeautifulSoup(response.text, "html.parser")
        desc_tag = soup.find("div", {"class": "cvedetailssummary-text"})
        description = desc_tag.get_text(strip=True) if desc_tag else "No description found."
        logging.info(f"Fetched details for {cve_id}")
        return (cve_id, "CVE", url, description)
    except Exception as e:
        logging.error(f"Error fetching CVE details for {cve_id}: {e}")
        return (cve_id, "CVE", "", "Error retrieving data")

def fetch_exploit_details(exploit_id: str) -> tuple:
    try:
        url = f"{SPLOITUS_URL}{exploit_id}"
        headers = {
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/120.0.0.0 Safari/537.36")
        }
        response = requests.get(url, headers=headers)
        response.encoding = "utf-8"
        if response.status_code != 200:
            logging.error(f"Failed to fetch data for {exploit_id} (HTTP {response.status_code})")
            return (exploit_id, "Exploit", url, f"No data available (HTTP {response.status_code})")
        soup = BeautifulSoup(response.text, "html.parser")
        desc_tag = soup.find("pre", {"data-lang": "MARKDOWN"})
        description = desc_tag.get_text(strip=True) if desc_tag else "No description found."
        logging.info(f"Fetched details for {exploit_id}")
        return (exploit_id, "Exploit", url, description)
    except Exception as e:
        logging.error(f"Error fetching exploit details for {exploit_id}: {e}")
        return (exploit_id, "Exploit", "", "Error retrieving data")

def extract_ids_from_text(text: str) -> set:
    return set(match.group(0) for match in PATTERN.finditer(text))

def fetch_vulnerability_details(input_file: str):
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        logging.error(f"Error reading file {input_file}: {e}")
        sys.exit(1)

    vuln_ids = extract_ids_from_text(content)
    if not vuln_ids:
        logging.info("No vulnerability IDs found in the file.")
        return

    logging.info(f"Found {len(vuln_ids)} unique vulnerability IDs.")
    results = []
    for vuln_id in sorted(vuln_ids):
        if "CVE" in vuln_id.upper():
            result = fetch_cve_details(vuln_id.upper())
        else:
            result = fetch_exploit_details(vuln_id)
        results.append(result)

    results.sort(key=lambda x: (0 if x[1].upper() == "CVE" else 1, x[0].upper()))

    wrapped_results = []
    for identifier, vtype, url, description in results:
        wrapped_description = textwrap.fill(
            description,
            width=100,
            break_long_words=False,
            break_on_hyphens=False
        )
        wrapped_results.append((identifier, vtype, url, wrapped_description))

    headers = ["Identifier", "Type", "URL", "Description"]
    table = tabulate(wrapped_results, headers=headers, tablefmt="grid")
    output_file = os.path.join(OUTPUT_DIR, "exploitCVE_details.txt")
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(table)
        logging.info(f"Vulnerability details saved to {output_file}")
    except Exception as e:
        logging.error(f"Error writing to {output_file}: {e}")

# ----- Website Scanner Function -----
def run_website_scanner(website):
    if not website:
        logging.error("No website entered for website scanner. Exiting.")
        sys.exit(1)
    command = ["ptt", "-q", "run", "website_scanner", website]
    output_file = os.path.join(OUTPUT_DIR, "webappAUDIT.txt")
    try:
        with open(output_file, "w") as outfile:
            subprocess.run(command, stdout=outfile, stderr=subprocess.STDOUT, check=True)
        logging.info(f"Website scan completed successfully. Results saved in {output_file}.")
    except subprocess.CalledProcessError as e:
        logging.error("An error occurred while running the website scanner command: " + str(e))

# ----- Combined Tasks (to be run concurrently) -----
def nmap_task(target):
    logging.info(f"Starting nmap scan on target: {target}")
    scan_output = run_nmap_scan(target)
    host_info, ports_table, vulners_block = parse_nmap_output(scan_output)
    formatted_output = format_output(host_info, ports_table, vulners_block)
    
    nmap_output_file = os.path.join(OUTPUT_DIR, "exploitCVE.txt")
    try:
        with open(nmap_output_file, "w", encoding="utf-8") as f:
            f.write(formatted_output)
        logging.info(f"Nmap scan results saved to {nmap_output_file}")
    except Exception as e:
        logging.error(f"Error writing to {nmap_output_file}: {e}")
        sys.exit(1)

    logging.info("Extracting vulnerability details from nmap scan output...")
    fetch_vulnerability_details(nmap_output_file)

def website_scanner_task(target):
    logging.info(f"Starting website scan on target: {target}")
    run_website_scanner(target)

# ----- Main Function -----
def main():
    parser = argparse.ArgumentParser(description="Combined Nmap and Website Scanner Script")
    parser.add_argument('target', help='The target to scan (used for both Nmap and website scanner)')
    args = parser.parse_args()
    target = args.target

    # Create threads for concurrent execution.
    nmap_thread = threading.Thread(target=nmap_task, args=(target,))
    website_thread = threading.Thread(target=website_scanner_task, args=(target,))

    # Start threads.
    nmap_thread.start()
    website_thread.start()

    # Wait for both threads to complete.
    nmap_thread.join()
    website_thread.join()

    logging.info("Both scans have completed.")

if __name__ == "__main__":
    main()
