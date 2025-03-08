#!/usr/bin/env python3
import re
import sys
import os
import logging
import requests
import textwrap
import subprocess
from bs4 import BeautifulSoup
from tabulate import tabulate

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Ensure outputs directory exists.
OUTPUT_DIR = "outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Base URLs for fetching details
CVE_DETAILS_URL = "https://www.cvedetails.com/cve/"
SPLOITUS_URL = "https://sploitus.com/exploit?id="

# Regex patterns for different vulnerability IDs
PATTERN = re.compile(
    r'\b('
    r'CVE-\d{4}-\d{4,7}'                  # CVE IDs
    r'|[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}'  # GUID-style exploit IDs
    r'|PACKETSTORM:\d+'
    r'|1337DAY-ID-\d+'
    r'|SSV:\d+'
    r')\b'
)

def fetch_cve_details(cve_id: str) -> tuple:
    """
    Fetches CVE details from CVE Details.
    Returns a tuple: (Identifier, Type, URL, Description)
    """
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
    """
    Fetches exploit details from Sploitus.
    Returns a tuple: (Identifier, Type, URL, Description)
    """
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
    """Uses regex to find all vulnerability IDs in the provided text."""
    return set(match.group(0) for match in PATTERN.finditer(text))

def main(input_filename: str):
    # If the file is a .nessus file, run the two Wine commands.
    if input_filename.lower().endswith('.nessus'):
        logging.info(f"Detected .nessus file: {input_filename}. Running Wine commands.")
        try:
            subprocess.run(["wine", "./nessus.exe", "-i", input_filename], check=True)
            logging.info("Successfully ran: wine ./nessus.exe -i " + input_filename)
        except subprocess.CalledProcessError as e:
            logging.error(f"Error running wine command for input file: {e}")
            sys.exit(e.returncode)
        
        try:
            subprocess.run(["wine", "./nessus.exe", "-p", "result/vulnerabilities.xlsx"], check=True)
            logging.info("Successfully ran: wine ./nessus.exe -p result/vulnerabilities.xlsx")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error running wine command for processing vulnerabilities: {e}")
            sys.exit(e.returncode)

    # Process the input file as text
    try:
        with open(input_filename, "r", encoding="utf-8") as f:
            content = f.read()
        logging.info(f"Read file {input_filename} successfully.")
    except Exception as e:
        logging.error(f"Error reading file {input_filename}: {e}")
        sys.exit(1)
    
    vuln_ids = extract_ids_from_text(content)
    if not vuln_ids:
        logging.info("No vulnerability IDs found in the file.")
        sys.exit(0)
    
    logging.info(f"Found {len(vuln_ids)} unique vulnerability IDs.")
    
    results = []
    # For each vulnerability, fetch details and store the result tuple.
    for vuln_id in sorted(vuln_ids):
        if "CVE" in vuln_id.upper():
            result = fetch_cve_details(vuln_id.upper())
        else:
            result = fetch_exploit_details(vuln_id)
        results.append(result)
    
    # Sort results: CVEs first, then Exploits.
    results.sort(key=lambda x: (0 if x[1].upper() == "CVE" else 1, x[0].upper()))
    
    # Wrap the description text to a fixed width (e.g., 100 characters) without breaking words.
    wrapped_results = []
    for identifier, vtype, url, description in results:
        wrapped_description = textwrap.fill(
            description, 
            width=100, 
            break_long_words=False, 
            break_on_hyphens=False
        )
        wrapped_results.append((identifier, vtype, url, wrapped_description))
    
    # Create a table using tabulate with grid format.
    headers = ["Identifier", "Type", "URL", "Description"]
    table = tabulate(wrapped_results, headers=headers, tablefmt="grid")
    
    # Save the table into exploitCVE_details_imported.txt inside the outputs folder.
    output_file = os.path.join(OUTPUT_DIR, "exploitCVE_details_imported.txt")
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(table)
        logging.info(f"Final output saved to {output_file}")
    except Exception as e:
        logging.error(f"Error writing to {output_file}: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: {} <input_file>".format(sys.argv[0]))
    infile = sys.argv[1]
    main(infile)
