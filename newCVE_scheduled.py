import os
import requests
from bs4 import BeautifulSoup
from datetime import date, timedelta
from tabulate import tabulate
import textwrap

# Calculate today's and yesterday's dates in YYYY-MM-DD format
today = date.today()
yesterday = today - timedelta(days=1)
publishdatestart = yesterday.strftime("%Y-%m-%d")
publishdateend = today.strftime("%Y-%m-%d")

# Construct the URL using dynamic dates
url = (f"https://www.cvedetails.com/vulnerability-search.php?f=1"
       f"&publishdatestart={publishdatestart}&publishdateend={publishdateend}")
print("Fetching URL:", url)

# Set custom headers to mimic a real browser
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/58.0.3029.110 Safari/537.3'
}

# Send the GET request
response = requests.get(url, headers=headers)
if response.status_code != 200:
    print(f"Failed to retrieve page. Status code: {response.status_code}")
    exit()

# Parse HTML content using BeautifulSoup
soup = BeautifulSoup(response.text, 'html.parser')

# Find all CVE blocks (each with data-tsvfield="cveinfo")
cve_blocks = soup.find_all("div", class_="border-top py-3 px-2 hover-bg-light", attrs={"data-tsvfield": "cveinfo"})

# Prepare a list of rows; each row has the CVE ID and a combined Details cell
rows = []
for block in cve_blocks:
    # Extract CVE ID
    cve_id_tag = block.find("h3", attrs={"data-tsvfield": "cveId"})
    cve_id = cve_id_tag.get_text(strip=True) if cve_id_tag else "N/A"

    # Extract summary and wrap it to 80 characters
    summary_tag = block.find("div", class_="cvesummarylong")
    summary = summary_tag.get_text(strip=True) if summary_tag else "N/A"
    wrapped_summary = textwrap.fill(summary, width=80, break_long_words=False, break_on_hyphens=False)

    # Extract Max CVSS
    max_cvss_div = block.find("div", attrs={"data-tsvfield": "maxCvssBaseScore"})
    if max_cvss_div:
        cvss_box = max_cvss_div.find("div", class_="cvssbox")
        max_cvss = cvss_box.get_text(strip=True) if cvss_box else "N/A"
    else:
        max_cvss = "N/A"

    # Extract EPSS Score
    epss_div = block.find("div", attrs={"data-tsvfield": "epssScore"})
    if epss_div:
        epss_span = epss_div.find("span")
        epss_score = epss_span.get_text(strip=True) if epss_span else "N/A"
    else:
        epss_score = "N/A"

    # Combine the details into a single multi-line cell
    details = (
        f"Summary: {wrapped_summary}\n"
        f"Max CVSS: {max_cvss}\n"
        f"EPSS Score: {epss_score}"
    )
    rows.append([cve_id, details])

# Format the rows into a table using tabulate
table = tabulate(rows, headers=["CVE ID", "Details"], tablefmt="grid")

# Create the output directory if it doesn't exist
output_dir = "outputs"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)  # citePythonOSDocs

# Define the full path for the output file
output_file = os.path.join(output_dir, "newCVE_scheduled.txt")

# Save the table to the output file
with open(output_file, "w", encoding="utf-8") as f:
    f.write(table)

print("Final output saved to", output_file)
