import os
import re
from tabulate import tabulate

def extract_cve_descriptions(file_path):
    """
    Reads a table-formatted file and returns a dictionary mapping CVE identifiers 
    (from the Identifier column) to their combined Description (from the Description column).
    
    The function processes only rows that start with a new entry (non-empty identifier cell) 
    and appends subsequent lines (where the identifier cell is empty) to the Description.
    """
    cve_dict = {}
    current_cve = None
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return cve_dict

    for line in lines:
        line = line.rstrip("\n")
        # Skip lines that are table borders (starting with '+' or not starting with '|')
        if not line.startswith('|') or line.startswith('+'):
            continue

        # Split by '|' (the first and last items will be empty)
        fields = line.split('|')
        if len(fields) < 5:
            continue

        # The identifier is in fields[1] and description in fields[4]
        identifier = fields[1].strip()
        description_part = fields[4].strip()
        
        # Skip the header row
        if identifier.lower() == "identifier":
            continue

        if identifier:
            # New row starts; if current_cve exists, store it before starting a new one
            if current_cve is not None:
                # Only store if identifier starts with "CVE-"
                if current_cve["identifier"].startswith("CVE-"):
                    # Remove extra spaces in description
                    cve_dict[current_cve["identifier"]] = " ".join(current_cve["description"].split())
            # Start a new record
            current_cve = {"identifier": identifier, "description": description_part}
        else:
            # This is a continuation line; append the description part if we have a current entry.
            if current_cve is not None:
                current_cve["description"] += " " + description_part

    # Save the last record
    if current_cve is not None and current_cve["identifier"].startswith("CVE-"):
        cve_dict[current_cve["identifier"]] = " ".join(current_cve["description"].split())

    return cve_dict

def main():
    file1 = "outputs/exploitCVE_details.txt"
    file2 = "outputs/exploitCVE_details_imported.txt"
    output_file = "outputs/compare.txt"
    
    # Check if files exist
    missing_files = [f for f in (file1, file2) if not os.path.exists(f)]
    if missing_files:
        print("Make sure to run and import a scan of target website, the following file(s) do not exist:")
        for f in missing_files:
            print(f)
        return

    # Extract dictionaries mapping CVE -> Description from each file.
    cve_desc_file1 = extract_cve_descriptions(file1)
    cve_desc_file2 = extract_cve_descriptions(file2)
    
    # Compute union of all CVE identifiers
    all_cves = set(cve_desc_file1.keys()).union(set(cve_desc_file2.keys()))
    
    # Prepare table data.
    # Overlap is "YES" if CVE appears in both files; otherwise "NO".
    # For description, use file1's description if available, else file2's.
    table_data = []
    for cve in all_cves:
        overlap = "YES" if (cve in cve_desc_file1 and cve in cve_desc_file2) else "NO"
        description = cve_desc_file1.get(cve, cve_desc_file2.get(cve, ""))
        table_data.append([cve, overlap, description])
    
    # Sort rows so that those with "YES" overlap appear first, then by CVE identifier.
    table_data.sort(key=lambda x: (0 if x[1]=="YES" else 1, x[0]))
    
    # Format the table using tabulate with a grid style.
    table_output = tabulate(table_data, headers=["CVE", "Overlap", "Description"], tablefmt="grid")
    
    # Write the formatted table to the output file.
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(table_output)
        print("Comparison table written to", output_file)
    except Exception as e:
        print(f"Error writing to {output_file}: {e}")

if __name__ == "__main__":
    main()
