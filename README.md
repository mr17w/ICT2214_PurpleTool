PurpleTool Requirements:
- Linux / MacOS
- nmap
- wine (to run .exe)
- python modules:
    - tabulate
    - pentesttools
    - requests
    - beautifulsoup4
    - python3-crontab
    - flask

Usage:
- every file and directory is needed to run PurpleTool (except for the nessus.exe_decompiled directory)
- To run PurpleTool, run website.py and go to http://127.0.0.1:5000.

- Scan a Website Function:
    - takes a website/IP as an argument
    - takes argument and parses it to scan.py
        - outputs 'webappAUDIT.txt', 'exploitCVE.txt' & 'exploitCVE_details.txt' in the 'outputs' directory

- Import a Scan Function:
    - takes a file path of scan results as an argument
    - takes argument and parses it to details_imported.py
        - outputs 'exploitCVE_details_imported.txt' in the 'outputs' directory
    - if scan results are .nessus, parse them to nessus.exe (requires _template_nessus.docx & result/dict_vulns.json)
        - outputs .docx & .xlsx version of .nessus in 'result' directory 
    - Compare button will run compare.py
        - outputs 'compare.txt' in 'outputs' directory

- Schedule Scan Function:
    - takes a website/IP and time (in HH:MM) as arguments
    - takes arguments and parse them to schedule.py
        - schedule.py will create cronjob to run scan_sheduled.py
            - outputs 'webappAUDIT_scheduled.txt', 'exploitCVE_scheduled.txt' & 'exploitCVE_details_scheduled.txt' in the 'outputs' directory

- Get Latest CVEs Funcion:
    - takes time (in HH:MM) as an argument
    - takes argument and parses it to scheduleCVE.py
        - scheduleCVE.py will create cronjob to run newCVE_scheduled.py
            - outputs 'newCVE_scheduled.txt' in 'outputs' directory
    - Instant CVEs button will run newCVE.py
        - outputs 'newCVE.txt' in 'outputs' directory
