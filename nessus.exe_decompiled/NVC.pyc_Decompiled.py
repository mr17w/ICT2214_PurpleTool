import os
import requests
import argparse
import time
from argparse import RawTextHelpFormatter
from _nessus_core import NESSUS
import json
from convert_dict_to_excel import dict_to_excel
from convert_excel_to_words import excel_to_word
parser = argparse.ArgumentParser(description='Nessus Vulnerability Compiler', formatter_class=RawTextHelpFormatter, epilog='[Example]:\nNVC.exe -i report.nessus\nNVC.exe -p result\\vulnerabilities.xlsx')
parser.add_argument('-i', '--input', metavar='report.nessus', type=str, help='Input nessus file')
parser.add_argument('-p', '--process', metavar='vulnerabilities.xlsx', type=str, help='Input result\\vulnerabilities.xlsx file to process')
args = parser.parse_args()
nessus_filename = args.input
if nessus_filename == '':
    print('Input nessus report filename can not be empty')
    exit()

def main():
    if args.input:
        encodings = ['cp1252', 'utf-8', 'latin-1']
        nessus_xml_content = None
        for encoding in encodings:
            try:
                print(f'Trying to read the file with encoding: {encoding}')
                with open(nessus_filename, 'r', encoding=encoding) as f:
                    pass  # postinserted
            except UnicodeDecodeError as e:
                    nessus_xml_content = f.read()
                        print(f'Successfully read the file with encoding: {encoding}')
                    else:  # inserted
                        break
        if nessus_xml_content is None:
            print('FAILED: Unable to decode the file with the provided encodings.')
            raise UnicodeDecodeError('File encoding is not compatible with attempted encodings.')
        print('(*) Processing Nessus file ')
        nessus = NESSUS(nessus_xml_content)
        print('(*) Parsing Nessus file')
        vulns = nessus.parse_nessus_by_vuln()
        json_file_path = './result/dict_vulns.json'
        with open(json_file_path, 'w') as json_file:
            json.dump(vulns, json_file, indent=4)
        print('(*) Writing Parsed-Nessus to excel for analysing')
        dict_to_excel(vulns)
        print('(*) Excel vulnerabilities.xlsx created in results.')
        print('(*) IMPORTANT: Please select all the latest version for software in excel: \n1.Filter a-z in vul columns \n2.Delete duplicated software w older version patches')
    else:  # inserted
        if args.process:
            print('(*) Processing Excel file in result folder: ./result/vulnerabilties')
            print('(*) Creating Document')
            excel_to_word(args.process)
            note = '\n(*) IMPORTANT\n1. Look at Manual Analyse excel to identify any vulnerabilties that were removed from document.\n2. Check summary result to ensure that the number does not differ greatly. Same vulnerabilities will be group together hence the summary number will be lesser. \nFor example: two SSL Certificate Expired will be considered as 1:\n- SSL Certificate Expired \n- SSL Certificate Expired'
            print(note)
        print(f'Failed to read file with encoding {encoding}: {e}')
if __name__ == '__main__':
    main()