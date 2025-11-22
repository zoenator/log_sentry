import sys
import re
import copy
import json
import socket
from pathlib import Path 
from collections import Counter
import argparse

# ---- Mapping, globals, structs ----

# Regex to identify and extract IPv4 addresses from log lines
IP_REGEX = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
TIME_REGEX = r'[A-Za-z]{3}\s+\d{1,2}\s+(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d'
NUM_REGEX = r'\d+'



# Load security keywords from an external config file                                                                                                               │ 
# This allows modifying search patterns without changing the code
try:
    with open('config.json', 'r', encoding='utf-8') as f:
        SECURITY_KEYWORDS = json.load(f)
except FileNotFoundError:
    print("Error: config.json not found. Please make sure its in the same directory as log_sentry.py")
    sys.exit(1)
except json.JSONDecodeError:
    print("Error: Could not decode config.json. Please check JSON for syntax errors.")
    sys.exit(1)

# ---- helper functions for ML implementation ----


# Check logfile for differences to baseline
def check_for_anomalies(log_file: Path):

    try:
        with open('baseline.json', 'r', encoding='utf-8') as f:
            baseline_profile = json.load(f)
    except FileNotFoundError:
            print("Error: baseline.json not found. Please make sure its in the same directory as log_sentry.py")
            sys.exit(1)
    except json.JSONDecodeError:
            print("Error: Could not decode baseline.json. Please check JSON for syntax errors.")
            sys.exit(1)

    log_profile = create_log_profile(log_file)

    for key, value in log_profile.items():
        if key not in baseline_profile:
            print(f"[Warning] Anomaly found: New Pattern in {log_file}: {key} (Count:{value})")
        else:
            baseline_occurence = baseline_profile[key]
            if baseline_occurence * 2 < value:    
                print(f"[Warning] Anomaly found: Frequency deviation in {log_file}: {key} (Count: {value}, Baseline occurence: {baseline_occurence})")



# write baseline into json
def baseline_to_json(baseline):
    
    try:
        with open('baseline.json', 'w') as file:
            json.dump(baseline, file, indent=4)
    except PermissionError:
        print("Error: baseline.json not found. Please make sure its in the same directory as log_sentry.py")
        sys.exit(1)
    

def create_log_profile(log_file: Path):
    masked_lines_list = []
    line_count = 0

    try:
        # open log file
        with log_file.open('r', encoding='utf-8') as f:
            for line in f:
                # Iterate through log file
                masked_line = mask_log_line(line)
                masked_lines_list.append(masked_line)
                line_count += 1
                
    except (IOError, PermissionError) as e:
    
        print(f"[ERROR] Couldn't read log file {log_file}")
        print(f"        Try with permissions: 'sudo chmod 644 {log_file}'")
        print(f"        Error: {e}")
        sys.exit(1)

    except Exception as e:
    
        print(f"[FATAL ERROR] Unexcpected crash while parsing of line {line_count}: {e}")
        sys.exit(1)

    findings = Counter(masked_lines_list)
    print(f"[*] Scan finished. {line_count} lines analyzed.")
    return findings

# mask whole log file
def generate_baseline(log_file: Path):
    
    findings = create_log_profile(log_file)
    baseline_to_json(findings)
    




# mask 1 line
def mask_log_line(line: str) -> str:
    # turns 1 line into masked line
    modified_line = re.sub(TIME_REGEX, "<TIMESTAMP>", line)
    modified_line = re.sub(IP_REGEX, "<IP>",modified_line)
    modified_line = re.sub(NUM_REGEX, "<NUM>", modified_line)
    
    return modified_line

# ---- Key-word helper functions ----

def get_hostname_from_ip(ip: str) -> str:
# Performs a reverse DNS lookup to find the hostname for an IP
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except(socket.herror, socket.gaierror):
        return "(no hostname found)"


def process_file_paths(path_strings: list[str]) -> list[Path]:                                                                                                                 
    # Validate strings and return path object                                                                                                
    print("[*] Validating input files...")                                                                                                                                     
    valid_paths = []                                                                                                                                                           
    if not path_strings:                                                                                                                                                       
        print("[Warning] No file paths provided.")                                                                                                                             
        return []                                                                                                                                                              
                                                                                                                                                                            
    for path_str in path_strings:                                                                                                                                              
        log_file = Path(path_str).expanduser()                                                                                                                                 
        if log_file.is_file():                                                                                                                                                 
            valid_paths.append(log_file)                                                                                                                                       
            print(f"[*] Found valid log file: {log_file}")                                                                                                                     
        else:                                                                                                                                                                  
            print(f"[Warning] '{log_file}' does not exist or is not a file. Skipping...")                                                                                      
                                                                                                                                                                            
    if not valid_paths:                                                                                                                                                        
        print("[Error] No valid log files found to analyze.")                                                                                                                  
                                                                                                                                                                            
    return valid_paths  

def parse_log_file(log_file: Path):
# Parses log file looking out for the keywords from config.json
# Collects IPs and counts occurences
    findings = {
        "failed_pw": [],
        "invalid_user": [],
        "session_opened": [],
        "ssh_disconnect": [],
        # ...
    }

    # tracks events w/o IP
    findings_counter = copy.deepcopy(findings)

    line_count = 0

    try:
        # open log file
        with log_file.open('r', encoding='utf-8') as f:
            for line in f:
                # Iterate through log file
                line_count += 1
                for key_name, regex_pattern in SECURITY_KEYWORDS.items():

                    if re.search(regex_pattern, line, re.IGNORECASE):
                        # If keyword is found, try to extract an IP address    
                        ip_match = re.search(IP_REGEX, line)
                        if ip_match:
                            ip = ip_match.group(0)
                            hostname = get_hostname_from_ip(ip)
                            # store ip and hostname
                            findings[key_name].append((ip, hostname))
                        else:
                            # if no ip is found just count
                            findings_counter[key_name].append(1)    # append 1 if no ip is found

    except (IOError, PermissionError) as e:
    
        print(f"[ERROR] Couldn't read log file {log_file}")
        print(f"        Try with permissions: 'sudo chmod 644 {log_file}'")
        print(f"        Error: {e}")
        sys.exit(1)

    except Exception as e:
    
        print(f"[FATAL ERROR] Unexcpected crash while parsing of line {line_count}: {e}")
        sys.exit(1)

    print(f"[*] Scan finished. {line_count} lines analyzed.")
    return findings, findings_counter

def print_report(findings, findings_counter):
    # formats and prints the final analysis report to the console
    print("\n--- Log-sentry Report ---")
    total_alerts = 0

    for key_name in findings:
        ips_found = findings[key_name]
        simple_counts = findings_counter[key_name]

        total_ips = len(ips_found)
        total_simple = len(simple_counts)
        # only print sections that have alerts
        if total_ips > 0 or total_simple > 0:

            print(f"\n[!] Alert-Type: '{key_name}' (Total: {total_ips + total_simple})")
            total_alerts += (total_ips + total_simple)

            if total_ips > 0:
                # use counter to group and count identical (IP, hostname) tuples
                ip_counts = Counter(ips_found)
                for (ip, hostname), count in ip_counts.items():
                    print(f"    -IP: {ip} Hostname: {hostname} (Count: {count})")

    if total_alerts == 0:
        
        print("\n[+] No suspicious keywords found.")
    
    print("--------------------------------")

# ---- Main function ----

def main():
    parser = argparse.ArgumentParser(
        description="Log-Sentry - A log analysis tool.",
        epilog="Example: python3 log_sentry.py --check-anomalies <path>"
    )

    mode_group =  parser.add_mutually_exclusive_group()

    # Option 1: create baseline
    mode_group.add_argument('--create-baseline', dest = 'baseline_file',
                            metavar='FILE', help='Create a new Baseline from the given log file.')
    # Option 2: Check anomalies
    mode_group.add_argument('--check-anomalies', dest = 'log_files', nargs='*',
                            metavar='FILE', help='Compare a log file to baseline.')
    # Option 3: Check keywords
    mode_group.add_argument('--check-keywords', dest = 'keyword_file', nargs='*',
                            metavar='FILE', help='Log file(s) to scan for keywords.')
    args = parser.parse_args()

    if args.baseline_file:
        log_file = Path(args.baseline_file)
        if log_file.is_file():
            print(f"[*] Mode: Create Baseline from {args.baseline_file}")
            generate_baseline(log_file)
            print("[*] Log-sentry-job complete.")
        else:
            print(f"[ERROR] File not found: {log_file}")
    elif args.log_files:
        log_files = process_file_paths(args.log_files)
        for log_file in log_files:
            print(f"[*] Mode: Check for anomalies in {log_file}")
            check_for_anomalies(log_file)
        print("[*] Log-sentry-job complete.")
    elif args.keyword_file:
        log_files = process_file_paths(args.keyword_file)
        for log_file in log_files:
            print(f"[*] Starting log-scan of {log_file.name}")
            findings, findings_counter =  parse_log_file(log_file)
            print_report(findings, findings_counter)

        print("[*] Log-sentry-job complete.")
    else:
        print("[*] No log file specified. Showing help.")
        parser.print_help()


if __name__ == "__main__":
    main()

