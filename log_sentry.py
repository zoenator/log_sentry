import sys
import re
import copy
from pathlib import Path 
from collections import Counter

# ---- Mapping, globals, structs ----

# regular expression for ip structure
IP_REGEX = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'

#keywords to scan the log for
SECURITY_KEYWORDS = {
    "failed_pw": r'failed password for',
    "invalid_user": r'invalid user',
    "session_opened": r'session opened for user',
    "ssh_disconnect": r'received disconnect from',
    #.... expandable if necessary
}

# ---- helper functions ----

def get_log_file() -> Path:

    print("[*] Validating input file...")

    try: 
        log_file_path = sys.argv[1]
    except IndexError:
        print("Error: Please specify a log file.")
        print(f"Usage: python3 {sys.argv[0]} <filepath>")
        sys.exit(1)

    log_file = Path(log_file_path).expanduser()         # expanduser to decipher '~' 

    if not log_file.is_file():
        print(f"{log_file} does not exist or is not a file")
        sys.exit(1)
    
    print(f"[*] Input validated.")
    return log_file

def parse_log_file(log_file: Path):

    findings = {
        "failed_pw": [],
        "invalid_user": [],
        "session_opened": [],
        "ssh_disconnect": [],
        # ...
    }

    findings_counter = copy.deepcopy(findings)

    line_count = 0

    try:
    
        with log_file.open('r', encoding='utf-8') as f:
            for line in f:
                
                line_count += 1
                for key_name, regex_pattern in SECURITY_KEYWORDS.items():

                    if re.search(regex_pattern, line, re.IGNORECASE):
                        
                        ip_match = re.search(IP_REGEX, line)
                        if ip_match:
                            
                            ip = ip_match.group(0)
                            findings[key_name].append(ip)
                        else:

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
    
    print("\n--- Log-sentry Report ---")
    total_alerts = 0

    for key_name in findings:
        ips_found = findings[key_name]
        simple_counts = findings_counter[key_name]

        total_ips = len(ips_found)
        total_simple = len(simple_counts)

        if total_ips > 0 or total_simple > 0:

            print(f"\n[!] Alert-Type: '{key_name}' (Total: {total_ips + total_simple})")
            total_alerts += (total_ips + total_simple)

            if total_ips > 0:

                ip_counts = Counter(ips_found)
                for ip, count in ip_counts.items():
                    print(f"    -IP: {ip} (Count: {count})")

    if total_alerts == 0:
        
        print("\n[+] No suspicious keywords found.")
    
    print("--------------------------------")

# ---- Main function ----

def main():

    log_file = get_log_file()

    print(f"[*] Starting log-scan of {log_file.name}")
    
    findings, findings_counter =  parse_log_file(log_file)
    print_report(findings, findings_counter)

    print("[*] Log-sentry-job complete.")



if __name__ == "__main__":
    main()

