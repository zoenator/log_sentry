import sys
from pathlib import Path 
import re

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

# ---- Main function ----

def main():

    log_file = get_log_file()

    print(f"[*] Starting log-scan of {log_file}")
    # main logic
    print("[*] Log-sentry-job complete.")



if __name__ == "__main__":
    main()

