import re
import sys
from collections import defaultdict

# Define a regex pattern for failed login attempts (Example for SSH logs)
FAILED_LOGIN_PATTERN = r"Failed password for (invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)"

def analyze_log(file_path):
    failed_attempts = defaultdict(int)
    
    try:
        with open(file_path, "r") as file:
            for line in file:
                match = re.search(FAILED_LOGIN_PATTERN, line)
                if match:
                    ip_address = match.group(3)
                    failed_attempts[ip_address] += 1

        print("\n=== Potential Brute Force Attack Sources ===")
        for ip, count in failed_attempts.items():
            if count > 5:  # Adjust threshold as needed
                print(f"Suspicious IP: {ip} | Failed Attempts: {count}")
    except FileNotFoundError:
        print(f"Error: Log file '{file_path}' not found.")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python log_analysis.py <log_file_path>")
    else:
        analyze_log(sys.argv[1])
