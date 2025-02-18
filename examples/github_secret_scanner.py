import os
import re
import subprocess
import sys
import shutil

# Define regex patterns for common secrets
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9\/+=]{40})['\"]?",
    "Generic API Key": r"(?i)(api[_-]?key\s*=\s*['\"]?[A-Za-z0-9]{16,40}['\"]?)",
    "JWT Token": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.([a-zA-Z0-9_-]+)",
    "Private Key": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"
}

def scan_repo(repo_url, repo_name="temp_repo"):
    try:
        # Clone the repository
        print(f"Cloning repository: {repo_url}")
        subprocess.run(["git", "clone", repo_url, repo_name], check=True)

        # Walk through the repository files
        for root, _, files in os.walk(repo_name):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        for secret_name, pattern in SECRET_PATTERNS.items():
                            if re.search(pattern, content):
                                print(f"[!] Possible {secret_name} found in: {file_path}")
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")

    except subprocess.CalledProcessError as e:
        print(f"Error cloning repository: {e}")

    finally:
        # Clean up the repository
        print("Cleaning up cloned repo...")
        shutil.rmtree(repo_name, ignore_errors=True)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python github_secret_scanner.py <github_repo_url>")
    else:
        scan_repo(sys.argv[1])
