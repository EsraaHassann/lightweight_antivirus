import hashlib
import os
import shutil
from config import MALWARE_HASHES, QUARANTINE_DIR

def compute_file_hash(file_path):
    """Compute the hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read the file in chunks to prevent large files from using too much memory
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_file_signature(file_path):
    """Check if the file's hash matches any known malware hashes."""
    file_hash = compute_file_hash(file_path)
    if file_hash in MALWARE_HASHES:
        return True
    return False

def quarantine_file(file_path):
    """Move a suspicious file to quarantine."""
    if not os.path.exists(QUARANTINE_DIR):
        os.makedirs(QUARANTINE_DIR)
    filename = os.path.basename(file_path)
    shutil.move(file_path, os.path.join(QUARANTINE_DIR, filename))
    print(f"File {filename} has been quarantined.")

def remove_file(file_path):
    """Delete a suspicious file."""
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"File {file_path} has been deleted.")

def scan_directory(directory):
    """Scan all files in the given directory for malware."""
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"Scanning: {file_path}")
            if check_file_signature(file_path):
                print(f"Malware detected in {file_path}")
                quarantine_file(file_path)
            else:
                print(f"No malware found in {file_path}")

def check_file_heuristics(file_path):
    """Check the file for heuristic patterns (keywords)."""
    suspicious_keywords = ["suspicious", "malicious", "dangerous"]
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()
            for keyword in suspicious_keywords:
                if keyword in content:
                    return True
    except:
        # Skip non-text files
        pass
    return False

def scan_for_heuristics(directory):
    """Scan files for heuristic patterns."""
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"Scanning (heuristic): {file_path}")
            if check_file_heuristics(file_path):
                print(f"Suspicious content found in {file_path}")
                quarantine_file(file_path)
