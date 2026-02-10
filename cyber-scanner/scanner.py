import os
import hashlib
import math
import yara

# Colors
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
RESET = "\033[0m"

def calculate_entropy(data):
    if not data: return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def scan_file(file_path, rules):
    """Internal function to scan a single file and return results."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        
        matches = rules.match(data=data)
        entropy = calculate_entropy(data)
        
        if matches or entropy > 7.5:
            print(f"{RED}[!] THREAT DETECTED: {file_path}{RESET}")
            if matches: print(f"    - YARA Matches: {matches}")
            if entropy > 7.5: print(f"    - High Entropy: {entropy:.2f}")
            return True
        return False
    except Exception:
        # Skip files we can't read (like system files)
        return False

def analyze_directory(dir_path):
    dir_path = dir_path.strip()
    if not os.path.isdir(dir_path):
        print(f"{RED}[!] Error: {dir_path} is not a valid directory.{RESET}")
        return

    try:
        rules = yara.compile(filepath='my_rules.yar')
    except Exception as e:
        print(f"{RED}[!] YARA Compile Error: {e}{RESET}")
        return

    print(f"\n{CYAN}--- STARTING BULK FOLDER SCAN ---{RESET}")
    threat_count = 0
    total_files = 0

    # os.walk goes through every subfolder automatically!
    for root, dirs, files in os.walk(dir_path):
        for name in files:
            total_files += 1
            full_path = os.path.join(root, name)
            if scan_file(full_path, rules):
                threat_count += 1

    print(f"\n{CYAN}--- SCAN SUMMARY ---{RESET}")
    print(f"Total Files Scanned: {total_files}")
    print(f"Total Threats Found: {RED}{threat_count}{RESET}")

if __name__ == "__main__":
    print(f"{CYAN}====================================")
    print("   ENTERPRISE SCANNER v1.6")
    print("   (Enter a File OR a Folder path)")
    print(f"===================================={RESET}")
    
    while True:
        path = input(f"\n{YELLOW}Path to Scan (or 'exit'): {RESET}").strip()
        if path.lower() == 'exit': break
        
        if os.path.isdir(path):
            analyze_directory(path)
        else:
            # Re-use our logic from v1.5 for single files if needed
            # For simplicity in this demo, we'll just treat a file as a single-scan
            from scanner import analyze_file # Ensure your file is named scanner.py
            analyze_file(path)