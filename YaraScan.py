import yara
import os
import argparse
import psutil
import subprocess
import requests
import ctypes
import time
import sys

yara_folder = "yara64"


def is_admin():
    return ctypes.windll.shell32.IsUserAnAdmin()


def download_yara():
    yara_download_url = "https://github.com/VirusTotal/yara/releases/download/v4.0.5/yara-v4.0.5-1554-win64.zip"
    if not os.path.exists(yara_folder):
        print("Downloading YARA...")
        response = requests.get(yara_download_url)
        with open("yara64.zip", "wb") as f:
            f.write(response.content)
        print("Extracting YARA...")
        subprocess.run(["powershell", "-Command", "Expand-Archive yara64.zip -Force"])
        os.remove("yara64.zip")


def scan_processes(yara_rule_file):
    if not os.path.exists(yara_rule_file):
        print("The YARA rule file could not be found.")
        return

    print("Scanning Processes...")
    matches_found = False

    current_pid = os.getpid()

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pid = proc.info['pid']
            if pid == current_pid:
                continue
            
            result = subprocess.run([f"{yara_folder}/yara64.exe", yara_rule_file, str(pid), '-D', '-p', '10'], capture_output=True, text=True)
            if result.stdout:
                matches_found = True
                print(f"Match found in process {proc.info['name']} (PID: {pid}): {result.stdout.strip()}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not matches_found:
        print("No processes were found matching the provided YARA rule.")


def scan_process_memory(yara_rule_file, pid):
    if not os.path.exists(yara_rule_file):
        print("The YARA rule file could not be found.")
        return

    try:
        proc = psutil.Process(pid)
        print(f"Scanning process {proc.name()} (PID: {pid})")

        
        result = subprocess.run([f"{yara_folder}/yara64.exe", yara_rule_file, str(pid), '-D', '-p', '10'], capture_output=True, text=True)
        
        if result.stdout:
            print(f"Match found in process {proc.name()} (PID: {pid}): {result.stdout.strip()}")
        else:
            print(f"No matches found in process {proc.name()} (PID: {pid})")
    
    except psutil.NoSuchProcess:
        print(f"Process with PID {pid} does not exist.")
    except psutil.AccessDenied:
        print(f"Access denied to process with PID {pid}.")


def scan_directory(rules, directory):
    print(f"Scanning directory: {directory} \n")
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                    matches = rules.match(data=data)
                    if matches:
                        print(f"Match found in file {file_path}: {matches}")
            except Exception as e:
                print(f"Could not read file {file_path}: {e}")


def compile_yara_rules(yara_rule_file):
    try:
        return yara.compile(filepath=yara_rule_file)
    except Exception as e:
        print(f"Error compiling YARA rules: {e}")
        return None


def main():
    if not is_admin():
        print("This script must be executed as Administrator.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="YARA Scanning Tool")
    parser.add_argument("-d", "--directory", help="Directory to scan with YARA rules")
    parser.add_argument("-m", "--memory", action="store_true", help="Scan all processes and DLLs in memory")
    parser.add_argument("-PM", "--process-memory", type=int, help="Scan specific process memory by PID")
    parser.add_argument("-r", "--rules", required=True, help="Path to YARA rule file")
    
    args = parser.parse_args()

    yara_rule_file = args.rules
    download_yara()

    
    rules = compile_yara_rules(yara_rule_file)
    if not rules:
        return

    if args.directory:
        scan_directory(rules, args.directory)
    elif args.memory:
        scan_processes(yara_rule_file)  
    elif args.process_memory:
        scan_process_memory(yara_rule_file, args.process_memory)  
    else:
        print("Please provide a valid scanning option (-d, -m, or -PM)")

if __name__ == "__main__":
    main()
