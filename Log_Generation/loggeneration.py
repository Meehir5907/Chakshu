import time
import subprocess
import platform
from pathlib import Path

# Dynamically set the base directory to where the script is currently located
BASE_DIR = Path(__file__).resolve().parent
RAW_LOG_DIR = BASE_DIR / "logs" 

LOG_FILES = {
    "network": RAW_LOG_DIR / "network.log",
    "os": RAW_LOG_DIR / "os.log",
    "app": RAW_LOG_DIR / "app.log"
}

OS_TYPE = platform.system()

def run_cmd(cmd, is_powershell=False):
    """Executes commands natively based on the OS environment."""
    try:
        if OS_TYPE == "Windows" and is_powershell:
            process = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True, text=True, encoding='utf-8', errors='ignore'
            )
        else:
            # Native execution for Linux (bash/sh) or Windows CMD
            process = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore'
            )
        return process.stdout if process.returncode == 0 else f"ERROR: {process.stderr}"
    except Exception as e:
        return f"SCRIPT_ERROR: {str(e)}"

def get_network_logs():
    if OS_TYPE == "Windows":
        return run_cmd("netstat -ano | Select-Object -First 30", is_powershell=True)
    else:
        # Arch/Linux equivalent using modern socket stats
        return run_cmd("ss -tupan | head -n 30")

def get_os_logs():
    if OS_TYPE == "Windows":
        return run_cmd("Get-Service | Select-Object Name, Status -First 20", is_powershell=True)
    else:
        # Arch/Linux equivalent for service statuses
        return run_cmd("systemctl list-units --type=service --all --no-pager | head -n 20")

def get_app_logs():
    if OS_TYPE == "Windows":
        return run_cmd("tasklist /V")
    else:
        # Arch/Linux equivalent for verbose process list (sorted by memory)
        return run_cmd("ps aux --sort=-%mem | head -n 30")

def generate_heavy_logs():
    print(f"[*] Starting Cross-Platform Forensic Collector...")
    print(f"[*] Detected Host OS: {OS_TYPE}")
    print(f"[*] Saving logs to: {RAW_LOG_DIR}")
    
    RAW_LOG_DIR.mkdir(parents=True, exist_ok=True)

    while True:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")

        # 1. NETWORK
        with open(LOG_FILES["network"], "a") as f:
            f.write(f"--- [{ts}] NETWORK DUMP ---\n{get_network_logs()}\n\n")

        # 2. OS
        with open(LOG_FILES["os"], "a") as f:
            f.write(f"--- [{ts}] OS SNAPSHOT ---\n{get_os_logs()}\n\n")

        # 3. APP
        with open(LOG_FILES["app"], "a") as f:
            f.write(f"--- [{ts}] PROCESS DUMP ---\n{get_app_logs()}\n\n")

        print(f"[+] All logs captured: {ts}")
        time.sleep(15)

if __name__ == "__main__":
    generate_heavy_logs()
