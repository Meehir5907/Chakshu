import time
import subprocess
from pathlib import Path


BASE_DIR = Path(r"F:\CODING AND AI\Codings file VS code\forensics_lab")
RAW_LOG_DIR = BASE_DIR / "logs" 

LOG_FILES = {
    "network": RAW_LOG_DIR / "network.log",
    "os": RAW_LOG_DIR / "os.log",
    "app": RAW_LOG_DIR / "app.log"
}

def run_ps_cmd(cmd):
    """Executes a PowerShell command specifically formatted for Windows."""
    try:
        # We use -NoProfile to make it faster and -Command to execute
        process = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        return process.stdout if process.returncode == 0 else f"PS_ERROR: {process.stderr}"
    except Exception as e:
        return f"SCRIPT_ERROR: {str(e)}"

def generate_heavy_logs():
    print(f"[*] Starting Forensic Collector...")
    print(f"[*] Check logs here: {RAW_LOG_DIR}")
    
    RAW_LOG_DIR.mkdir(parents=True, exist_ok=True)

    while True:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")

        # 1. NETWORK: Native Windows Netstat
        net_data = run_ps_cmd("netstat -ano | Select-Object -First 30") 
        # change the value '30' to get more system logs in th json file 
        with open(LOG_FILES["network"], "a") as f:
            f.write(f"--- [{ts}] NETWORK DUMP ---\n{net_data}\n\n")

        # 2. OS: Services (Native PS)
        # Using -First 20 instead of 'head'
        os_data = run_ps_cmd("Get-Service | Select-Object Name, Status -First 20")
        with open(LOG_FILES["os"], "a") as f:
            f.write(f"--- [{ts}] OS SNAPSHOT ---\n{os_data}\n\n")

        # 3. APP: Verbose Processes
        # tasklist works better in standard CMD mode or simple PS call
        app_data = run_ps_cmd("tasklist /V")
        with open(LOG_FILES["app"], "a") as f:
            f.write(f"--- [{ts}] PROCESS DUMP ---\n{app_data}\n\n")

        print(f"[+] All logs captured: {ts}")
        
      
        time.sleep(15)

if __name__ == "__main__":
    generate_heavy_logs()