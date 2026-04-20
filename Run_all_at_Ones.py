import subprocess
import time 
def run_in_new_terminal(script_name):
    print(f"Starting {script_name} in new terminal...")
    subprocess.Popen([
        "cmd", "/c", "start", "cmd", "/k", f"python {script_name}"
    ])

# Start all scripts in parallel
run_in_new_terminal("loggeneration.py")
time.sleep(5)
run_in_new_terminal("phase2.py")
run_in_new_terminal("phase3.py")

print("All scripts started in separate terminals.")