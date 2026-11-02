import subprocess
import os
import sys
import time
import webbrowser
import ctypes

def main():
    if getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))

    capture_exe = os.path.join(base_dir, "capture_runner.exe")
    dashboard_exe = os.path.join(base_dir, "dashboard_runner.exe")

    print(f"Base dir: {base_dir}")

    print("Starting packet capture (approve the admin prompt)...")
    # Trigger UAC elevation directly via Windows ShellExecute, bypassing
    # PowerShell entirely -- avoids quoting issues with spaces in the path.
    ctypes.windll.shell32.ShellExecuteW(None, "runas", capture_exe, None, base_dir, 1)

    time.sleep(5)
    print("Starting dashboard...")
    subprocess.Popen([dashboard_exe], cwd=base_dir)

    time.sleep(8)
    webbrowser.open("http://localhost:8501")

    input("Press Enter to close this launcher window...")

if __name__ == "__main__":
    main()