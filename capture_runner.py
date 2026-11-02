import sys
import os
import runpy

if __name__ == "__main__":
    if getattr(sys, 'frozen', False):
        exe_dir = os.path.dirname(sys.executable)
    else:
        exe_dir = os.path.dirname(os.path.abspath(__file__))

    os.chdir(exe_dir)
    os.makedirs("dataset", exist_ok=True)   # capture writes dataset/live_flows.csv here
    sys.path.insert(0, exe_dir)

    # Actually executes capture_v2's `if __name__ == "__main__"` block
    runpy.run_module("packet_capture.capture_v2", run_name="__main__")