import sys
import os

if __name__ == "__main__":
    if getattr(sys, 'frozen', False):
        exe_dir = os.path.dirname(sys.executable)   # where the exe, .env and dataset/ live
        bundle_dir = sys._MEIPASS                   # where --add-data files land (_internal)
    else:
        exe_dir = os.path.dirname(os.path.abspath(__file__))
        bundle_dir = exe_dir

    # Run from the exe folder so "dataset/live_flows.csv" resolves next to the exe
    os.chdir(exe_dir)
    os.makedirs("dataset", exist_ok=True)
    sys.path.insert(0, bundle_dir)
    sys.path.insert(0, exe_dir)

    # Load the API key from the .env sitting next to the exe
    from dotenv import load_dotenv
    load_dotenv(os.path.join(exe_dir, ".env"), override=True)

    from streamlit.web import cli as stcli
    app_path = os.path.join(bundle_dir, "dashboard", "app.py")
    sys.argv = [
        "streamlit", "run", app_path,
        "--server.headless=true",
        "--server.port=8501",
        "--global.developmentMode=false",   # required when Streamlit runs from a frozen exe
    ]
    sys.exit(stcli.main())