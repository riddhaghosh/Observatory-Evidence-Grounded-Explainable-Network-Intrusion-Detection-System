# 🛡️ Observatory: Evidence-Grounded Explainable Network Intrusion Detection

Observatory captures live traffic on your Windows PC, detects **port scans, brute-force attempts and DoS floods**, and explains every alert in plain English using **MITRE ATT&CK**. It combines:

- **ML detection:** Random Forest, XGBoost and SVM models trained on CICIDS2017 (pre-trained models included).
- **Rule-based aggregate detectors:** port scan, brute force, DoS flood.
- **RAG + LLM explanations:** the LLM may cite only MITRE technique IDs that appear in the retrieved documents.
- **A Streamlit dashboard** with live threat level, charts, alert tables and AI explanations (times in IST).

> **Why it is different:** the ML models score about 99% F1 on CICIDS2017 but detected at most 5.2% of attacks launched live from a separate Kali VM. The rule detectors close that gap, and every explanation is tied to retrievable evidence.

---

## Quick start (recommended)

**1. Install the prerequisites**

| Requirement | Notes |
|---|---|
| Windows 10 / 11 | Live capture is built for Windows |
| [Python 3.11](https://www.python.org/downloads/) | Tick **"Add python.exe to PATH"** during install. Use 3.11 specifically (not 3.12+) |
| [Npcap](https://npcap.com/) | Tick **"Install Npcap in WinPcap API-compatible Mode"** |
| Free [Groq API key](https://console.groq.com/keys) | Used for the AI explanations (takes about 2 minutes to create) |
| Internet on first run | The embedding model downloads once |

**2. Download the project**

Either click **Code → Download ZIP** on GitHub and extract it, or:

```powershell
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
```

Extract it to a short folder path such as `C:\Observatory` or your Desktop.

**3. Double-click `setup.bat`** (one time). It creates a virtual environment, installs the packages and asks for your Groq API key.

**4. Double-click `run.bat`** and approve the Administrator prompt. It starts packet capture and opens the dashboard at <http://localhost:8501>. Open the **Live Monitor** tab.

That's it. Browse the web or run a scan against the PC, then click **🔄 Refresh live feed**.

---

## Run in VS Code (or any terminal)

**1. Open the project.** Install [VS Code](https://code.visualstudio.com/) and its **Python** extension, then choose **File → Open Folder** and select the project folder.

**2. Create the environment** (one time). Open **Terminal → New Terminal** and run:

```powershell
py -3.11 -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If PowerShell blocks the script, run `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` once, then repeat the activate line.

**3. Select the interpreter.** Press `Ctrl+Shift+P`, choose **Python: Select Interpreter**, and pick the one inside `.\venv`.

**4. Add your API key.** Copy `.env.example` to a new file named `.env` and edit it:

```
GROQ_API_KEY=your_key_here
```

Never share or commit `.env`.

**5. Build the knowledge base** (one time):

```powershell
python rag\build_knowledge_base.py
```

**6. Start packet capture as Administrator.** Capture needs admin rights. Either start VS Code with *Run as administrator*, or open a separate **PowerShell as Administrator**:

```powershell
cd <project-folder>
.\venv\Scripts\python.exe packet_capture\capture_v2.py
```

It lists the interfaces it listens on. Leave it running.

**7. Start the dashboard** in a normal VS Code terminal:

```powershell
streamlit run dashboard\app.py
```

If `streamlit` is not recognised, use `.\venv\Scripts\python.exe -m streamlit run dashboard\app.py`. The dashboard opens at <http://localhost:8501>.

> **Moved or renamed the folder?** A virtual environment can't be moved. Delete `venv` and repeat step 2.

---

## Try it: attack your own PC (optional)

Use a Kali Linux VM on the same network. Find your PC's IP with `ipconfig` and make sure `ping <windows-ip>` works. **Only test machines you own.**

```bash
# Port scan
nmap -sS -p 1-1000 <windows-ip>

# SYN flood
sudo hping3 -S --flood -p 80 <windows-ip>
```

For brute force, send many concurrent connection attempts to one login port (for example 22). Wait a few seconds, press **Refresh live feed**, open the matching tab and click **Generate AI Explanation**.

| Attack | Detector rule | Expected explanation |
|---|---|---|
| Port scan | 15+ distinct ports from one source in 10 s | T1046 |
| Brute force | 15+ attempts to one login port in 10 s | T1110 |
| DoS flood | 200+ flow records from one source in 10 s | T1498 / T1498.001 |

---

## What works out of the box

- **Live Monitor tab:** real-time capture, ML detection, the three rule detectors and AI explanations.
- **Pre-trained models** are included, so no training is needed.

## What is not included

- **The CICIDS2017 dataset** (too large). The **Historical Analysis** tab shows a notice instead of crashing. It is only needed for that tab and for retraining. To use it, download the *MachineLearningCSV* files from the [CIC website](https://www.unb.ca/cic/datasets/ids-2017.html) into `dataset/`, then run:

```powershell
python preprocessing\clean_dataset.py
python models\random_forest.py
python models\xgboost_model.py
python models\svm.py
```

- **The packaged `.exe`** (`dist/`). It is built locally and is not stored in the repository.
- **Your `.env` file**. Each user adds their own key.

---

## Project structure

```
preprocessing/   clean_dataset.py          merge and clean CICIDS2017
models/          training scripts, saved/  Random Forest, XGBoost, SVM (+ pre-trained files)
packet_capture/  capture_v2.py             live capture -> dataset/live_flows.csv
detection/       scan / bruteforce / dos   aggregate rule detectors
rag/             documents, retrieve.py    MITRE ATT&CK knowledge base
llm/             explain.py                grounded LLM explanation
dashboard/       app.py                    Streamlit dashboard (Observatory)
setup.bat        one-time installer
run.bat          starts capture + dashboard
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| No live flows appear | Capture is not running as Administrator, or Npcap is not installed |
| Dashboard says `live_flows.csv not found` | Start `capture_v2.py` first and wait for some traffic |
| Dashboard looks empty after an attack | Wait a few seconds, then press **Refresh live feed** |
| `Fatal error in launcher` for `streamlit.exe` | The venv was moved or renamed. Delete `venv` and recreate it, or run `.\venv\Scripts\python.exe -m streamlit run dashboard\app.py` |
| `401 Invalid API Key` | Wrong or expired key in `.env`. Create a new one at Groq and restart the dashboard |
| Explanation is empty or fails | Check your internet connection and `.env`. Restart the dashboard after editing `.env` |
| `Port 8501 is already in use` | Close the old dashboard window or use `--server.port 8502` |
| Chroma folder cannot be deleted | Stop the dashboard first, then delete `rag/chroma_db` and rebuild |
| First run is slow | The embedding model is downloading once |
| `ModuleNotFoundError` | The venv is not active. Activate it, or reinstall with `pip install -r requirements.txt` |

---

## Known limitations

- Live evaluation covers three attack types on one network.
- Rule thresholds were tuned on the same test scenarios, so rule results are optimistic.
- Slow or distributed attacks can stay under the 10-second window thresholds.
- The knowledge base covers T1046, T1110 and T1498 only.
- Capture only sees traffic that reaches the PC's own network interfaces, not other devices on the network.
- Windows only for live capture.

## Responsible use

For learning, and for networks you own or have written permission to test. Do not run scans or floods against anyone else's systems.

## Author

Name : Riddha Ghosh Dastidar, Institution : KIIT, Contact: riddha2019@gmail.com