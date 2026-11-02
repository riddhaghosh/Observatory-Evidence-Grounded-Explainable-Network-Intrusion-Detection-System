# AI Network Intrusion Detection System (AI-NIDS)

An AI-powered network security dashboard combining ML-based detection,
rule-based aggregate detectors (port scan, brute-force, DoS), and
RAG+LLM-generated explanations grounded in MITRE ATT&CK.

## Quick Start

1. **Install Python 3.11** from https://python.org (check "Add to PATH")
2. **Install Npcap** from https://npcap.com (required for packet capture)
3. **Double-click `setup.bat`** — installs everything, asks for a free Groq API key
   (get one at https://console.groq.com/keys, takes 2 minutes)
4. **Double-click `run.bat`** — starts capture (approve the Administrator prompt)
   and opens the dashboard in your browser

## What works out of the box
- **Live Monitor tab**: real-time traffic capture, ML detection, port-scan/
  brute-force/DoS rule-based detection, AI-generated MITRE-grounded explanations
- Pre-trained models included — no training required

## What's not included
- The full CICIDS2017 dataset (too large to distribute) — the Historical
  Analysis tab will show a notice instead of crashing

## Requirements
- Windows 10/11
- Administrator privileges (for packet capture only)
- A free Groq API key (for AI explanations)
# AI-NIDS-RAG: Network Intrusion Detection with AI-Explained Alerts

A network intrusion detection system that captures live traffic on your Windows PC, detects port scans, brute-force attempts and DoS floods, and explains every alert in plain English using MITRE ATT&CK.

**What it does**

1. Captures live packets (Scapy + Npcap) and turns them into flow records.
2. Detects attacks with three rule detectors (port scan, brute force, DoS flood) and ML models (Random Forest, XGBoost, SVM) trained on CICIDS2017.
3. Explains each alert with a RAG + LLM pipeline that may cite only MITRE ATT&CK technique IDs found in the retrieved documents.
4. Shows everything on a Streamlit dashboard (times in IST).

> **Why it is different:** the ML models score about 99% F1 on CICIDS2017 but detected at most 5.2% of attacks launched live from a separate Kali VM. The rule detectors close that gap, and the alert explanations are tied to retrievable evidence.

---

## 1. Requirements

| Requirement | Notes |
|---|---|
| Windows 10/11 | Live capture is built for Windows |
| Python **3.11** | Not 3.12+ (package compatibility). Check with `py -3.11 --version` |
| [Npcap](https://npcap.com/) | During install, tick **"Install Npcap in WinPcap API-compatible Mode"** |
| Administrator rights | Needed for packet capture |
| Internet (first run) | Downloads the embedding model once |
| Free [Groq](https://console.groq.com) API key | For the AI explanations |

Optional, only for testing attacks: a Kali Linux VM on the same network.

## 2. Install (one time)

Open PowerShell and run:

```powershell
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
py -3.11 -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Or simply double-click **`setup.bat`**, which does the same.

If PowerShell blocks the activate script, run this once:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## 3. Add your API key

1. Copy `.env.example` to a new file named `.env`.
2. Edit it so it contains:

```
GROQ_API_KEY=your_key_here
```

Never share or upload `.env`.

## 4. Build the knowledge base (one time)

```powershell
python rag\build_knowledge_base.py
```

This indexes the MITRE ATT&CK documents in `rag/documents/mitre_attack/`. If you edit those documents later, delete `rag/chroma_db` and run it again (stop Streamlit first).

## 5. Run

You need **two windows**.

**Window 1: PowerShell as Administrator** (right-click, Run as administrator):

```powershell
cd <repo-name>
.\venv\Scripts\Activate.ps1
python packet_capture\capture_v2.py
```

It prints the interfaces it is listening on. Leave it running.

**Window 2: normal PowerShell:**

```powershell
cd <repo-name>
.\venv\Scripts\Activate.ps1
streamlit run dashboard\app.py
```

The dashboard opens at <http://localhost:8501>. Open the **Live Monitor** tab.

Shortcut: **`run.bat`** starts both (run it as Administrator).

## 6. Try it (optional)

From a Kali VM, attack the Windows PC. Find the PC's IP with `ipconfig`, and check `ping <windows-ip>` works first. Only test machines you own.

```bash
# Port scan
nmap -sS -p 1-1000 <windows-ip>

# SYN flood
sudo hping3 -S --flood -p 80 <windows-ip>
```

For brute force, send many concurrent connection attempts to one login port (for example 22) on the PC. Wait a few seconds, refresh the dashboard, and click **Explain** on an alert.

| Attack | Detector rule | Expected explanation |
|---|---|---|
| Port scan | 15+ distinct ports from one source in 10 s | T1046 |
| Brute force | 15+ attempts to one login port in 10 s | T1110 |
| DoS flood | 200+ flow records from one source in 10 s | T1498 / T1498.001 |

## 7. Models and data

- Trained models are in `models/saved/`. If they are not in the repository (large files), download them from the link provided by the author and place them in that folder.
- The CICIDS2017 dataset is **not** included. It is only needed for the **Historical** tab and for retraining. Download the MachineLearningCSV files from the [CIC website](https://www.unb.ca/cic/datasets/ids-2017.html) into `dataset/`, then:

```powershell
python preprocessing\clean_dataset.py
python models\random_forest.py
python models\xgboost_model.py
python models\svm.py
```

## 8. Project structure

```
preprocessing/   clean_dataset.py          merge and clean CICIDS2017
models/          training scripts, saved/  Random Forest, XGBoost, SVM, ensemble
packet_capture/  capture_v2.py             live capture -> dataset/live_flows.csv
detection/       scan / bruteforce / dos   aggregate rule detectors
rag/             documents, retrieve.py    MITRE ATT&CK knowledge base
llm/             explain.py                grounded LLM explanation
dashboard/       app.py                    Streamlit dashboard
```

## 9. Troubleshooting

| Problem | Fix |
|---|---|
| No live flows appear | Capture is not running as Administrator, or Npcap is not installed |
| Dashboard shows nothing | Wait a few seconds after starting an attack, then refresh |
| `401 Invalid API Key` | Wrong or expired key in `.env`. Create a new one at Groq |
| Explanation is empty or fails | Check internet and `.env`. Restart Streamlit after editing `.env` |
| `Port 8501 is already in use` | Close the old Streamlit window or use `--server.port 8502` |
| Chroma folder cannot be deleted | Stop Streamlit first, then delete `rag/chroma_db` |
| First run is slow | The embedding model is downloading once |

## 10. Known limitations

- Live evaluation covers three attack types on one network.
- Rule thresholds were tuned on the same test scenarios, so rule results are optimistic.
- Slow or distributed attacks can stay under the 10-second window thresholds.
- The knowledge base covers T1046, T1110 and T1498 only.
- Capture only sees traffic that reaches the PC's own interfaces, not other devices on the network.

## 11. Responsible use

For learning and for networks you own or have written permission to test. Do not run scans or floods against anyone else's systems.

## Author

[Your Name], [Institution]. Contact: [email]
