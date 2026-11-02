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