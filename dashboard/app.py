import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import streamlit as st
import pandas as pd
import numpy as np
import joblib
import plotly.express as px

from llm.explain import get_explanation
from detection.scan_detector import detect_port_scans
from detection.bruteforce_detector import detect_bruteforce
from detection.dos_detector import detect_dos_flood

st.set_page_config(page_title="AI Network Security Dashboard", layout="wide")

st.title("🛡️ AI Network Security Dashboard")

# When running as a PyInstaller exe, bundled files (models, etc.) live in
# sys._MEIPASS (the _internal folder). When running from source, they live
# in the project root.
BUNDLE_DIR = getattr(sys, "_MEIPASS",
                     os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MODEL_PATH = os.path.join(BUNDLE_DIR, "models", "saved", "xgboost_model.pkl")
REDUCED_MODEL_PATH = os.path.join(BUNDLE_DIR, "models", "saved", "rf_reduced.pkl")

# Live data is written by the capture process next to the exe, so it stays relative
LIVE_FILE = "dataset/live_flows.csv"
HISTORICAL_DATA_PATH = "dataset/clean_combined.csv"
SAMPLE_SIZE = 100_000
IST_OFFSET = "Asia/Kolkata"

REDUCED_FEATURES = [
    "Destination Port", "Flow Duration",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Mean",
    "Bwd Packet Length Max", "Bwd Packet Length Std",
    "Max Packet Length", "Min Packet Length",
    "Packet Length Mean", "Packet Length Std",
    "Average Packet Size",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "Flow Bytes/s", "Flow Packets/s",
    "FIN Flag Count", "SYN Flag Count",
]


def get_attack_probs(model, X):
    """
    Safely extract P(ATTACK) from a model's predict_proba output, regardless
    of whether the model was trained on string labels ("ATTACK"/"BENIGN",
    which scikit-learn sorts alphabetically -> ATTACK ends up at index 0)
    or numeric labels (0/1, where 1 was mapped to ATTACK during training).

    This fixes a real bug found during Phase 22 testing: RandomForest models
    trained on string labels had ATTACK at index 0, not 1, so predict_proba(X)[:, 1]
    was silently returning P(BENIGN) instead of P(ATTACK).
    """
    classes = list(model.classes_)
    if "ATTACK" in classes:
        attack_idx = classes.index("ATTACK")
    elif 1 in classes:
        attack_idx = classes.index(1)
    else:
        raise ValueError(f"Could not determine ATTACK class index from model.classes_ = {classes}")
    return model.predict_proba(X)[:, attack_idx]


def get_attack_preds_as_labels(model, preds):
    """Normalize predict() output to always be 'ATTACK'/'BENIGN' strings."""
    classes = list(model.classes_)
    if "ATTACK" in classes:
        return np.where(preds == "ATTACK", "ATTACK", "BENIGN")
    else:
        return np.where(preds == 1, "ATTACK", "BENIGN")


def to_ist(unix_timestamp_series):
    """Convert a Series of Unix timestamps (seconds) to readable IST strings."""
    return (
        pd.to_datetime(unix_timestamp_series, unit="s", utc=True)
        .dt.tz_convert(IST_OFFSET)
        .dt.strftime("%Y-%m-%d %H:%M:%S IST")
    )


def add_readable_time(df, time_cols):
    """Add human-readable IST columns next to each given Unix-timestamp column."""
    df = df.copy()
    for col in time_cols:
        if col in df.columns:
            readable_col = col.replace("_", " ").title() + " (IST)"
            df[readable_col] = to_ist(df[col])
    return df


tab1, tab2 = st.tabs(["📊 Historical Analysis (CICIDS2017)", "🔴 Live Monitor"])

# ===========================================================================
# TAB 1 — Historical / static demo
# ===========================================================================
with tab1:
    if not os.path.exists(HISTORICAL_DATA_PATH):
        st.info(
            "📊 Historical CICIDS2017 analysis is not available in this build "
            "(the dataset file was not included to keep the download small). "
            "This does not affect the Live Monitor tab, which works fully "
            "with the included pre-trained models."
        )
    else:
        st.caption(
            "Static demo mode: analyzing a sampled slice of CICIDS2017, not live traffic. "
            "See the Live Monitor tab for real-time capture."
        )

        @st.cache_data
        def load_data_with_confidence():
            df = pd.read_csv(HISTORICAL_DATA_PATH, low_memory=False)

            if len(df) > SAMPLE_SIZE:
                df = df.sample(SAMPLE_SIZE, random_state=42).reset_index(drop=True)

            model = joblib.load(MODEL_PATH)

            drop_cols = ["Label", "Binary_Label"]
            X = df.drop(columns=drop_cols)
            X = X.select_dtypes(include=["number"])

            preds = model.predict(X)
            probs = get_attack_probs(model, X)

            df["model_prediction"] = get_attack_preds_as_labels(model, preds)
            df["confidence"] = probs

            return df

        df = load_data_with_confidence()

        total_flows = len(df)
        total_attacks = (df["model_prediction"] == "ATTACK").sum()
        high_conf_attacks = ((df["model_prediction"] == "ATTACK") & (df["confidence"] > 0.9)).sum()

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Flows (sampled)", f"{total_flows:,}")
        col2.metric("Attacks Detected", f"{total_attacks:,}")
        col3.metric("High Risk Alerts (conf > 0.9)", f"{high_conf_attacks:,}")

        st.divider()

        st.subheader("Attack Type Distribution")
        label_counts = df["Label"].value_counts().reset_index()
        label_counts.columns = ["Attack Type", "Count"]
        fig = px.bar(label_counts, x="Attack Type", y="Count", log_y=True)
        st.plotly_chart(fig, use_container_width=True)

        st.divider()

        st.subheader("Alert Explorer")
        st.caption("Pick from the highest-confidence flagged flows in the sampled dataset.")

        attack_rows = df[df["model_prediction"] == "ATTACK"].sort_values(
            "confidence", ascending=False
        )

        if not attack_rows.empty:
            top_alerts = attack_rows.head(20)
            options = [
                f"Row {idx} — {row['Label']} (conf {row['confidence']:.3f})"
                for idx, row in top_alerts.iterrows()
            ]
            selected = st.selectbox("Select an alert", options)
            row_idx = top_alerts.index[options.index(selected)]

            left, right = st.columns([1, 2])

            with left:
                st.write("**Row index:**", row_idx)
                st.write("**Label:**", df.loc[row_idx, "Label"])
                st.write("**Model confidence:**", f"{df.loc[row_idx, 'confidence']:.4f}")
                st.write("**Destination Port:**", df.loc[row_idx, "Destination Port"])
                st.write("**Flow Duration:**", df.loc[row_idx, "Flow Duration"])
                st.write("**Flow Packets/s:**", df.loc[row_idx, "Flow Packets/s"])

                if st.button("Generate AI Explanation", key="static_explain_btn"):
                    with st.spinner("Retrieving evidence and generating explanation..."):
                        evidence = {
                            "row_index": int(row_idx),
                            "prediction": "ATTACK",
                            "confidence": round(float(df.loc[row_idx, "confidence"]), 4),
                            "destination_port": int(df.loc[row_idx, "Destination Port"]),
                            "flow_duration": float(df.loc[row_idx, "Flow Duration"]),
                            "flow_bytes_per_sec": float(df.loc[row_idx, "Flow Bytes/s"]),
                            "flow_packets_per_sec": float(df.loc[row_idx, "Flow Packets/s"]),
                            "syn_flag_count": int(df.loc[row_idx, "SYN Flag Count"]),
                            "fin_flag_count": int(df.loc[row_idx, "FIN Flag Count"]),
                            "top_contributing_features": ["Flow Packets/s", "Destination Port"],
                        }
                        explanation = get_explanation(evidence)
                        st.session_state["last_explanation"] = explanation
                        st.session_state["last_row_idx"] = row_idx

            with right:
                if st.session_state.get("last_explanation") and st.session_state.get("last_row_idx") == row_idx:
                    st.markdown("### AI Explanation")
                    st.write(st.session_state["last_explanation"])
                else:
                    st.info("Click 'Generate AI Explanation' to run the RAG+LLM pipeline on this alert.")
        else:
            st.info("No attack rows found in the sampled dataset.")

# ===========================================================================
# TAB 2 — Live Monitor (Phase 22)
# ===========================================================================
with tab2:
    st.subheader("Live Traffic Monitor")
    st.caption(
        "Reads completed flows from packet_capture/capture_v2.py in real time. "
        "Run that script separately (as Administrator) in another terminal. "
        "All times shown below are in Indian Standard Time (IST)."
    )

    if st.button("🔄 Refresh live feed"):
        st.rerun()

    if os.path.exists(LIVE_FILE):
        live_df = pd.read_csv(LIVE_FILE)

        if not live_df.empty:
            reduced_model = joblib.load(REDUCED_MODEL_PATH)
            X_live = live_df[REDUCED_FEATURES]
            preds = reduced_model.predict(X_live)
            probs = get_attack_probs(reduced_model, X_live)

            live_df["prediction"] = get_attack_preds_as_labels(reduced_model, preds)
            live_df["confidence"] = probs
            live_df["Time (IST)"] = to_ist(live_df["timestamp"])

            total_live = len(live_df)
            attacks_live = (live_df["prediction"] == "ATTACK").sum()

            c1, c2 = st.columns(2)
            c1.metric("Total Live Flows", total_live)
            c2.metric("Flagged as ATTACK (per-flow ML)", attacks_live)

            st.dataframe(
                live_df[["Time (IST)", "src_ip", "dst_ip", "Destination Port", "prediction", "confidence"]]
                .sort_values("Time (IST)", ascending=False)
                .head(50)
            )

            ML_CONFIDENCE_THRESHOLD = 0.75  # filters out low-confidence noise (e.g. DHCP/near-zero-duration artifacts)

            attack_live_rows = live_df[
                (live_df["prediction"] == "ATTACK") & (live_df["confidence"] >= ML_CONFIDENCE_THRESHOLD)
            ].sort_values("confidence", ascending=False)

            if not attack_live_rows.empty:
                st.subheader("⚠️ Live Alerts (Per-Flow ML)")
                st.caption(
                    f"Showing only alerts with confidence ≥ {ML_CONFIDENCE_THRESHOLD:.0%}. "
                    "Lower-confidence flags are often noise from very short flows "
                    "(see project limitations: near-zero flow duration can produce "
                    "artificially high computed packet/byte rates)."
                )
                options = [
                    f"[{row['Time (IST)']}] {row['src_ip']} → {row['dst_ip']}:{int(row['Destination Port'])} (conf {row['confidence']:.3f})"
                    for _, row in attack_live_rows.head(10).iterrows()
                ]
                selected_live = st.selectbox("Select a live alert", options, key="live_alert_select")
                sel_idx = attack_live_rows.index[options.index(selected_live)]
                sel_row = live_df.loc[sel_idx]

                if st.button("Generate AI Explanation (Live)", key="live_explain_btn"):
                    with st.spinner("Retrieving evidence and generating explanation..."):
                        evidence = {
                            "src_ip": sel_row["src_ip"],
                            "dst_ip": sel_row["dst_ip"],
                            "prediction": "ATTACK",
                            "confidence": round(float(sel_row["confidence"]), 4),
                            "destination_port": int(sel_row["Destination Port"]),
                            "flow_duration": float(sel_row["Flow Duration"]),
                            "flow_bytes_per_sec": float(sel_row["Flow Bytes/s"]),
                            "flow_packets_per_sec": float(sel_row["Flow Packets/s"]),
                            "syn_flag_count": int(sel_row["SYN Flag Count"]),
                            "fin_flag_count": int(sel_row["FIN Flag Count"]),
                            "top_contributing_features": ["Destination Port", "Flow Packets/s", "Max Packet Length"],
                        }
                        explanation = get_explanation(evidence)
                        st.session_state["live_explanation"] = explanation
                        st.session_state["live_explanation_idx"] = sel_idx

                if st.session_state.get("live_explanation") and st.session_state.get("live_explanation_idx") == sel_idx:
                    st.markdown("### AI Explanation")
                    st.write(st.session_state["live_explanation"])
            else:
                st.info(f"No high-confidence (≥{ML_CONFIDENCE_THRESHOLD:.0%}) ML alerts in current live data.")

            st.divider()
            st.subheader("🎯 Aggregate Port Scan Detection")
            st.caption(
                "Complements the per-flow ML model: flags a source IP if it contacts "
                "many distinct destination ports within a short time window — the "
                "classic port-scan signature that single-flow classifiers often miss."
            )

            scan_alerts = detect_port_scans(LIVE_FILE, time_window_seconds=10, port_threshold=15)

            if not scan_alerts.empty:
                scan_alerts_display = add_readable_time(scan_alerts, ["window_start", "window_end"])
                st.dataframe(scan_alerts_display)

                options_scan = [
                    f"[{row['Window Start (IST)']}] {row['src_ip']} → {row['dst_ip']} ({row['distinct_ports_contacted']} ports)"
                    for _, row in scan_alerts_display.iterrows()
                ]
                selected_scan = st.selectbox("Select a scan alert", options_scan, key="scan_alert_select")
                scan_idx = options_scan.index(selected_scan)
                scan_row = scan_alerts.iloc[scan_idx]

                if st.button("Generate AI Explanation (Scan)", key="scan_explain_btn"):
                    with st.spinner("Retrieving evidence and generating explanation..."):
                        evidence = {
                            "src_ip": str(scan_row["src_ip"]),
                            "dst_ip": str(scan_row["dst_ip"]),
                            "prediction": "ATTACK",
                            "detection_type": "PortScan (aggregate rule)",
                            "distinct_ports_contacted": int(scan_row["distinct_ports_contacted"]),
                            "sample_ports": [int(p) for p in scan_row["sample_ports"]],
                            "time_window_seconds": 10,
                        }
                        explanation = get_explanation(evidence)
                        st.session_state["scan_explanation"] = explanation
                        st.session_state["scan_explanation_idx"] = scan_idx

                if st.session_state.get("scan_explanation") and st.session_state.get("scan_explanation_idx") == scan_idx:
                    st.markdown("### AI Explanation")
                    st.write(st.session_state["scan_explanation"])
            else:
                st.info("No aggregate port-scan patterns detected in current live data.")

            st.divider()
            st.subheader("🔑 Aggregate Brute-Force Detection")
            st.caption(
                "Flags a source IP making many rapid connection attempts to the SAME "
                "destination port (repeated login attempts) — restricted by default to "
                "known auth-service ports (SSH, FTP, RDP, SMB, etc.) and short, low-data "
                "flows, to avoid false positives on normal high-frequency traffic like DNS "
                "or HTTPS."
            )

            bruteforce_alerts = detect_bruteforce(LIVE_FILE, time_window_seconds=10, attempt_threshold=15)

            if not bruteforce_alerts.empty:
                bruteforce_alerts_display = add_readable_time(bruteforce_alerts, ["window_start", "window_end"])
                st.dataframe(bruteforce_alerts_display)

                options_bf = [
                    f"[{row['Window Start (IST)']}] {row['src_ip']} → {row['dst_ip']}:{row['dst_port']} ({row['attempts_in_window']} attempts)"
                    for _, row in bruteforce_alerts_display.iterrows()
                ]
                selected_bf = st.selectbox("Select a brute-force alert", options_bf, key="bf_alert_select")
                bf_idx = options_bf.index(selected_bf)
                bf_row = bruteforce_alerts.iloc[bf_idx]

                if st.button("Generate AI Explanation (Brute-Force)", key="bf_explain_btn"):
                    with st.spinner("Retrieving evidence and generating explanation..."):
                        evidence = {
                            "src_ip": str(bf_row["src_ip"]),
                            "dst_ip": str(bf_row["dst_ip"]),
                            "prediction": "ATTACK",
                            "detection_type": "Brute-force (aggregate rule)",
                            "destination_port": int(bf_row["dst_port"]),
                            "attempts_in_window": int(bf_row["attempts_in_window"]),
                            "time_window_seconds": 10,
                        }
                        explanation = get_explanation(evidence)
                        st.session_state["bf_explanation"] = explanation
                        st.session_state["bf_explanation_idx"] = bf_idx

                if st.session_state.get("bf_explanation") and st.session_state.get("bf_explanation_idx") == bf_idx:
                    st.markdown("### AI Explanation")
                    st.write(st.session_state["bf_explanation"])
            else:
                st.info("No brute-force patterns detected on known auth-service ports.")

            st.divider()
            st.subheader("💥 Aggregate DoS/Flood Detection")
            st.caption(
                "Flags a source-destination pair receiving an abnormally high "
                "volume of flow records within a short time window — the "
                "signature of a volumetric flood attack."
            )

            dos_alerts = detect_dos_flood(LIVE_FILE, time_window_seconds=10, flow_count_threshold=200)

            if not dos_alerts.empty:
                dos_alerts_display = add_readable_time(dos_alerts, ["window_start", "window_end"])
                st.dataframe(dos_alerts_display)

                options_dos = [
                    f"[{row['Window Start (IST)']}] {row['src_ip']} → {row['dst_ip']} ({row['flow_count_in_window']} flows)"
                    for _, row in dos_alerts_display.iterrows()
                ]
                selected_dos = st.selectbox("Select a DoS/flood alert", options_dos, key="dos_alert_select")
                dos_idx = options_dos.index(selected_dos)
                dos_row = dos_alerts.iloc[dos_idx]

                if st.button("Generate AI Explanation (DoS)", key="dos_explain_btn"):
                    with st.spinner("Retrieving evidence and generating explanation..."):
                        evidence = {
                            "src_ip": str(dos_row["src_ip"]),
                            "dst_ip": str(dos_row["dst_ip"]),
                            "prediction": "ATTACK",
                            "detection_type": "DoS/Flood (aggregate rule)",
                            "flow_count_in_window": int(dos_row["flow_count_in_window"]),
                            "time_window_seconds": 10,
                        }
                        explanation = get_explanation(evidence)
                        st.session_state["dos_explanation"] = explanation
                        st.session_state["dos_explanation_idx"] = dos_idx

                if st.session_state.get("dos_explanation") and st.session_state.get("dos_explanation_idx") == dos_idx:
                    st.markdown("### AI Explanation")
                    st.write(st.session_state["dos_explanation"])
            else:
                st.info("No DoS/flood patterns detected in current live data.")
        else:
            st.info("No flows captured yet. Run capture_v2.py and wait for some flows to complete.")
    else:
        st.warning("live_flows.csv not found yet. Start packet_capture/capture_v2.py first.")