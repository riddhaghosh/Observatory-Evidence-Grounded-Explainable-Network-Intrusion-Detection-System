import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import streamlit as st
import pandas as pd
import numpy as np
import joblib
import plotly.express as px
import plotly.graph_objects as go

from llm.explain import get_explanation
from detection.scan_detector import detect_port_scans
from detection.bruteforce_detector import detect_bruteforce
from detection.dos_detector import detect_dos_flood

st.set_page_config(page_title="Observatory", page_icon="🛡️", layout="wide")

# ---------------------------------------------------------------------------
# Paths and constants
# ---------------------------------------------------------------------------
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
ML_CONFIDENCE_THRESHOLD = 0.75  # filters out low-confidence noise (e.g. DHCP/near-zero-duration artifacts)

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

# Colour palette
C_CYAN = "#22D3EE"
C_BLUE = "#6366F1"
C_RED = "#F43F5E"
C_AMBER = "#F59E0B"
C_GREEN = "#10B981"
C_VIOLET = "#A855F7"
C_MUTED = "#94A3B8"

# ---------------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------------
st.markdown(
    f"""
    <style>
    .stApp {{
        background: radial-gradient(1200px 600px at 10% -10%, #14213d 0%, #0b1220 55%) fixed;
    }}
    .block-container {{ padding-top: 1.6rem; max-width: 1400px; }}
    h1, h2, h3, h4 {{ letter-spacing: .2px; }}

    .hero {{
        background: linear-gradient(120deg, rgba(34,211,238,.18), rgba(99,102,241,.22) 55%, rgba(168,85,247,.18));
        border: 1px solid rgba(148,163,184,.25);
        border-radius: 18px;
        padding: 22px 28px;
        margin-bottom: 14px;
    }}
    .hero h1 {{ margin: 0; font-size: 2.1rem; color: #F8FAFC; }}
    .hero p {{ margin: 4px 0 0 0; color: {C_MUTED}; font-size: .98rem; }}

    .kpi {{
        background: rgba(15,23,42,.72);
        border: 1px solid rgba(148,163,184,.18);
        border-left: 5px solid var(--accent);
        border-radius: 14px;
        padding: 14px 16px;
        height: 100%;
    }}
    .kpi .label {{ color: {C_MUTED}; font-size: .78rem; text-transform: uppercase; letter-spacing: .8px; }}
    .kpi .value {{ color: #F8FAFC; font-size: 1.9rem; font-weight: 700; line-height: 1.25; }}
    .kpi .sub {{ color: {C_MUTED}; font-size: .75rem; }}

    .pill {{
        display: inline-block; padding: 4px 14px; border-radius: 999px;
        font-weight: 700; font-size: .85rem; letter-spacing: .6px;
    }}
    .pill.high {{ background: rgba(244,63,94,.18); color: {C_RED}; border: 1px solid {C_RED}; }}
    .pill.med  {{ background: rgba(245,158,11,.18); color: {C_AMBER}; border: 1px solid {C_AMBER}; }}
    .pill.low  {{ background: rgba(16,185,129,.18); color: {C_GREEN}; border: 1px solid {C_GREEN}; }}

    .section-title {{
        margin: 22px 0 6px 0; font-size: 1.15rem; font-weight: 700; color: #E2E8F0;
        border-left: 4px solid {C_CYAN}; padding-left: 10px;
    }}
    .section-sub {{ color: {C_MUTED}; font-size: .85rem; margin-bottom: 8px; }}

    div[data-testid="stTabs"] button[role="tab"] {{
        font-weight: 600; padding: 10px 18px;
    }}
    div[data-testid="stTabs"] button[aria-selected="true"] {{ color: {C_CYAN}; }}

    div.stButton > button {{
        border-radius: 10px; font-weight: 600; border: 1px solid rgba(148,163,184,.35);
    }}
    div.stButton > button[kind="primary"] {{
        background: linear-gradient(90deg, {C_BLUE}, {C_CYAN}); border: 0; color: #0b1220;
    }}
    div[data-testid="stDataFrame"] {{ border-radius: 12px; overflow: hidden; }}

    /* ---- Force readable colours even when Streamlit's light theme is active ---- */
    .stApp, .stApp p, .stApp li, .stApp span, .stApp label, .stApp td, .stApp th,
    .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6,
    .stApp [data-testid="stMarkdownContainer"], .stApp [data-testid="stCaptionContainer"],
    .stApp [data-testid="stWidgetLabel"] {{ color: #E2E8F0; }}
    .stApp [data-testid="stCaptionContainer"], .stApp small {{ color: {C_MUTED}; }}
    .stApp code {{
        background: rgba(34,211,238,.12) !important; color: #67E8F9 !important;
        border-radius: 6px; padding: 2px 6px;
    }}
    .stApp pre {{ background: #0F172A !important; border: 1px solid rgba(148,163,184,.2); border-radius: 10px; }}
    .stApp pre code {{ background: transparent !important; color: #A7F3D0 !important; }}
    .stApp table {{ border-collapse: collapse; width: 100%; }}
    .stApp th {{ background: rgba(99,102,241,.18); }}
    .stApp th, .stApp td {{ border: 1px solid rgba(148,163,184,.25) !important; padding: 6px 10px; }}
    .stApp a {{ color: {C_CYAN}; }}
    header[data-testid="stHeader"] {{ background: transparent; }}

    /* ---- Dark HTML tables ---- */
    .dtbl-wrap {{ overflow: auto; border: 1px solid rgba(148,163,184,.28); border-radius: 12px; background: #0F172A; margin-bottom: 10px; }}
    .stApp .dtbl {{ width: 100%; border-collapse: collapse; font-size: .88rem; }}
    .stApp .dtbl thead th {{
        position: sticky; top: 0; z-index: 1; background: #1E293B !important; color: {C_CYAN} !important;
        text-align: left; padding: 9px 14px; font-weight: 700; white-space: nowrap;
        border: 0 !important; border-bottom: 2px solid rgba(34,211,238,.35) !important;
    }}
    .stApp .dtbl td {{
        padding: 8px 14px; color: #F1F5F9 !important; white-space: nowrap;
        border: 0 !important; border-top: 1px solid rgba(148,163,184,.14) !important;
        font-variant-numeric: tabular-nums;
    }}
    .stApp .dtbl tbody tr:nth-child(even) {{ background: rgba(148,163,184,.06); }}
    .stApp .dtbl tbody tr:hover {{ background: rgba(34,211,238,.10); }}
    .dtbl .atk {{ color: {C_RED}; font-weight: 700; }}
    .dtbl .ben {{ color: {C_GREEN}; font-weight: 600; }}

    /* ---- Select boxes / dropdowns (older and newer Streamlit) ---- */
    .stApp [data-testid="stSelectbox"] [role="group"],
    .stApp [data-testid="stSelectbox"] div[data-baseweb="select"] > div {{
        background: #0F172A !important; border: 1px solid rgba(34,211,238,.35) !important; border-radius: 10px !important;
    }}
    .stApp [data-testid="stSelectbox"] input {{ color: #F1F5F9 !important; -webkit-text-fill-color: #F1F5F9 !important; background: transparent !important; }}
    .stApp [data-testid="stSelectbox"] svg {{ fill: #E2E8F0 !important; color: #E2E8F0 !important; }}
    [role="listbox"], [role="listbox"] [role="option"], ul[role="listbox"] li,
    div[data-baseweb="popover"] ul, div[data-baseweb="popover"] li, div[data-baseweb="menu"] {{
        background: #0F172A !important; color: #F1F5F9 !important;
    }}
    [role="option"]:hover, [role="option"][data-focused="true"], [role="option"][aria-selected="true"],
    div[data-baseweb="popover"] li:hover {{ background: #1E293B !important; color: {C_CYAN} !important; }}

    /* ---- Buttons: explicit colours so they are readable in any theme ---- */
    .stApp div.stButton > button, .stApp button[data-testid="stBaseButton-secondary"] {{
        background: #0F172A !important; color: #E2E8F0 !important;
        border: 1px solid rgba(34,211,238,.45) !important;
    }}
    .stApp div.stButton > button:hover, .stApp button[data-testid="stBaseButton-secondary"]:hover {{
        border-color: {C_CYAN} !important; color: {C_CYAN} !important; background: #13203a !important;
    }}
    .stApp div.stButton > button p, .stApp div.stButton > button span,
    .stApp button[data-testid="stBaseButton-secondary"] p {{ color: inherit !important; }}
    .stApp button[data-testid="stBaseButton-primary"], .stApp div.stButton > button[kind="primary"] {{
        background: linear-gradient(90deg, {C_BLUE}, {C_CYAN}) !important; color: #0B1220 !important; border: 0 !important;
    }}
    .stApp button[data-testid="stBaseButton-primary"] p, .stApp div.stButton > button[kind="primary"] p {{
        color: #0B1220 !important; font-weight: 700;
    }}
    div[data-baseweb="select"] > div, div[data-baseweb="input"] > div {{
        background: #0F172A !important; border-color: rgba(148,163,184,.3) !important; color: #E2E8F0 !important;
    }}
    div[data-baseweb="select"] span, div[data-baseweb="select"] div {{ color: #E2E8F0 !important; }}
    div[data-baseweb="popover"] ul, div[data-baseweb="popover"] li {{ background: #0F172A !important; color: #E2E8F0 !important; }}
    div[data-testid="stAlert"] p {{ color: inherit; }}
    div[data-testid="stVerticalBlockBorderWrapper"] {{ background: rgba(15,23,42,.55); border-color: rgba(148,163,184,.25) !important; }}
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
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


def kpi_card(col, label, value, accent, sub=""):
    col.markdown(
        f"""<div class="kpi" style="--accent:{accent}">
                <div class="label">{label}</div>
                <div class="value">{value}</div>
                <div class="sub">{sub}&nbsp;</div>
            </div>""",
        unsafe_allow_html=True,
    )


def section(title, subtitle=""):
    st.markdown(f'<div class="section-title">{title}</div>', unsafe_allow_html=True)
    if subtitle:
        st.markdown(f'<div class="section-sub">{subtitle}</div>', unsafe_allow_html=True)


def style_fig(fig, height=300):
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=height,
        margin=dict(l=10, r=10, t=40, b=10),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        font=dict(color="#CBD5E1"),
    )
    fig.update_xaxes(gridcolor="rgba(148,163,184,.12)")
    fig.update_yaxes(gridcolor="rgba(148,163,184,.12)")
    return fig


def dark_table(df, max_height=340):
    """Render a DataFrame as a dark, always-readable HTML table (sticky header, scrollable)."""
    d = df.copy()
    fmt = lambda x: f"{x:.4f}".rstrip("0").rstrip(".") if pd.notna(x) else ""
    html = d.to_html(index=False, escape=True, border=0, classes="dtbl", float_format=fmt)
    html = html.replace(">ATTACK<", '><span class="atk">ATTACK</span><')
    html = html.replace(">BENIGN<", '><span class="ben">BENIGN</span><')
    html = "".join(line.strip() for line in html.splitlines())
    st.markdown(
        f'<div class="dtbl-wrap" style="max-height:{max_height}px">{html}</div>',
        unsafe_allow_html=True,
    )


def alert_panel(key, alerts, display_df, option_fn, evidence_fn, button_label, empty_msg):
    """
    Generic panel: table of alerts, a selector, an 'explain' button and the
    AI explanation. `alerts` holds the raw rows used to build evidence;
    `display_df` is the same rows (same order) formatted for display.
    """
    if alerts.empty:
        st.success(empty_msg)
        return

    dark_table(display_df)

    options = [option_fn(row) for _, row in display_df.iterrows()]
    selected = st.selectbox("Select an alert to investigate", options, key=f"{key}_select")
    idx = options.index(selected)
    row = alerts.iloc[idx]

    if st.button(button_label, key=f"{key}_btn", type="primary"):
        with st.spinner("Retrieving evidence and generating explanation..."):
            explanation = get_explanation(evidence_fn(row))
            st.session_state[f"{key}_explanation"] = explanation
            st.session_state[f"{key}_explanation_idx"] = idx

    if (st.session_state.get(f"{key}_explanation")
            and st.session_state.get(f"{key}_explanation_idx") == idx):
        with st.container(border=True):
            st.markdown("#### 🤖 AI Explanation")
            st.write(st.session_state[f"{key}_explanation"])
    else:
        st.caption("Click the button above to run the RAG + LLM pipeline on the selected alert.")


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.markdown(
    """
    <div class="hero">
        <h1>🛡️ Observatory</h1>
        <p>Evidence-Grounded Explainable Network Intrusion Detection System</p>
    </div>
    """,
    unsafe_allow_html=True,
)

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

        k1, k2, k3 = st.columns(3)
        kpi_card(k1, "Total Flows (sampled)", f"{total_flows:,}", C_CYAN)
        kpi_card(k2, "Attacks Detected", f"{total_attacks:,}", C_RED)
        kpi_card(k3, "High Risk Alerts (conf > 0.9)", f"{high_conf_attacks:,}", C_AMBER)

        section("Attack Type Distribution", "Log scale, so rare attack types stay visible next to benign traffic.")
        label_counts = df["Label"].value_counts().reset_index()
        label_counts.columns = ["Attack Type", "Count"]
        fig = px.bar(label_counts, x="Attack Type", y="Count", log_y=True,
                     color="Count", color_continuous_scale=[C_BLUE, C_CYAN, C_AMBER, C_RED])
        fig.update_coloraxes(showscale=False)
        st.plotly_chart(style_fig(fig, 360), use_container_width=True, theme=None)

        section("Alert Explorer", "Pick from the highest-confidence flagged flows in the sampled dataset.")

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
                with st.container(border=True):
                    st.write("**Row index:**", row_idx)
                    st.write("**Label:**", df.loc[row_idx, "Label"])
                    st.write("**Model confidence:**", f"{df.loc[row_idx, 'confidence']:.4f}")
                    st.write("**Destination Port:**", df.loc[row_idx, "Destination Port"])
                    st.write("**Flow Duration:**", df.loc[row_idx, "Flow Duration"])
                    st.write("**Flow Packets/s:**", df.loc[row_idx, "Flow Packets/s"])

                if st.button("Generate AI Explanation", key="static_explain_btn", type="primary"):
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
                    with st.container(border=True):
                        st.markdown("#### 🤖 AI Explanation")
                        st.write(st.session_state["last_explanation"])
                else:
                    st.info("Click 'Generate AI Explanation' to run the RAG+LLM pipeline on this alert.")
        else:
            st.info("No attack rows found in the sampled dataset.")

# ===========================================================================
# TAB 2 — Live Monitor
# ===========================================================================
with tab2:
    top_l, top_r = st.columns([4, 1])
    top_l.caption(
        "Reads completed flows from packet_capture/capture_v2.py in real time. "
        "Run that script separately (as Administrator) in another terminal. "
        "All times shown below are in Indian Standard Time (IST)."
    )
    if top_r.button("🔄 Refresh live feed", use_container_width=True):
        st.rerun()

    if not os.path.exists(LIVE_FILE):
        st.warning("live_flows.csv not found yet. Start packet_capture/capture_v2.py first.")
    else:
        live_df = pd.read_csv(LIVE_FILE)

        if live_df.empty:
            st.info("No flows captured yet. Run capture_v2.py and wait for some flows to complete.")
        else:
            # ---------------- ML scoring ----------------
            reduced_model = joblib.load(REDUCED_MODEL_PATH)
            X_live = live_df[REDUCED_FEATURES]
            preds = reduced_model.predict(X_live)
            probs = get_attack_probs(reduced_model, X_live)

            live_df["prediction"] = get_attack_preds_as_labels(reduced_model, preds)
            live_df["confidence"] = probs
            live_df["Time (IST)"] = to_ist(live_df["timestamp"])

            total_live = len(live_df)
            attacks_live = int((live_df["prediction"] == "ATTACK").sum())

            attack_live_rows = live_df[
                (live_df["prediction"] == "ATTACK") & (live_df["confidence"] >= ML_CONFIDENCE_THRESHOLD)
            ].sort_values("confidence", ascending=False)

            # ---------------- Rule detectors ----------------
            scan_alerts = detect_port_scans(LIVE_FILE, time_window_seconds=10, port_threshold=15)
            bruteforce_alerts = detect_bruteforce(LIVE_FILE, time_window_seconds=10, attempt_threshold=15)
            dos_alerts = detect_dos_flood(LIVE_FILE, time_window_seconds=10, flow_count_threshold=200)

            n_scan, n_bf, n_dos = len(scan_alerts), len(bruteforce_alerts), len(dos_alerts)
            n_rules = n_scan + n_bf + n_dos

            if n_rules >= 2 or n_dos > 0:
                level, level_cls, level_color = "HIGH", "high", C_RED
            elif n_rules == 1 or len(attack_live_rows) > 0:
                level, level_cls, level_color = "ELEVATED", "med", C_AMBER
            else:
                level, level_cls, level_color = "NORMAL", "low", C_GREEN

            # ---------------- KPI row ----------------
            st.markdown(
                f'Threat level &nbsp;<span class="pill {level_cls}">● {level}</span>',
                unsafe_allow_html=True,
            )
            k1, k2, k3, k4, k5, k6 = st.columns(6)
            kpi_card(k1, "Live Flows", f"{total_live:,}", C_CYAN, "captured so far")
            kpi_card(k2, "ML Flags", f"{attacks_live:,}", C_BLUE, "per-flow classifier")
            kpi_card(k3, "Port Scans", n_scan, C_AMBER, "aggregate rule")
            kpi_card(k4, "Brute Force", n_bf, C_VIOLET, "aggregate rule")
            kpi_card(k5, "DoS / Flood", n_dos, C_RED, "aggregate rule")
            kpi_card(k6, "Unique Sources", f"{live_df['src_ip'].nunique():,}", level_color, "distinct source IPs")

            # ---------------- Charts ----------------
            section("Traffic Overview")
            ch1, ch2, ch3 = st.columns([2, 1, 1])

            tl = live_df.copy()
            tl["bucket"] = (
                pd.to_datetime(tl["timestamp"], unit="s", utc=True)
                .dt.tz_convert(IST_OFFSET)
                .dt.floor("10s")
                .dt.tz_localize(None)
            )
            timeline = tl.groupby(["bucket", "prediction"]).size().reset_index(name="flows")
            fig_t = px.area(timeline, x="bucket", y="flows", color="prediction",
                            color_discrete_map={"BENIGN": C_CYAN, "ATTACK": C_RED},
                            title="Flows over time (10 s buckets, IST)")
            fig_t.update_layout(xaxis_title=None, yaxis_title=None)
            ch1.plotly_chart(style_fig(fig_t, 300), use_container_width=True, theme=None)

            top_src = live_df["src_ip"].value_counts().head(6).reset_index()
            top_src.columns = ["src_ip", "flows"]
            fig_s = px.bar(top_src.iloc[::-1], x="flows", y="src_ip", orientation="h",
                           title="Top source IPs", color_discrete_sequence=[C_BLUE])
            fig_s.update_layout(xaxis_title=None, yaxis_title=None)
            ch2.plotly_chart(style_fig(fig_s, 300), use_container_width=True, theme=None)

            top_ports = live_df["Destination Port"].astype(int).astype(str).value_counts().head(6).reset_index()
            top_ports.columns = ["port", "flows"]
            fig_p = px.bar(top_ports.iloc[::-1], x="flows", y="port", orientation="h",
                           title="Top destination ports", color_discrete_sequence=[C_VIOLET])
            fig_p.update_layout(xaxis_title=None, yaxis_title=None, yaxis_type="category")
            ch3.plotly_chart(style_fig(fig_p, 300), use_container_width=True, theme=None)

            # ---------------- Alerts ----------------
            section(
                "Detections & AI Explanations",
                "Rule-based detectors look across many flows (the behaviour single-flow ML often misses). "
                "Select an alert and generate its explanation.",
            )

            t_scan, t_bf, t_dos, t_ml, t_flows = st.tabs([
                f"🎯 Port Scan ({n_scan})",
                f"🔑 Brute Force ({n_bf})",
                f"💥 DoS / Flood ({n_dos})",
                f"⚠️ ML Alerts ({len(attack_live_rows)})",
                "📜 Recent Flows",
            ])

            with t_scan:
                st.caption(
                    "Flags a source IP if it contacts many distinct destination ports within a "
                    "short time window — the classic port-scan signature."
                )
                scan_display = (add_readable_time(scan_alerts, ["window_start", "window_end"])
                                if not scan_alerts.empty else scan_alerts)
                alert_panel(
                    "scan", scan_alerts, scan_display,
                    option_fn=lambda r: f"[{r['Window Start (IST)']}] {r['src_ip']} → {r['dst_ip']} ({r['distinct_ports_contacted']} ports)",
                    evidence_fn=lambda r: {
                        "src_ip": str(r["src_ip"]),
                        "dst_ip": str(r["dst_ip"]),
                        "prediction": "ATTACK",
                        "detection_type": "PortScan (aggregate rule)",
                        "distinct_ports_contacted": int(r["distinct_ports_contacted"]),
                        "sample_ports": [int(p) for p in r["sample_ports"]],
                        "time_window_seconds": 10,
                    },
                    button_label="Generate AI Explanation (Scan)",
                    empty_msg="✅ No aggregate port-scan patterns detected in current live data.",
                )

            with t_bf:
                st.caption(
                    "Flags a source IP making many rapid connection attempts to the SAME destination "
                    "port (repeated login attempts) — restricted to known auth-service ports "
                    "(SSH, FTP, RDP, SMB, etc.) and short, low-data flows, to avoid false positives "
                    "on normal high-frequency traffic like DNS or HTTPS."
                )
                bf_display = (add_readable_time(bruteforce_alerts, ["window_start", "window_end"])
                              if not bruteforce_alerts.empty else bruteforce_alerts)
                alert_panel(
                    "bf", bruteforce_alerts, bf_display,
                    option_fn=lambda r: f"[{r['Window Start (IST)']}] {r['src_ip']} → {r['dst_ip']}:{r['dst_port']} ({r['attempts_in_window']} attempts)",
                    evidence_fn=lambda r: {
                        "src_ip": str(r["src_ip"]),
                        "dst_ip": str(r["dst_ip"]),
                        "prediction": "ATTACK",
                        "detection_type": "Brute-force (aggregate rule)",
                        "destination_port": int(r["dst_port"]),
                        "attempts_in_window": int(r["attempts_in_window"]),
                        "time_window_seconds": 10,
                    },
                    button_label="Generate AI Explanation (Brute-Force)",
                    empty_msg="✅ No brute-force patterns detected on known auth-service ports.",
                )

            with t_dos:
                st.caption(
                    "Flags a source-destination pair receiving an abnormally high volume of flow "
                    "records within a short time window — the signature of a volumetric flood attack."
                )
                dos_display = (add_readable_time(dos_alerts, ["window_start", "window_end"])
                               if not dos_alerts.empty else dos_alerts)
                alert_panel(
                    "dos", dos_alerts, dos_display,
                    option_fn=lambda r: f"[{r['Window Start (IST)']}] {r['src_ip']} → {r['dst_ip']} ({r['flow_count_in_window']} flows)",
                    evidence_fn=lambda r: {
                        "src_ip": str(r["src_ip"]),
                        "dst_ip": str(r["dst_ip"]),
                        "prediction": "ATTACK",
                        "detection_type": "DoS/Flood (aggregate rule)",
                        "flow_count_in_window": int(r["flow_count_in_window"]),
                        "time_window_seconds": 10,
                    },
                    button_label="Generate AI Explanation (DoS)",
                    empty_msg="✅ No DoS/flood patterns detected in current live data.",
                )

            with t_ml:
                st.caption(
                    f"Per-flow ML alerts with confidence ≥ {ML_CONFIDENCE_THRESHOLD:.0%}. "
                    "Lower-confidence flags are often noise from very short flows "
                    "(near-zero flow duration can produce artificially high computed packet/byte rates)."
                )
                ml_alerts = attack_live_rows.head(10).reset_index(drop=True)
                ml_display = ml_alerts[["Time (IST)", "src_ip", "dst_ip", "Destination Port", "confidence"]]
                alert_panel(
                    "ml", ml_alerts, ml_display,
                    option_fn=lambda r: f"[{r['Time (IST)']}] {r['src_ip']} → {r['dst_ip']}:{int(r['Destination Port'])} (conf {r['confidence']:.3f})",
                    evidence_fn=lambda r: {
                        "src_ip": r["src_ip"],
                        "dst_ip": r["dst_ip"],
                        "prediction": "ATTACK",
                        "confidence": round(float(r["confidence"]), 4),
                        "destination_port": int(r["Destination Port"]),
                        "flow_duration": float(r["Flow Duration"]),
                        "flow_bytes_per_sec": float(r["Flow Bytes/s"]),
                        "flow_packets_per_sec": float(r["Flow Packets/s"]),
                        "syn_flag_count": int(r["SYN Flag Count"]),
                        "fin_flag_count": int(r["FIN Flag Count"]),
                        "top_contributing_features": ["Destination Port", "Flow Packets/s", "Max Packet Length"],
                    },
                    button_label="Generate AI Explanation (Live)",
                    empty_msg=f"✅ No high-confidence (≥{ML_CONFIDENCE_THRESHOLD:.0%}) ML alerts in current live data.",
                )

            with t_flows:
                st.caption("The 50 most recent completed flows.")
                dark_table(
                    live_df[["Time (IST)", "src_ip", "dst_ip", "Destination Port", "prediction", "confidence"]]
                    .sort_values("Time (IST)", ascending=False)
                    .head(50),
                    max_height=460,
                )