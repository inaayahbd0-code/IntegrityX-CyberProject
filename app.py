import os
import sqlite3
import tempfile
from datetime import datetime

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh

import scanner

try:  # desktop notifications only work when running locally
    from plyer import notification
except Exception:  # pragma: no cover
    notification = None

st.set_page_config(page_title="IntegrityX", page_icon="🛡️", layout="wide")
st_autorefresh(interval=10000, key="refresh")

DEMO_DIR = os.path.join(tempfile.gettempdir(), "integrityx_demo")
DEMO_FILES = {
    "payroll.csv": "name,salary\nAsha,50000\nRavi,62000\n",
    "config.ini": "[server]\nport=8080\nadmin=false\n",
    "notes/readme.txt": "Quarterly audit notes.\n",
    "notes/keys.txt": "do-not-change-me\n",
}

if "last_alert_signature" not in st.session_state:
    st.session_state.last_alert_signature = None

st.markdown("<h1 style='text-align:center'>🛡️ IntegrityX</h1>", unsafe_allow_html=True)
st.markdown(
    "<p style='text-align:center;color:#9a9a9a'>Verify. Protect. Trust your data.</p>",
    unsafe_allow_html=True,
)
st.divider()


def fetch_logs(search=None, status=None):
    conn = scanner.get_connection()
    query = "SELECT file_path, status, hash_data, last_modify FROM baselines WHERE 1=1"
    params = []
    if search:
        query += " AND file_path LIKE ?"
        params.append(f"%{search}%")
    if status and status != "ALL":
        query += " AND status = ?"
        params.append(status)
    query += " ORDER BY last_modify DESC"
    df = pd.read_sql_query(query, conn, params=params)
    conn.close()
    return df


def write_demo_files():
    for rel, text in DEMO_FILES.items():
        path = os.path.join(DEMO_DIR, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)


# ---------------- Sidebar: scan controls ----------------
with st.sidebar:
    st.header("Scan")
    target = st.text_input("File or folder path", placeholder="e.g. /home/me/documents")
    if st.button("Run scan", use_container_width=True):
        if target and os.path.exists(target):
            res = scanner.scan(target)
            st.success(f"Scanned {len(res)} file(s).")
        else:
            st.warning("Enter a valid path first.")

    st.divider()
    st.subheader("Try a demo")
    st.caption("Creates sample files, then lets you tamper with them.")
    if st.button("1. Create baseline", use_container_width=True):
        write_demo_files()
        scanner.scan(DEMO_DIR)
        st.success("Baseline stored.")
    if st.button("2. Modify a file", use_container_width=True):
        with open(os.path.join(DEMO_DIR, "payroll.csv"), "a") as f:
            f.write("Intruder,999999\n")
        st.info("payroll.csv edited. Now re-scan.")
    if st.button("3. Delete a file", use_container_width=True):
        p = os.path.join(DEMO_DIR, "config.ini")
        if os.path.exists(p):
            os.remove(p)
        st.info("config.ini deleted. Now re-scan.")
    if st.button("4. Re-scan demo folder", use_container_width=True):
        scanner.scan(DEMO_DIR)
        st.success("Re-scan complete.")

# ---------------- Load data ----------------
try:
    df = fetch_logs()
except Exception as e:
    st.error(f"Could not read database: {e}")
    st.stop()

alerts_df = df[df["status"].isin(["MODIFIED", "DELETED"])] if not df.empty else df
alerts = len(alerts_df)

# Desktop notification only when the set of alerting files changes
signature = tuple(sorted(alerts_df["file_path"].tolist())) if alerts else ()
if alerts and signature != st.session_state.last_alert_signature and notification:
    try:
        notification.notify(
            title="File Integrity Alert",
            message=f"{alerts} file(s) modified/deleted",
            timeout=5,
        )
    except Exception:
        pass
st.session_state.last_alert_signature = signature

# ---------------- Metrics ----------------
c1, c2, c3 = st.columns(3)
total = df["file_path"].nunique() if not df.empty else 0
last_scan = (
    datetime.fromtimestamp(df["last_modify"].max()).strftime("%Y-%m-%d %H:%M:%S")
    if not df.empty and df["last_modify"].max() > 0
    else "No scans yet"
)
c1.metric("📁 Files Monitored", total, border=True)
c2.metric(
    "🚨 Security Alerts",
    alerts,
    delta=f"{alerts} changes" if alerts else None,
    delta_color="inverse",
    border=True,
)
c3.metric("⏱️ Last File Activity", last_scan, border=True)

if alerts:
    st.error(f"🚨 {alerts} unauthorized file modification(s)/deletion(s) detected. Inspect logs.")
elif total:
    st.success("✅ System secure: all monitored file hashes match their baselines.")
else:
    st.info("No baseline yet. Use the sidebar to scan a folder or run the demo.")

st.divider()

# ---------------- Logs ----------------
st.subheader("📋 Detailed Activity Logs")
f1, f2 = st.columns([2, 1])
with f1:
    search = st.text_input("🔍 Files", placeholder="Search by file path...")
with f2:
    options = ["ALL", "NEW", "MATCH", "MODIFIED", "DELETED"]
    selected = st.selectbox("🎯 Filter by status", options)

view = fetch_logs(search, selected)
st.dataframe(view, hide_index=True)
st.caption(f"Showing {len(view)} records")
