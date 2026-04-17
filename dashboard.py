import streamlit as st
import pandas as pd
import json
import os

st.set_page_config(page_title="Chakshu SIEM", layout="wide", page_icon="👁️")

st.title("👁️ Chakshu | Fusion Engine Dashboard")
st.markdown("Real-time telemetry, cross-layer correlation, and XAI payload forensics.")

data_path = "data/processed/alerts.json"

@st.cache_data(ttl=5)
def load_data():
    if not os.path.exists(data_path):
        return pd.DataFrame()
    with open(data_path, "r") as f:
        data = json.load(f)
    df = pd.DataFrame(data)
    if not df.empty:
        # We add format='ISO8601' here to handle the mixed microsecond precision
        df['ts'] = pd.to_datetime(df['ts'], format='ISO8601')
        df = df.sort_values(by='ts', ascending=False)
    return df

df = load_data()

if df.empty:
    st.warning(f"No alerts detected. Please ensure {data_path} exists and contains data.")
else:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Anomalies", len(df))
    c2.metric("Unique Attacker IPs", df['src_ip'].nunique())
    c3.metric("Gateway Alerts (Auth)", len(df[df['tag'].str.contains("AUTH")]))
    c4.metric("Critical Scores (> 0.8)", len(df[df['score'] >= 0.8]))

    st.divider()

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Anomalies by Specialist")
        tag_counts = df['tag'].value_counts()
        st.bar_chart(tag_counts, color="#ff4b4b")

    with col2:
        st.subheader("Top Attacking Origin IPs")
        ip_counts = df['src_ip'].value_counts().head(5)
        st.bar_chart(ip_counts, color="#ffa421")

    st.divider()

    st.subheader("XAI Forensic Feed")
    
    f_col1, f_col2 = st.columns([1, 3])
    with f_col1:
        selected_tag = st.selectbox("Filter by Specialist", ["ALL"] + list(df['tag'].unique()))
    
    filtered_df = df if selected_tag == "ALL" else df[df['tag'] == selected_tag]

    for _, row in filtered_df.head(100).iterrows():
        severity_icon = "🔴" if row['score'] > 0.7 else "🟠"
        
        with st.expander(f"{severity_icon} [{row['tag']}] IP: {row['src_ip']} | Correlation Score: {row['score']}", expanded=False):
            st.caption(f"**Timestamp:** {row['ts']}")
            
            st.text("Raw Payload / Telemetry:")
            st.code(row['payload'], language="bash")
            
            st.markdown("**XAI Extracted Evidence (Structural Entropy / Key N-Grams):**")
            
            if isinstance(row['forensics'], list):
                evidence_tags = " ".join([f"`{ev}`" for ev in row['forensics']])
                st.markdown(evidence_tags)
            else:
                st.write("No distinct features isolated.")
