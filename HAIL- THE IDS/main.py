import streamlit as st
import pandas as pd
import os
from datetime import datetime
import plotly.express as px
from streamlit_autorefresh import st_autorefresh
from streamlit import query_params
# === CONFIG ===
CSV_PATH = 'utils/Data/threatdetection.csv'
WHITELIST_PATH = 'utils/Data/whitelist.csv'
BLOCKED_IP_PATH = 'utils/Data/blocked_ips.csv'
REFRESH_INTERVAL = 5
COMMON_BRUTE_PORTS = [22, 23, 3389, 3306, 1433]

def sev_priority(sev):
    return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(sev, 0)

# === STREAMLIT SETUP ===
st.set_page_config(page_title="Real-Time IDS", layout="wide")
st.markdown("""
    <style>
        .main { background-color: #f8f9fa; }
        .block-button { padding: 5px 10px; background-color: #ff4d4d; color: white; border: none; border-radius: 5px; }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ AI Powered Intrusion Detection System")

kpi1, kpi2, kpi3 = st.columns(3)
status = st.empty()

# === SIDEBAR SETTINGS ===
st.sidebar.header("⚙️ Detection Settings")
brute_threshold = st.sidebar.slider("Brute Force Attempts / Min", 5, 100, 30)
scan_threshold = st.sidebar.slider("Port Scan Ports / Min", 5, 200, 50)
ddos_threshold = st.sidebar.slider("DDoS Packets Threshold", 100, 5000, 1000)
ddos_unique_sources = st.sidebar.slider("DDoS Unique IPs Threshold", 2, 500, 10)
large_packet_threshold = st.sidebar.slider("Large Packet Size", 1000, 9000, 1500)
large_packet_count = st.sidebar.slider("Large Packet Count/IP", 2, 50, 10)
icmp_flood_threshold = st.sidebar.slider("ICMP Packets / Min", 50, 500, 150)
recent_minutes = st.sidebar.slider("Time Window (minutes)", 1, 60, 5)

st_autorefresh(interval=REFRESH_INTERVAL * 1000, limit=None, key="autorefresh")

@st.cache_data
def load_whitelist():
    wl = set()
    if os.path.exists(WHITELIST_PATH):
        try:
            wl.update(pd.read_csv(WHITELIST_PATH)['IP'].dropna().astype(str))
        except:
            st.sidebar.warning("Could not load whitelist.")
    wl.update(['192.168.', '10.', '172.16.'])
    return wl

@st.cache_data
def load_blocked_ips():
    if os.path.exists(BLOCKED_IP_PATH):
        return set(pd.read_csv(BLOCKED_IP_PATH)['IP'].dropna().astype(str))
    return set()

def block_ip(ip):
    blocked = load_blocked_ips()
    blocked.add(ip)
    pd.DataFrame({'IP': list(blocked)}).to_csv(BLOCKED_IP_PATH, index=False)
    st.success(f"✅ IP {ip} has been blocked.")

def clean_data(df):
    df['Time'] = pd.to_datetime(df['Time'], errors='coerce')
    df = df[df['Time'].notna()]
    for col in ['Length', 'Source_Port', 'Destination_Port']:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)
    df['Protocol'] = df.get('Protocol', '').astype(str).str.upper().str.strip()
    return df

def detect_threats(df, whitelist):
    df = clean_data(df)
    now = pd.Timestamp.now()
    recent_df = df[df['Time'] >= (now - pd.Timedelta(minutes=recent_minutes))].copy()
    if len(recent_df) == 0:
        return [], recent_df

    recent_df['Minute'] = recent_df['Time'].dt.floor('T')
    alerts_dict = {}

    # === BRUTE FORCE ===
    brute_df = recent_df[recent_df['Destination_Port'].isin(COMMON_BRUTE_PORTS)]
    bf = brute_df.groupby(['Source', 'Destination_Port', 'Minute']).size().reset_index(name='Attempts')
    bf = bf[bf['Attempts'] >= brute_threshold]
    for _, r in bf.iterrows():
        ip = r['Source']
        desc = f"Brute Force on port {r['Destination_Port']} ({r['Attempts']} attempts)"
        sev = "High"
        if any(ip.startswith(w) for w in whitelist if '.' in w): continue
        alerts_dict[ip] = {"Description": desc, "Severity": sev, "Role": "Attacker"}

    # === PORT SCAN ===
    port_scan_df = recent_df.groupby('Source')['Destination_Port'].nunique().reset_index(name='UniquePorts')
    port_scan_df = port_scan_df[port_scan_df['UniquePorts'] >= scan_threshold]
    for _, r in port_scan_df.iterrows():
        ip = r['Source']
        desc = f"Port Scan - {r['UniquePorts']} unique ports"
        sev = "High"
        if any(ip.startswith(w) for w in whitelist if '.' in w): continue
        alerts_dict[ip] = {"Description": desc, "Severity": sev, "Role": "Attacker"}

    # === DDoS ===
    target_count = recent_df['Destination'].value_counts()
    ddos_ips = target_count[target_count >= ddos_threshold].index
    for ip in ddos_ips:
        desc = f"DDoS Target - {target_count[ip]} packets"
        sev = "Critical"
        if any(ip.startswith(w) for w in whitelist if '.' in w): continue
        alerts_dict[ip] = {"Description": desc, "Severity": sev, "Role": "Victim"}

    # === Distributed DDoS ===
    ddos_target_df = recent_df.groupby('Destination')['Source'].nunique().reset_index(name='UniqueAttackers')
    ddos_target_df = ddos_target_df[ddos_target_df['UniqueAttackers'] >= ddos_unique_sources]
    for _, row in ddos_target_df.iterrows():
        victim = row['Destination']
        attackers = row['UniqueAttackers']
        desc = f"Distributed DDoS - {attackers} unique IPs targeting {victim}"
        sev = "Critical"
        if any(victim.startswith(w) for w in whitelist if '.' in w): continue
        alerts_dict[victim] = {"Description": desc, "Severity": sev, "Role": "Victim"}

    # === Large Packet Attack ===
    large_df = recent_df[recent_df['Length'] > large_packet_threshold]
    large_attackers = large_df.groupby('Source').size()
    for ip, count in large_attackers.items():
        if count >= large_packet_count and not any(ip.startswith(w) for w in whitelist if '.' in w):
            desc = f"Large Packet Attack - {count} packets"
            sev = "Medium"
            alerts_dict[ip] = {"Description": desc, "Severity": sev, "Role": "Attacker"}

    # === ICMP Flood ===
    icmp_df = recent_df[recent_df['Protocol'] == 'ICMP']
    icmp_count = icmp_df.groupby(['Source', 'Minute']).size().reset_index(name='Count')
    icmp_attacks = icmp_count[icmp_count['Count'] >= icmp_flood_threshold]
    for _, r in icmp_attacks.iterrows():
        ip = r['Source']
        desc = f"ICMP Flood - {r['Count']} packets"
        sev = "Medium"
        if any(ip.startswith(w) for w in whitelist if '.' in w): continue
        alerts_dict[ip] = {"Description": desc, "Severity": sev, "Role": "Attacker"}

    recent_df['Blocked'] = recent_df['Source'].isin(load_blocked_ips())
    alerts = [(ip, data['Description'], data['Severity'], data['Role']) for ip, data in alerts_dict.items()]
    return alerts, recent_df

# === MAIN LOGIC ===
whitelist = load_whitelist()

if not os.path.exists(CSV_PATH):
    status.warning(f"Waiting for traffic data at {CSV_PATH}...")
else:
    try:
        df = pd.read_csv(CSV_PATH)
    except Exception as e:
        status.error(f"CSV Error: {str(e)}")
        st.stop()

    alerts, recent_df = detect_threats(df, whitelist)

    kpi1.metric("📦 Total Packets", len(recent_df))
    kpi2.metric("🌐 Unique Sources", recent_df['Source'].nunique())
    kpi3.metric("⚠️ Active Threats", len(alerts))
    st.markdown("---")

    st.subheader("Threat Sources & Manual IP Blocking")
    if alerts:
        alert_df = pd.DataFrame(alerts, columns=["IP", "Description", "Severity", "Role"])
        alert_df['Severity'] = alert_df['Severity'].map({
            "Critical": "🔥 Critical",
            "High": "🚫 High",
            "Medium": "⚠️ Medium",
            "Low": "ℹ️ Low"
        })

        import urllib.parse  # Add at top if not already imported

        for i, row in alert_df.iterrows():
            col1, col2, col3, col4, col5, col6 = st.columns([3, 5, 2, 2, 2, 3])

            with col1:
                st.write(row['IP'])

            with col2:
                st.write(row['Description'])

            with col3:
                st.write(row['Severity'])

            with col4:
                st.write("🎯 " + row['Role'])

            with col5:
                if row['Role'] == "Attacker":
                    if st.button("🚫 Block", key=f"block_{row['IP']}_{i}"):
                        block_ip(row['IP'])



        with col6:
            if st.button("🤖 Analyze with AI", key=f"explain_{row['IP']}_{i}"):
                st.session_state.threat_description = row['Description']
                st.switch_page("pages/AI_Assistant.py")  # Adjust path if needed
        st.toast(f"⚠️ {len(alerts)} Threat{'s' if len(alerts)!=1 else ''} Detected!", icon="⚠️")
    else:
        st.info("✅ No major threats detected. Monitoring live traffic...")

    st.subheader("Live Traffic Flow")
    display_cols = ['Time', 'Source', 'Destination', 'Protocol', 'Length', 'Source_Port', 'Destination_Port']
    live_table = recent_df.sort_values('Time', ascending=False).head(50)
    if all(col in live_table.columns for col in display_cols):
        live_table = live_table[display_cols]

    def highlight_source_border(val):
        if val in [a[0] for a in alerts]:
            return 'border: 2px solid red;'
        return ''

    styled_df = live_table.style.applymap(highlight_source_border, subset=['Source'])
    st.dataframe(styled_df, use_container_width=True, height=450)

    st.markdown("---")
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📊 Protocol Distribution")
        if 'Protocol' in recent_df.columns:
            proto_stats = recent_df['Protocol'].value_counts().nlargest(10).reset_index()
            proto_stats.columns = ['Protocol', 'Count']
            fig = px.pie(proto_stats, names='Protocol', values='Count', hole=0.4)
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("📈 Alert Activity Timeline")
        if 'Minute' in recent_df.columns and alerts:
            threat_sources = [a[0] for a in alerts if a[3] == "Attacker"]
            timeline_df = recent_df[recent_df['Source'].isin(threat_sources)]
            timeline_df = timeline_df.groupby('Minute').size().reset_index(name='Threats')
            fig2 = px.line(timeline_df, x='Minute', y='Threats', title="Threats Over Time")
            st.plotly_chart(fig2, use_container_width=True)

    st.markdown("---")
    status.info(f"⏱ Last update: {datetime.now().strftime('%H:%M:%S')} | Monitoring last {recent_minutes} mins")
