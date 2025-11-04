import streamlit as st
import sqlite3
import pandas as pd
import folium
from streamlit_folium import st_folium
import plotly.express as px
import json
import os

# --- Page & App Configuration ---
st.set_page_config(page_title="NTAVis Dashboard", layout="wide", page_icon="🌐")

# --- Constants & Mappings ---
DB_PATH = "/home/hadifshah/NTAVisProject/packets.db"
PROTOCOL_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP"}
USER_DATA_FILE = "user_data.json"

# --- Helper Function for CSV Download ---
@st.cache_data
def convert_df_to_csv(df):
    return df.to_csv(index=False).encode('utf-8')

# --- Data Loading ---
@st.cache_data(ttl=10)
def get_data():
    try:
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
        df = pd.read_sql_query("SELECT * FROM packets", conn)
        conn.close()
        if "protocol" in df.columns:
            df["protocol"] = df["protocol"].apply(lambda x: PROTOCOL_MAP.get(int(x), str(x)) if pd.notnull(x) else "Unknown")
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df
    except Exception:
        return pd.DataFrame()

# --- Login Page ---
def login_page():
    col1, col2, col3 = st.columns([1, 1.2, 1])
    with col2:
        st.title("NTAVis Dashboard")
        st.markdown("Please sign in to continue.")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            if password == st.secrets["login"]["password"]:
                st.session_state.logged_in = True
                st.success("Login successful!")
                st.experimental_rerun()
            else:
                st.error("❌ Incorrect password.")

# --- Main Dashboard ---
def main_dashboard():
    st.sidebar.title(f"Welcome, {st.secrets['login']['username']}!")
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.experimental_rerun()

    st.sidebar.markdown("---")
    menu = st.sidebar.radio("📋 Menu", ["📊 Overview", "🗺️ Geo Map", "📈 Analytics"])
    
    df = get_data()

    if df.empty:
        st.warning("No packet data found. Is the capture script running?")
        return

    # --- Overview ---
    if menu == "📊 Overview":
        st.markdown("## 📊 Threat Overview")
        threat_counts = df["threat_type"].value_counts()
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("🕵️ Suspicious", int(threat_counts.get("Suspicious", 0)))
        col2.metric("⚠️ Malformed", int(threat_counts.get("Malformed", 0)))
        col3.metric("🌊 SYN Flood", int(threat_counts.get("SYN Flood", 0)))
        col4.metric("💧 UDP Flood", int(threat_counts.get("UDP Flood", 0)))
        st.markdown("---")
        st.subheader("📂 Raw Packet Data")
        st.dataframe(df.tail(1000), use_container_width=True)

    # --- Geo Map ---
    elif menu == "🗺️ Geo Map":
        st.markdown("## 🗺️ Threat Source Map")
        map_df = df.dropna(subset=["latitude", "longitude"])
        if not map_df.empty:
            avg_lat, avg_lon = map_df["latitude"].mean(), map_df["longitude"].mean()
            m = folium.Map(location=[avg_lat, avg_lon], zoom_start=2, tiles="CartoDB positron")
            for _, row in map_df.iterrows():
                folium.CircleMarker(
                    location=[row["latitude"], row["longitude"]],
                    radius=5, color="red", fill=True, fill_color="red",
                    popup=f"IP: {row['src_ip']}<br>Threat: {row['threat_type']}"
                ).add_to(m)
            st_folium(m, use_container_width=True, height=600)
        else:
            st.info("No geolocation data to display on the map.")

    # --- Analytics ---
    elif menu == "📈 Analytics":
        st.markdown("## 📈 Analytics Dashboard")
        config = {'toImageButtonOptions': {'format': 'png', 'scale': 2}}

        st.markdown("#### Traffic Composition")
        col1, col2 = st.columns(2)
        with col1:
            threat_counts_df = df["threat_type"].value_counts().reset_index()
            fig1 = px.bar(threat_counts_df, x="threat_type", y="count", title="Threats by Type", labels={'threat_type':'Threat Type'})
            st.plotly_chart(fig1, use_container_width=True, config=config)
            st.download_button("Download Data as CSV", convert_df_to_csv(threat_counts_df), "threats_by_type.csv", "text/csv")
        with col2:
            protocol_counts_df = df["protocol"].value_counts().reset_index()
            fig2 = px.pie(protocol_counts_df, names="protocol", values="count", title="Protocol Distribution")
            st.plotly_chart(fig2, use_container_width=True, config=config)
            st.download_button("Download Data as CSV", convert_df_to_csv(protocol_counts_df), "protocol_dist.csv", "text/csv")

        st.markdown("---")
        st.markdown("#### Top IP Addresses")
        col3, col4 = st.columns(2)
        with col3:
            top_src_ips_df = df['src_ip'].value_counts().nlargest(10).reset_index()
            fig3 = px.bar(top_src_ips_df, x='src_ip', y='count', title="Top 10 Source IPs")
            st.plotly_chart(fig3, use_container_width=True, config=config)
            st.download_button("Download Data as CSV", convert_df_to_csv(top_src_ips_df), "top_source_ips.csv", "text/csv")
        with col4:
            top_dst_ips_df = df['dst_ip'].value_counts().nlargest(10).reset_index()
            fig4 = px.bar(top_dst_ips_df, x='dst_ip', y='count', title="Top 10 Destination IPs")
            st.plotly_chart(fig4, use_container_width=True, config=config)
            st.download_button("Download Data as CSV", convert_df_to_csv(top_dst_ips_df), "top_dest_ips.csv", "text/csv")

# --- Run App ---
if __name__ == "__main__":
    if "login" not in st.secrets:
        st.error("CRITICAL: Your .streamlit/secrets.toml file is missing or incomplete.")
    else:
        if "logged_in" not in st.session_state:
            st.session_state.logged_in = False
        
        if st.session_state.logged_in:
            main_dashboard()
        else:
            login_page()
