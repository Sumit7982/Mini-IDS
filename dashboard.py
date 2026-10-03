import streamlit as st
import sqlite3
import pandas as pd


# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="Mini IDS Dashboard",
    page_icon="🛡️",
    layout="wide"
)


# ==========================================
# GET ALERTS
# ==========================================

def get_alerts():

    connection = sqlite3.connect(
        "ids_alerts.db"
    )

    data = pd.read_sql_query(
        """
        SELECT *
        FROM alerts
        ORDER BY id DESC
        """,
        connection
    )

    connection.close()

    return data


# ==========================================
# GET PACKET STATISTICS
# ==========================================

def get_packet_stats():

    connection = sqlite3.connect(
        "ids_alerts.db"
    )

    data = pd.read_sql_query(
        """
        SELECT *
        FROM packet_stats
        ORDER BY id DESC
        LIMIT 1
        """,
        connection
    )

    connection.close()

    return data


# ==========================================
# DASHBOARD TITLE
# ==========================================

st.title(
    "🛡️ Mini Intrusion Detection System"
)

st.write(
    "Real-Time Network Security Monitoring Dashboard"
)


# ==========================================
# LIVE DASHBOARD
# ==========================================

@st.fragment(run_every="10s")
def live_dashboard():


    # ======================================
    # LOAD DATA
    # ======================================

    alerts = get_alerts()

    stats = get_packet_stats()


    # ======================================
    # ALERT COUNTS
    # ======================================

    total_alerts = len(alerts)


    if not alerts.empty:

        high_alerts = len(
            alerts[
                alerts["severity"] == "High"
            ]
        )

        medium_alerts = len(
            alerts[
                alerts["severity"] == "Medium"
            ]
        )

        low_alerts = len(
            alerts[
                alerts["severity"] == "Low"
            ]
        )

    else:

        high_alerts = 0

        medium_alerts = 0

        low_alerts = 0


    # ======================================
    # PACKET COUNTS
    # ======================================

    if not stats.empty:

        total_packets = int(
            stats.iloc[0]["total_packets"]
        )

        tcp_packets = int(
            stats.iloc[0]["tcp_packets"]
        )

        udp_packets = int(
            stats.iloc[0]["udp_packets"]
        )

        icmp_packets = int(
            stats.iloc[0]["icmp_packets"]
        )

        other_packets = int(
            stats.iloc[0]["other_packets"]
        )

    else:

        total_packets = 0

        tcp_packets = 0

        udp_packets = 0

        icmp_packets = 0

        other_packets = 0


    # ======================================
    # SECURITY ALERTS
    # ======================================

    st.subheader(
        "🚨 Security Alerts"
    )


    col1, col2, col3, col4 = st.columns(4)


    with col1:

        st.metric(
            "Total Alerts",
            total_alerts
        )


    with col2:

        st.metric(
            "High Severity",
            high_alerts
        )


    with col3:

        st.metric(
            "Medium Severity",
            medium_alerts
        )


    with col4:

        st.metric(
            "Low Severity",
            low_alerts
        )


    # ======================================
    # NETWORK TRAFFIC
    # ======================================

    st.subheader(
        "📦 Network Traffic"
    )


    col1, col2, col3, col4, col5 = st.columns(5)


    with col1:

        st.metric(
            "Total Packets",
            total_packets
        )


    with col2:

        st.metric(
            "TCP",
            tcp_packets
        )


    with col3:

        st.metric(
            "UDP",
            udp_packets
        )


    with col4:

        st.metric(
            "ICMP",
            icmp_packets
        )


    with col5:

        st.metric(
            "Other",
            other_packets
        )


    # ======================================
    # LAST UPDATE
    # ======================================

    if not stats.empty:

        st.caption(
            "Last statistics update: "
            + str(
                stats.iloc[0]["timestamp"]
            )
        )


    # ======================================
    # SEVERITY DISTRIBUTION
    # ======================================

    if not alerts.empty:

        st.subheader(
            "📊 Alert Severity Distribution"
        )


        severity_data = pd.DataFrame({

            "Severity": [
                "High",
                "Medium",
                "Low"
            ],

            "Alerts": [
                high_alerts,
                medium_alerts,
                low_alerts
            ]

        })


        st.bar_chart(
            severity_data,
            x="Severity",
            y="Alerts",
            width="stretch"
        )


    # ======================================
    # ALERT TYPE STATISTICS
    # ======================================

    if not alerts.empty:

        st.subheader(
            "🔎 Alert Type Statistics"
        )


        alert_counts = (
            alerts["alert_type"]
            .value_counts()
        )


        st.bar_chart(
            alert_counts,
            width="stretch"
        )


    # ======================================
    # TOP SOURCE IPs
    # ======================================

    if not alerts.empty:

        st.subheader(
            "🌐 Top Source IP Addresses"
        )


        source_counts = (
            alerts["source_ip"]
            .value_counts()
            .head(10)
        )


        st.bar_chart(
            source_counts,
            width="stretch",
            horizontal=True
        )


    # ======================================
    # PROTOCOL DISTRIBUTION
    # ======================================

    protocol_data = pd.DataFrame({

        "Protocol": [
            "TCP",
            "UDP",
            "ICMP",
            "Other"
        ],

        "Packets": [
            tcp_packets,
            udp_packets,
            icmp_packets,
            other_packets
        ]

    })


    st.subheader(
        "📡 Protocol Distribution"
    )


    st.bar_chart(
        protocol_data,
        x="Protocol",
        y="Packets",
        width="stretch"
    )


    # ======================================
    # RECENT ALERTS
    # ======================================

    st.subheader(
        "🚨 Recent Security Alerts"
    )


    if alerts.empty:

        st.info(
            "No security alerts have been recorded yet."
        )

    else:

        recent_alerts = alerts.head(20)


        st.dataframe(
            recent_alerts,
            width="stretch",
            hide_index=True
        )


# ==========================================
# RUN DASHBOARD
# ==========================================

live_dashboard()