from scapy.all import sniff, IP, TCP, UDP, ICMP
import time
import sqlite3
import ipaddress


# =========================================
# DATABASE CONNECTION
# =========================================

connection = sqlite3.connect("ids_alerts.db")
cursor = connection.cursor()


# =========================================
# CREATE ALERTS TABLE
# =========================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    source_ip TEXT,
    alert_type TEXT,
    severity TEXT
)
""")


# =========================================
# CREATE PACKET STATISTICS TABLE
# =========================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS packet_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    total_packets INTEGER,
    tcp_packets INTEGER,
    udp_packets INTEGER,
    icmp_packets INTEGER,
    other_packets INTEGER
)
""")

connection.commit()


# =========================================
# TRACKING VARIABLES
# =========================================

# Track normal port scans
ip_ports = {}

# Track SYN scans
syn_tracker = {}

# Prevent the same alert from being generated repeatedly
last_alert_time = {}

# Alert cooldown = 60 seconds
ALERT_COOLDOWN = 60


# =========================================
# PACKET COUNTERS
# =========================================

packet_count = 0
tcp_count = 0
udp_count = 0
icmp_count = 0
other_count = 0

last_stats_save = time.time()


# =========================================
# CHECK SPECIAL DESTINATION
# =========================================

def is_special_destination(ip):

    try:

        address = ipaddress.ip_address(ip)

        # Ignore multicast traffic
        if address.is_multicast:
            return True

        # Ignore broadcast traffic
        if ip == "255.255.255.255":
            return True

        return False

    except ValueError:

        return False


# =========================================
# DETERMINE ALERT SEVERITY
# =========================================

def get_severity(port_count):

    if port_count >= 10:
        return "High"

    elif port_count >= 8:
        return "Medium"

    elif port_count >= 5:
        return "Low"

    return None


# =========================================
# SAVE ALERT TO DATABASE
# =========================================

def save_alert(source_ip, alert_type, severity):

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
    INSERT INTO alerts
    (
        timestamp,
        source_ip,
        alert_type,
        severity
    )
    VALUES (?, ?, ?, ?)
    """, (
        timestamp,
        source_ip,
        alert_type,
        severity
    ))

    connection.commit()

    print("🚨 ALERT SAVED TO DATABASE")


# =========================================
# SAVE PACKET STATISTICS
# =========================================

def save_statistics():

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
    INSERT INTO packet_stats
    (
        timestamp,
        total_packets,
        tcp_packets,
        udp_packets,
        icmp_packets,
        other_packets
    )
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        packet_count,
        tcp_count,
        udp_count,
        icmp_count,
        other_count
    ))

    connection.commit()

    print("📊 PACKET STATISTICS SAVED")


# =========================================
# PACKET CALLBACK
# =========================================

def packet_callback(packet):

    global packet_count
    global tcp_count
    global udp_count
    global icmp_count
    global other_count
    global last_stats_save


    # -----------------------------------------
    # COUNT EVERY PACKET
    # -----------------------------------------

    packet_count += 1


    # -----------------------------------------
    # CHECK FOR IP PACKET
    # -----------------------------------------

    if IP not in packet:

        other_count += 1

        return


    # -----------------------------------------
    # GET SOURCE AND DESTINATION IP
    # -----------------------------------------

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst


    # =========================================
    # TCP PACKET
    # =========================================

    if TCP in packet:

        tcp_count += 1

        destination_port = packet[TCP].dport

        protocol = "TCP"


        # -----------------------------------------
        # GET TCP FLAGS
        # -----------------------------------------

        tcp_flags = packet[TCP].flags


        # =========================================
        # SYN SCAN DETECTION
        # =========================================

        # SYN packet without ACK
        if "S" in tcp_flags and "A" not in tcp_flags:

            current_time = time.time()


            # -----------------------------------------
            # CREATE SOURCE ENTRY
            # -----------------------------------------

            if source_ip not in syn_tracker:

                syn_tracker[source_ip] = []


            # -----------------------------------------
            # ADD SYN PORT
            # -----------------------------------------

            syn_tracker[source_ip].append(
                (destination_port, current_time)
            )


            # -----------------------------------------
            # REMOVE OLD ENTRIES
            # -----------------------------------------

            syn_tracker[source_ip] = [

                (port, timestamp)

                for port, timestamp in syn_tracker[source_ip]

                if current_time - timestamp <= 10

            ]


            # -----------------------------------------
            # FIND UNIQUE SYN PORTS
            # -----------------------------------------

            unique_syn_ports = set()

            for port, timestamp in syn_tracker[source_ip]:

                unique_syn_ports.add(port)


            print(
                "SYN Ports/10 sec :",
                len(unique_syn_ports)
            )


            # -----------------------------------------
            # DETERMINE SEVERITY
            # -----------------------------------------

            syn_severity = get_severity(
                len(unique_syn_ports)
            )


            # -----------------------------------------
            # GENERATE SYN SCAN ALERT
            # -----------------------------------------

            if syn_severity is not None:

                syn_key = source_ip + "_syn"

                last_alert = last_alert_time.get(
                    syn_key,
                    0
                )


                # -----------------------------------------
                # CHECK ALERT COOLDOWN
                # -----------------------------------------

                if current_time - last_alert >= ALERT_COOLDOWN:

                    print()
                    print("⚠ POSSIBLE SYN SCAN DETECTED!")
                    print("Source IP:", source_ip)
                    print("Severity:", syn_severity)


                    save_alert(
                        source_ip,
                        "Possible SYN Scan",
                        syn_severity
                    )


                    last_alert_time[syn_key] = current_time


    # =========================================
    # UDP PACKET
    # =========================================

    elif UDP in packet:

        udp_count += 1

        destination_port = packet[UDP].dport

        protocol = "UDP"


    # =========================================
    # ICMP PACKET
    # =========================================

    elif ICMP in packet:

        icmp_count += 1

        print("--------------------------------")
        print("Source IP      :", source_ip)
        print("Destination IP :", destination_ip)
        print("Protocol       :", "ICMP")


        current_time = time.time()


        # Save statistics every 10 seconds
        if current_time - last_stats_save >= 10:

            save_statistics()

            last_stats_save = current_time


        return


    # =========================================
    # OTHER PACKET
    # =========================================

    else:

        other_count += 1

        return


    # =========================================
    # PORT SCAN TRACKING
    # =========================================

    current_time = time.time()


    # Check multicast/broadcast
    special_destination = is_special_destination(
        destination_ip
    )


    # -----------------------------------------
    # CREATE SOURCE ENTRY
    # -----------------------------------------

    if source_ip not in ip_ports:

        ip_ports[source_ip] = {}


    # -----------------------------------------
    # CREATE DESTINATION ENTRY
    # -----------------------------------------

    if destination_ip not in ip_ports[source_ip]:

        ip_ports[source_ip][destination_ip] = []


    # -----------------------------------------
    # ADD PORT
    # -----------------------------------------

    ip_ports[source_ip][destination_ip].append(
        (
            destination_port,
            current_time
        )
    )


    # -----------------------------------------
    # REMOVE PORTS OLDER THAN 10 SECONDS
    # -----------------------------------------

    ip_ports[source_ip][destination_ip] = [

        (port, timestamp)

        for port, timestamp
        in ip_ports[source_ip][destination_ip]

        if current_time - timestamp <= 10

    ]


    # -----------------------------------------
    # FIND UNIQUE PORTS
    # -----------------------------------------

    unique_ports = set()

    for port, timestamp in ip_ports[source_ip][destination_ip]:

        unique_ports.add(port)


    # =========================================
    # DISPLAY PACKET INFORMATION
    # =========================================

    print("--------------------------------")

    print(
        "Source IP       :",
        source_ip
    )

    print(
        "Destination IP  :",
        destination_ip
    )

    print(
        "Protocol        :",
        protocol
    )

    print(
        "Destination Port:",
        destination_port
    )

    print(
        "Ports/10 sec    :",
        len(unique_ports)
    )


    # =========================================
    # PORT SCAN DETECTION
    # =========================================

    if not special_destination:

        port_count = len(unique_ports)


        # Determine severity
        severity = get_severity(
            port_count
        )


        # -----------------------------------------
        # IF SCAN DETECTED
        # -----------------------------------------

        if severity is not None:

            scan_key = (
                source_ip
                + "_"
                + destination_ip
            )


            last_alert = last_alert_time.get(
                scan_key,
                0
            )


            # -----------------------------------------
            # ALERT COOLDOWN
            # -----------------------------------------

            if current_time - last_alert >= ALERT_COOLDOWN:

                print()
                print(
                    "⚠ POSSIBLE PORT SCAN DETECTED!"
                )

                print(
                    "Source IP:",
                    source_ip
                )

                print(
                    "Destination IP:",
                    destination_ip
                )

                print(
                    "Severity:",
                    severity
                )


                save_alert(
                    source_ip,
                    "Possible Port Scan",
                    severity
                )


                last_alert_time[
                    scan_key
                ] = current_time


    # =========================================
    # SAVE STATISTICS EVERY 10 SECONDS
    # =========================================

    if current_time - last_stats_save >= 10:

        save_statistics()

        last_stats_save = current_time


# =========================================
# START IDS
# =========================================

print("===================================")
print("       🛡️ MINI IDS STARTED")
print("===================================")

print(
    "Monitoring network traffic..."
)

print(
    "Interface: Npcap Loopback"
)

print()


# =========================================
# START PACKET CAPTURE
# =========================================

sniff(
    iface=r"\Device\NPF_Loopback",
    prn=packet_callback
)