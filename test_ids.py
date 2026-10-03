from scapy.all import IP, TCP, send
import time


print("Starting IDS test...")
print("Sending test SYN packets to localhost")


for port in range(1, 16):

    packet = IP(
        dst="127.0.0.1"
    ) / TCP(
        dport=port,
        flags="S"
    )

    send(
        packet,
        verbose=False
    )

    print(
        "Sent SYN packet to port:",
        port
    )

    time.sleep(0.2)


print()
print("Test completed.")