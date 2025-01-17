from time import sleep
from scapy.all import *
from scapy.layers.inet6 import IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr

# Set your MAC address and IPv6 address here
mac_source = "98:ed:5c:93:0d:65"  # Replace with your desired MAC address

# Send the packet
while True:
    # Create the Ethernet frame
    eth = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac_source)
    ip = IP(dst="43.43.43.43", src="13.38.13.38")

    # Construct the final packet
    packet = eth / ip
    sendp(packet, iface="eth0")  # Replace eth0 with your network interface
    sleep(0.2)
