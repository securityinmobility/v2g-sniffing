from scapy.all import sendp

def bytes_to_str_with_colon(bytes):
    return ':'.join(f'{i:02x}' for i in bytes)

def str_with_colon_to_bytes(str):
    return bytes.fromhex(str.replace(':', ''))

def str_to_bytes(str):
    return bytes.fromhex(str)

def send_packet(packet, iface):
    sendp(packet, iface=iface)