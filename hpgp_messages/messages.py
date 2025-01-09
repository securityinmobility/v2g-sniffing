from external_libraries.HomePlugPWN.layerscapy.HomePlugAV import *
from scapy.all import Ether
from scapy.contrib.homeplugav import HomePlugAV

class CM_GET_KEY_REQ(Packet):
    name = "CM_GET_KEY_REQ"
    fields_desc = [
        ByteField("KeyType", 0x01),  # Key type (e.g., NMK (AES-128))
        ByteField("KeyIndex", 0x00),  # Key index (e.g., 0 for default)
        StrFixedLenField("MACAddress", b"\x00" * 6, 6),  # MAC address
        StrFixedLenField("Padding", b"\x00" * 10, 10)  # Padding bytes
    ]

def build_CM_GET_KEY_REQ(src_mac, dst_mac):
    ethLayer = Ether(src = src_mac, dst = dst_mac)
    
    homePlugAVLayer = HomePlugAV()
    homePlugAVLayer.version = 0x01
    homePlugAVLayer.HPtype = 0x600c

    homePlugLayer = CM_GET_KEY_REQ()

    return (ethLayer / homePlugAVLayer / homePlugLayer)


# Reset Device Request
class RS_DEV_REQ(Packet):
    name = "RS_DEV_REQ"
    fields_desc = [
        ByteField("Reserved", 0x00),  # Reserved byte, typically unused but part of the spec
        StrFixedLenField("Padding", b"\x00" * 6, 6)  # Padding bytes to align the packet
    ]

def build_RS_DEV_REQ(src_mac, dst_mac): 
    # build set key message in different layers
    ethLayer = Ether(src= src_mac, dst=dst_mac)

    # version 0x00 and hptype 0xa01c => RS_DEV.REQ -> Reset Device Request
    homePlugAVLayer = HomePlugAV()
    homePlugAVLayer.version = 0x00
    homePlugAVLayer.HPtype = 0xa01c

    homePlugLayer = RS_DEV_REQ()

    return (ethLayer / homePlugAVLayer / homePlugLayer)
    