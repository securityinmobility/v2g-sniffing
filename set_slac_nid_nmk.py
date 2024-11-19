import sys
import os

# add HomePlugPWN to sys.path to avoid import errors in HomePlugPWN files
submodule_path = os.path.join(os.path.dirname(__file__), 'external_libraries', 'HomePlugPWN')
sys.path.append(submodule_path)

from scapy.all import Ether, sendp
from scapy.contrib.homeplugav import HomePlugAV
from external_libraries.HomePlugPWN.layerscapy.HomePlugGP import CM_SET_KEY_REQ



def set_key(nid, nmk, src_mac, dst_mac, interface):
    # build set key message in different layers
    ethLayer = Ether(src= src_mac, dst=dst_mac)

    homePlugAVLayer = HomePlugAV()
    homePlugAVLayer.version = 0x01

    homePlugLayer = CM_SET_KEY_REQ()
    homePlugLayer.KeyType = 0x1
    homePlugLayer.MyNonce = 0xAAAAAAAA
    homePlugLayer.YourNonce = 0x00000000
    homePlugLayer.PID = 0x4
    homePlugLayer.NetworkID = nid
    homePlugLayer.NewEncKeySelect = 0x1
    homePlugLayer.NewKey = nmk

    responsePacket = ethLayer / homePlugAVLayer / homePlugLayer

    sendp(responsePacket, iface=interface, verbose=0) # send message with no output (verbose 0)


# if __name__ == "__main__":
#     set_key(nid='01:02:03:04:05:06:07', nmk='50D3E4933F855B7040784DF815AA8DB7', src_mac='F4:A8:0D:58:FD:04', dst_mac='c0:ff:ee:c0:ff:ee', interface='Ethernet 5')
