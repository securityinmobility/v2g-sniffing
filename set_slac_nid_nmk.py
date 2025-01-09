from enum import Enum
import sys
import os
from binascii import unhexlify
from time import sleep
from threading import Thread

from hpgp_messages.messages import build_CM_GET_KEY_REQ, build_RS_DEV_REQ

# add HomePlugPWN to sys.path to avoid import errors in HomePlugPWN files
submodule_path = os.path.join(os.path.dirname(__file__), 'external_libraries', 'HomePlugPWN')
sys.path.append(submodule_path)

from scapy.all import *
from scapy.contrib.homeplugav import HomePlugAV
from scapy.contrib.homepluggp import HomePlugGPTypes, CM_SET_KEY_REQ, CM_SET_KEY_CNF

# def send_sniffer_request(src_mac, dst_mac, interface):
#     pkt = Ether(src= src_mac, dst=dst_mac)/HomePlugAV()/SnifferRequest(SnifferControl=1)
#     sendp(pkt, iface=interface)

def find_set_key_rsp(packets, set_key_pkg, interface):
    for packet in packets:
        print('asdf')
        packet.show()
        print()
        # 24585 is the type of CM_SET_KEY.CNF
        if 'HomePlugAV' in packet and packet['HomePlugAV'].HPtype == 24585:
            print()
            nonce = int.from_bytes(packet[Raw].load[1:5], byteorder="big")
            print("Nonce: " + str(nonce))
            print()
            set_key_pkg[CM_SET_KEY_REQ].YourNonce = nonce
            sendp(set_key_pkg, iface=interface, verbose=1)
            exit(0)

def delayed_send(pkg, iface):
    sleep(2)
    sendp(pkg, iface=iface, verbose=1)

def set_key(nid, nmk, src_mac, dst_mac, interface):
    set_key_pkg = Ether(src=src_mac, dst=dst_mac) \
        / HomePlugAV(version=0x01, HPtype=0x6008) \
        / CM_SET_KEY_REQ(KeyType=0x1, MyNonce=0, YourNonce=0, PID=0x4, NetworkID=nid, NewEncKeySelect=0x1, NewKey=nmk)
    Thread(target=delayed_send, args=(set_key_pkg, interface)).start()
    sniff(iface=interface, prn=lambda packet: find_set_key_rsp(packet, set_key_pkg, interface), store=False)



def set_key_old(nid, nmk, src_mac, dst_mac, interface):
    set_key_pkg = Ether(src=src_mac, dst=dst_mac) \
        / HomePlugAV(version=0x01, HPtype=0x6008) \
        / CM_SET_KEY_REQ(KeyType=0x1, MyNonce=0xAAAAAAAA, YourNonce=0xe0218244, PID=0x4, NetworkID=nid, NewEncKeySelect=0x1, NewKey=nmk)

    resp = sr(set_key_pkg, iface=interface, verbose=1)
    # catch response from first packet to get the nonce and send a second set key with a correct nonce for success
    # TODO: get nonce from the last packet 
    resp.show()
    nonce = int.from_bytes(resp[Raw].load[1:5], byteorder="big")
    set_key_pkg[CM_SET_KEY_REQ].YourNonce = nonce
    sendp(set_key_pkg, iface=interface, verbose=1)
    # nonce = int.from_bytes(resp[Raw].load[1:5], byteorder="big")
    # set_key_pkg[CM_SET_KEY_REQ].YourNonce = nonce
    # sendp(set_key_pkg, iface=interface, verbose=1)
    print(nid, nmk, src_mac, dst_mac, interface)

if __name__ == "__main__":
    #set_key(nid=unhexlify("B0F2E695666B03"), nmk=unhexlify('50D3E4933F855B7040784DF815AA8DB7'), src_mac='7C:C2:C6:1E:C9:FD', dst_mac='c4:93:00:4f:56:bd', interface='Ethernet 7') # Ethernet 7 WLAN 4
    set_key(nid=unhexlify("ac1e434be29903"), nmk=unhexlify('2cdd639d09ea83bbb75b9a9b5f326a9a'), src_mac='7C:C2:C6:1E:C9:FD', dst_mac='c4:93:00:4f:56:bd', interface='Ethernet 7') # Ethernet 7 WLAN 4
    #set_key(nid=unhexlify("F98F3BABB6FF00"), nmk=unhexlify('3D15B9C7239B9DBB9A573C58D310355B'), src_mac='7C:C2:C6:1E:C9:FD', dst_mac='c4:93:00:4f:56:bd', interface='Ethernet 7') # Ethernet 7 WLAN 4
    

# redbeet mac c4:93:00:4f:56:bd
# eva mac 00:b0:52:00:00:01