from scapy.all import Ether,sendp, sniff, TCP, UDP, Packet
from scapy.contrib.homeplugav import HomePlugAV
from scapy.contrib.homepluggp import CM_SET_KEY_REQ
from optparse import OptionParser

def set_key_on_modem(nid, nmk, srcmac, dstmac, interface):
    set_key_pkg = Ether(src=srcmac, dst=dstmac) \
        / HomePlugAV(version=0x01, HPtype=0x6008) \
        / CM_SET_KEY_REQ(KeyType=0x1, MyNonce=0xAAAAAAAA, YourNonce=0xe0218244, PID=0x4, NetworkID=nid, NewEncKeySelect=0x1, NewKey=nmk)

    # send packet twice -> first time the response is a failure for some reason
    print("setting key on " + dstmac + " over " + interface)
    sendp(set_key_pkg, iface=interface, verbose=0)
    sendp(set_key_pkg, iface=interface, verbose=0)

def handle_cm_slac_match_cnf(packet, src_mac, dst_mac1, iface1, dst_mac2 = None, iface2 = None):
    nid = packet['CM_SLAC_MATCH_CNF']['SLAC_varfield'].NetworkID
    nmk = packet['CM_SLAC_MATCH_CNF']['SLAC_varfield'].NMK
    
    print('found CM_SLAC_MATCH_CNF message')
    print("NID: " + ':'.join(f'{byte:02X}' for byte in nid))
    print("NID: " + ''.join(f'{byte:02X}' for byte in nid))
    print()
    print("NMK: " + ':'.join(f'{byte:02X}' for byte in nmk))
    print("NMK: " + ''.join(f'{byte:02X}' for byte in nmk))

    set_key_on_modem(nid, nmk, src_mac, dst_mac1, iface1)
    if (dst_mac2 and iface2):
        set_key_on_modem(nid, nmk, src_mac, dst_mac2, iface2)

def handle_packet(packet, our_mac, iface1, modem_mac1, iface2 = None, modem_mac2 = None):
    global evse_mac, pev_mac

    if 'HomePlugAV' in packet and packet['HomePlugAV'].HPtype == 0x607d:
        handle_cm_slac_match_cnf(packet, our_mac, modem_mac1, iface1, modem_mac2, iface2)
        print("keys are set")
        exit(0)


if __name__ =="__main__":
    usage = "usage: %prog [options] \nUse this program to extract the NID and NMK of the CM_SLAC_MATCH.CNF message and set them on one or two powerline modems."
    parser = OptionParser(usage)
    parser.add_option("-y", "--yourmac", help="Your MAC Address of the given Interface", metavar="YOURMAC")
    parser.add_option("-i", "--pev_modem_interface", help="Interface where the first powerline modem is connected. This interface is used to sniff for the CM_SLAC_MATCH.CNF, so it should be a PEV Modem connected.", metavar="INTERFACE1")
    parser.add_option("-m", "--pevmodemmac", help="MAC Address of the first modem, to which the set_key message ist sent", metavar="MODEMMAC1")
    parser.add_option("-I", "--evse_modem_interface", help="Interface where the second powerline modem is connected (optional)", metavar="INTERFACE2")
    parser.add_option("-M", "--evsemodemmac", help="MAC Address of the second modem, to which the set_key message ist sent (optional)", metavar="MODEMMAC2")
    (options, _) = parser.parse_args()

    modemmac2 = None
    iface2 = None

    if not(options.interface1):
        print("The interface must be specified.")
        exit(1)
    if not(options.modemmac1):
        print("The modem 1 mac must be specified.")
        exit(1)
    if not(options.yourmac):
        print("Your own mac must be specified.")
        exit(1)
    if options.interface2 and options.modemmac2:
        iface2 = options.interface2
        modemmac2 = options.modemmac2
    
    print("starting to sniff for a CM_SLAC_MATCH_CNF")
    sniff(iface=options.interface1, prn=lambda packet: handle_packet(packet, options.yourmac, options.interface1, options.modemmac1, iface2, modemmac2), store=False)
