from scapy.all import rdpcap, sniff, sendp, Ether
from scapy.contrib.homeplugav import QualcommTypeList
from optparse import OptionParser
#from set_slac_nid_nmk import set_key
from scapy.contrib.homeplugav import HomePlugAV
from scapy.contrib.homepluggp import HomePlugGPTypes, CM_SET_KEY_REQ

def set_key(nid, nmk, src_mac, dst_mac, interface):
    set_key_pkg = Ether(src=src_mac, dst=dst_mac) \
        / HomePlugAV(version=0x01, HPtype=0x6008) \
        / CM_SET_KEY_REQ(KeyType=0x1, MyNonce=0xAAAAAAAA, YourNonce=0xe0218244, PID=0x4, NetworkID=nid, NewEncKeySelect=0x1, NewKey=nmk)

    # send the packet two times -> the first time the response is a failure for some reason
    sendp(set_key_pkg, iface=interface, verbose=1)
    sendp(set_key_pkg, iface=interface, verbose=1)

# check if the packet contains CM_SLAC_MATCH.CNF
def extract_load_if_cm_slac_match_cnf(packets, set_key_on_modem: bool, interface, src_mac, dst_mac):
    for packet in packets:
        # 24701 is the type of CM_SLAC_MATCH.CNF
        if 'HomePlugAV' in packet and packet['HomePlugAV'].HPtype == 24701:
            print()
            nid = packet['CM_SLAC_MATCH_CNF']['SLAC_varfield'].NetworkID
            print("NID: " + ':'.join(f'{byte:02X}' for byte in nid))
            print("NID: " + ''.join(f'{byte:02X}' for byte in nid))
            print()
            nmk = packet['CM_SLAC_MATCH_CNF']['SLAC_varfield'].NMK
            print("NMK: " + ':'.join(f'{byte:02X}' for byte in nmk))
            print("NMK: " + ''.join(f'{byte:02X}' for byte in nmk))
            print()

            if set_key_on_modem:
                print(f"Setting key on destination {dst_mac}")
                set_key(nid, nmk, src_mac, dst_mac, interface)
            exit(0)

def extract_nid_nmk_from_load(load):
    nmk = load[-16:] # last 16 bytes of load is the nmk
    # nmk_readable = ''.join(f'{byte:02X}' for byte in nmk) # konvert into readable hex
    print("NMK: " + ':'.join(f'{byte:02X}' for byte in nmk))
    print("NMK: " + ''.join(f'{byte:02X}' for byte in nmk))
    nid = load[-24:-17] # 8 bytes before nmk and remove last byte -> nid
    # nid_readable = ':'.join(f'{byte:02X}' for byte in nid) # konvert into readable hex
    print("NID: " + ':'.join(f'{byte:02X}' for byte in nid))
    print("NID: " + ''.join(f'{byte:02X}' for byte in nid))
    return(nid, nmk)


# sniff(iface='Ethernet 7', prn=lambda packet: extract_load_if_cm_slac_match_cnf(packet, True, 'Ethernet 7', '7C:C2:C6:1E:C9:FD', 'c4:93:00:4f:56:bd'), store=False)


if __name__ =="__main__":
    usage = "usage: %prog [options] \nUse either the interface or the file attribute to extract the NID and NMK of the CM_SLAC_MATCH.CNF message."
    parser = OptionParser(usage)
    parser.add_option("-k", "--keyset", action="store_true", help="Flag to set the NID and NMK after extracting it.", metavar="KEYSET")
    parser.add_option("-i", "--interface", help="Interface to listen for CM_SLAC_MATCH.CNF message for extracting the NID and NMK. Required if -k or --keyset flag is set.", metavar="INTERFACE")
    parser.add_option("-f", "--file", help="Pcap file to extract the NID and NMK from the CM_SLAC_MATCH.CNF message", metavar="FILE")
    parser.add_option("-s", "--sourcemac", default="c0:ff:ee:c0:ff:ee", help="MAC Address from which the set key message ist sent. Default Value is c0:ff:ee:c0:ff:ee", metavar="SOURCEMAC")
    parser.add_option("-d", "--destinationmac", help="MAC Address to which the set_key message ist sent. Required if the -k or --keyset flag is set.", metavar="DESTINATIONMAC")
    (options, _) = parser.parse_args()

    set_key_after_sniffing = False
    if options.keyset:
        if not(options.interface):
            print("For setting the NID and NMK (activated with flag -k or --keyset), the interface must be specified.")
            exit(1)
        if not(options.destinationmac):
            print("For setting the NID and NMK (activated with flag -k or --keyset), the destination mac address must be specified.")
        set_key_after_sniffing = True

    if bool(options.interface) == bool(options.file):
        parser.error("You must specify exactly one option: interface or file.")

    if options.file:
        packets = rdpcap(options.file)
        for packet in packets:
            extract_load_if_cm_slac_match_cnf(packet, set_key_after_sniffing) # TODO wieder alle parameter umbauen
    else:
        sniff(iface=options.interface, prn=lambda packet: extract_load_if_cm_slac_match_cnf(packet, set_key_after_sniffing, options.interface, options.sourcemac, options.destinationmac), store=False)

# python3 find_nid_nmk.py -i '...' -s '...' -d 'c4:93:00:4f:56:bd' -k
# redbeet mac c4:93:00:4f:56:bd
# eva mac 00:b0:52:00:00:01