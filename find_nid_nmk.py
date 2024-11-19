from scapy.all import rdpcap, sniff
from scapy.contrib.homeplugav import QualcommTypeList
from optparse import OptionParser
from set_slac_nid_nmk import set_key


# check if the packet contains CM_SLAC_MATCH.CNF
def extract_load_if_cm_slac_match_cnf(packets, set_key_on_modem: bool, interface, src_mac, dst_mac):
    for packet in packets:
        if 'HomePlugAV' in packet and packet['HomePlugAV'].HPtype == 24701:  # 24701 is the type of CM_SLAC_MATCH.CNF
            nid, nmk = extract_nid_nmk_from_load(packet['HomePlugAV'].load)
            print(f"Found NID: {nid} and NMK: {nmk}")
            if set_key_on_modem:
                print("Setting key on destination {dst_mac}")
                set_key(nid, nmk, src_mac, dst_mac, interface)
            exit(0)

def extract_nid_nmk_from_load(load):
    nmk = load[-16:] # last 16 bytes of load is the nmk
    nmk = ''.join(f'{byte:02X}' for byte in nmk) # konvert into readable hex
    nid = load[-24:-17] # 8 bytes before nmk and remove last byte -> nid
    nid = ':'.join(f'{byte:02X}' for byte in nid) # konvert into readable hex
    return(nid, nmk)


if __name__ =="__main__":
    usage = "usage: %prog [options] \nUse either the interface or the file attribute to extract the NID and NMK of the CM_SLAC_MATCH.CNF message."
    parser = OptionParser(usage)
    parser.add_option("-k", "--keyset", action="store_true", help="Flag to set the NID and NMK after extracting it.", metavar="KEYSET")
    parser.add_option("-i", "--interface", help="Interface to listen for CM_SLAC_MATCH.CNF message for extracting the NID and NMK. Required if -k or --keyset flag is set.", metavar="INTERFACE")
    parser.add_option("-f", "--file", help="Pcap file to extract the NID and NMK from the CM_SLAC_MATCH.CNF message", metavar="FILE")
    parser.add_option("-s", "--sourcemac", default="c0:ff:ee:c0:ff:ee", help="MAC Address from which the set key message ist sent. Default Value is c0:ff:ee:c0:ff:ee", metavar="SOURCEMAC")
    parser.add_option("-d", "--destinationmac", help="MAC Address to which the set_key message ist sent. Required if the -k or --keyset flag is set.", metavar="DESTINATIONMAC")
    (options, _) = parser.parse_args()

    set_key = False
    if options.keyset:
        if not(options.interface):
            print("For setting the NID and NMK (activated with flag -k or --keyset), the interface must be specified.")
            exit(1)
        if not(options.destinationmac):
            print("For setting the NID and NMK (activated with flag -k or --keyset), the destination mac address must be specified.")
        set_key = True

    if bool(options.interface) == bool(options.file):
        parser.error("You must specify exactly one option: interface or file.")

    if options.file:
        packets = rdpcap(options.file)
        for packet in packets:
            extract_load_if_cm_slac_match_cnf(packet, set_key)
    else:
        sniff(iface=options.interface, prn=lambda packet: extract_load_if_cm_slac_match_cnf(packet, set_key, options.interface, options.sourcemac, options.destinationmac), store=False)