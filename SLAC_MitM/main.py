import logging
from scapy.all import sniff, rdpcap
from copy_and_adjust_slac import handle_packet


evse_simulation_interface = "Ethernet 3"
ev_simulation_interface = "Ethernet 4"
mitm_evse_mac = 'c0:ff:ee:c0:ff:ee'
mitm_ev_mac = 'c0:ff:ee:c0:ff:ee'
mitm_ev_run_id = 'c0:ff:ee:c0:ff:ee:ee:ee'
mitm_ev_sender_id = '00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00' # do we have to change it? Only saw 0 id's so far - maybe required, when multiple slac sessions are running

nid_original_ev_simulated_evse = '01:23:45:67:89:ab:cd'
nmk_original_ev_simulated_evse = '0123456789abcdef0123456789abcdef'


logger = None

def init_logger():
    global logger
    logger = logging.getLogger(__name__)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logger.info('Initialized logger')

def main():
    init_logger()
    logger.info('Starting MitM in main()')
    pcap = rdpcap(r'C:\code\vehiclelogs\vehicle2grid\2024-10-24-tesla-successfull-precharge-and-chargeloop.pcapng')
    i = 0
    for packet in pcap:
        i += 1
        handle_packet(
            packet=packet,
            evse_simulation_interface=evse_simulation_interface,
            ev_simulation_interface=ev_simulation_interface,
            mitm_ev_mac=mitm_ev_mac,
            mitm_evse_mac=mitm_evse_mac,
            mitm_ev_run_id=mitm_ev_run_id,
            mitm_ev_sender_id=mitm_ev_sender_id,
            nid_original_ev_simulated_evse=nid_original_ev_simulated_evse,
            nmk_original_ev_simulated_evse=nmk_original_ev_simulated_evse
            )
        # if 'HomePlugAV' in packet and packet['HomePlugAV'].HPtype == 0x6064:
        #     print(i)
    # sniff(iface=iface, prn=handle_packet)
    logger.info('Stopping MitM in main()')



if __name__ == "__main__":
    main()