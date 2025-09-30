import logging
import threading
import signal
import sys
from scapy.all import rdpcap, AsyncSniffer
from scapy.utils import PcapWriter
from copy_and_adjust_slac import handle_packet
from datetime import datetime

evse_simulation_interface = "enx607d097bbc10"
ev_simulation_interface = "enx7cc2c61ec9fd"
mitm_evse_mac = 'c4:93:00:4f:56:bd'
mitm_ev_mac = 'c4:93:00:4f:5f:a1'
mitm_ev_run_id = 'c0:ff:ee:c0:ff:ee:ee:ee'
mitm_ev_sender_id = '00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00' # do we have to change it? Only saw 0 id's so far - maybe required, when multiple slac sessions are running
nid_original_ev_simulated_evse = '01:23:45:67:89:ab:cd'
nmk_original_ev_simulated_evse = '0123456789abcdef0123456789abcdef'

DATE=datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
PCAP_FILE = "capture_combined" + DATE + ".pcap"

logger = None
sniffer1 = AsyncSniffer(iface=evse_simulation_interface, prn=lambda packet: process_packet(packet))
sniffer2 = AsyncSniffer(iface=ev_simulation_interface, prn=lambda packet: process_packet(packet))

# --- Shared writer and lock ---
writer_lock = threading.Lock()
pcap_writer = PcapWriter(PCAP_FILE, append=True, sync=True) 

def init_logger():
    global logger
    logger = logging.getLogger(__name__)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logger.info('Initialized logger')

def process_packet(packet):
    with writer_lock:
        pcap_writer.write(packet)
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

def start_sniffers():
    sniffer1.start()
    sniffer2.start()
    logger.info("Sniffers started. Press Ctrl+C to stop.")

def stop_sniffers():
    logger.info("Stopping sniffers...")
    sniffer1.stop()
    sniffer2.stop()
    logger.info("Stopped.")

def signal_handler(sig, frame):
    stop_sniffers()
    pcap_writer.close()
    sys.exit(0)

def main():
    init_logger()
    logger.info('Starting MitM in main()')

    signal.signal(signal.SIGINT, signal_handler)  # Handle Ctrl+C
    start_sniffers()
    # Keep main thread alive
    signal.pause()


if __name__ == "__main__":
    main()