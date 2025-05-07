from scapy.all import Ether, sendp, Padding
from scapy.contrib.homeplugav import HomePlugAV

def send_get_sw_version_broadcast(srcmac: str, interface: str):
    get_sw_version_pkg = Ether(src=srcmac, dst='ff:ff:ff:ff:ff:ff', type=0x88e1) \
        / HomePlugAV(version=0x00, HPtype=0xA000) \
        / Padding(load=0x00*40)
    sendp(get_sw_version_pkg, interface, verbose=1)

if __name__ == '__main__':
    send_get_sw_version_broadcast('c0:ff:ee:c0:ff:ee', 'enx7cc2c61f051e')