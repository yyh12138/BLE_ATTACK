from scapy.all import *
from scapy.layers.bluetooth import *
import BLESMPServer

master_address = '70:a6:cc:b5:92:70'
slave_address = 'd9:91:8a:6a:7a:ba'
ia = ''.join(map(lambda x: chr(int(x, 16)), master_address.split(':')))
ra = ''.join(map(lambda x: chr(int(x, 16)), slave_address.split(':')))

BLESMPServer.set_iocap(0x03)  # NoInputNoOutput

BLESMPServer.configure_connection(ia, ra, 0, 0x03, 0)

s = HCI_Hdr() / HCI_ACL_Hdr() / L2CAP_Hdr() / SM_Hdr() / SM_Pairing_Request()

data = bytearray(s)

hci_res = BLESMPServer.send_hci(data)
# hci_res = BLESMPServer.pairing_request()
if hci_res is not None:
    pkt = HCI_Hdr(hci_res)
    print(pkt.summary())
    pkt.show()
    print('---------------------')
