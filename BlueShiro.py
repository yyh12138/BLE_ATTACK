import sys, os
sys.path.insert(0, os.getcwd() + '/libs')
from scapy.layers.bluetooth4LE import *
from scapy.utils import wrpcap
from threading import Timer
from scapy.compat import raw
from drivers.NRF52_dongle import NRF52Dongle
from colorama import Fore
from Crypto.Cipher import AES

class BlueShiro:
    def __init__(self, masterAddr=None, serialPort=None, slaveAddr=None) ->None:
        self.driver = NRF52Dongle(serialPort)
        self.none_count = 0
        self.slave_addr_type = 0
        self.master_addr_type = 0
        self.master_addr = masterAddr
        self.slave_addr = slaveAddr
        self.serial_port = serialPort
        self.access_addr = 0x9a328370
        
        self.connecting = False
        self.connected = False
        self.param_updating = False
        self.param_updated = False
        self.version_updating = False
        self.version_updated = False
        self.pairing = False
        self.paired = False
        self.bounding = False
        self.bounded = False

        self.encryptable = False
        self.conn_tx_pkt_count = 0
        self.conn_rx_pkt_count = 0

        self.scan_timer = Timer(3, self.scan)
        self.scan_timer.daemon = True
        self.scan_timer.setName("scan_timer")

    def set_pairing_iocap(self, iocap=0x03):
        # iocap = 0x01                 DisplayYesNo
        #         0x03                 NoInputNoOutput
        #         0x04                 KeyboardDisplay
        self.pairing_iocap = iocap

    def set_pairing_auth_request(self, auth_request=0x00):
        # auth_request = 0x00          No bounding
        #                0x01          bounding
        #                0x08 | 0x01   LESC + bounding
        #                0x04 | 0x01   MITM + bounding
        #                0x08 | 0x04 | 0x01  LESC + MITM + bounding
        self.pairing_auth_request = auth_request
    
    def set_NRF52Dongle_debug_mode(self, debug=False):
        self.driver.set_debug_mode(debug)

    def send(self, pkt, printTx=True):
        self.driver.send(pkt)

    def scan(self):
        if not self.connected:
            scan_req = BTLE() / BTLE_ADV(RxAdd=self.slave_addr_type) / BTLE_SCAN_REQ(
                ScanA=self.master_addr_type,
                AdvA=self.slave_addr)
            self.send(scan_req)

    def send_encrypted(self, pkt):
        try:
            raw_pkt = bytearray(raw(pkt))
            self.access_addr = raw_pkt[:4]
            header = raw_pkt[4]
            length = raw_pkt[5] + 4 
            crc = '\x00\x00\x00'  # Dummy CRC (Dongle automatically calculates it)
            
            self.driver.raw_send(self.access_addr + chr(header) + chr(length) + encrypt_pkt + mic + crc)
        except Exception as e:
            print(Fore.RED + "Send Encrypted Wrong: " + e)

    def receive_encrypted(self, pkt):
        raw_pkt = bytearray(raw(pkt))
        self.access_addr = raw_pkt[:4]
        header = raw_pkt[4]
        length = raw_pkt[5]
        crc = '\x00\x00\x00'  # Fake CRC (Dongle automatically calculates it)
        if length is 0 or length<5:
            return pkt        # Empty PDU
        length -= 4           # subtract MIC

        decrypt_pkt = ''
        try:
            pass
        except Exception as e:
            print(Fore.RED + "MIC Wrong: " + e)
        # resamble the pkt
        return BTLE(self.access_addr + chr(header) + chr(length) + decrypt_pkt + crc)

    def save2wireshark(filename, pkt):
        wrpcap("logs/"+ filename +".pcap", pkt)
        

