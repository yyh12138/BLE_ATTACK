import sys, os
sys.path.insert(0, os.getcwd() + '/libs')
from scapy.layers.bluetooth4LE import *
from scapy.utils import wrpcap
from threading import Timer
from scapy.compat import raw
from drivers.NRF52_dongle import NRF52Dongle
from colorama import Fore
from Cryptodome.Cipher import AES

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
        self.sn = 0
        self.nesn = 0 
        self.fragment = None
        self.fragment_start = False
        self.fragment_left = 0
        
        self.conn_skd = "\x00" * 8  # init SKDm
        self.conn_iv  = "\x00" * 4  # init IVm
        self.conn_ltk = None
        self.conn_session_key = None

        self.scan_timer = Timer(3, self.scan)
        self.scan_timer.daemon = False
        self.scan_timer.setName("scan_timer")

    def set_pairing_iocap(self, iocap=0x04):
        # iocap = 0x01                 DisplayYesNo
        #         0x03                 NoInputNoOutput
        #         0x04                 KeyboardDisplay
        self.pairing_iocap = iocap

    def set_pairing_auth_request(self, auth_request=0x01):
        # auth_request = 0x00          LELP + No bounding
        #                0x01          LELP + bounding
        #                0x08 | 0x01   LESC + bounding
        #                0x04 | 0x01   MITM + bounding
        #                0x08 | 0x04 | 0x01  LESC + MITM + bounding
        self.pairing_auth_request = auth_request
    
    def set_pairing_oob(self, oob=0):
        self.pairing_oob = oob

    def set_pairing_mode(self, mode=False):
        # pairing_mode = False      LELP
        #                True       LESC
        self.pairing_mode = mode

    def set_NRF52Dongle_debug_mode(self, debug=False):
        self.driver.set_debug_mode(debug)

    def send(self, pkt, print_tx=True):
        if self.encryptable:
            self._send_encrypted(pkt, print_tx)
        else:
            self.driver.send(pkt, print_tx)

    def receive(self, pkt):
        if self.encryptable:
            return self._receive_encrypted(pkt)
        else:
            return pkt

    def scan(self):
        if not self.connecting:
            scan_req = BTLE() / BTLE_ADV(RxAdd=self.slave_addr_type) / BTLE_SCAN_REQ(
                ScanA=self.master_addr_type,
                AdvA=self.slave_addr)
            self.send(scan_req)

    def _send_encrypted(self, pkt, print_tx):
        raw_pkt = bytearray(raw(pkt))
        self.access_addr = raw_pkt[:4]
        header = raw_pkt[4]
        length = raw_pkt[5] + 4 # add 4 bytes for mic
        crc = b'\x00\x00\x00'  # Dummy CRC (Dongle automatically calculates it)
        
        pkt_count = bytearray(struct.pack("<Q", self.conn_tx_pkt_count)[:5])
        pkt_count[4] |= 0x80   # set for M->S
        nonce = pkt_count + self.conn_iv

        aes = AES.new(self.conn_session_key, AES.MODE_CCM, nonce=nonce, mac_len=4) # mac=mic
        aes.update(chr(header&0xE3))
        encrypt_pkt, mic = aes.encrypt_and_digest(raw_pkt[6:-3]) # get payload without CRC
        self.conn_tx_pkt_count += 1
        self.driver.raw_send(self.access_addr + chr(header) + chr(length) + encrypt_pkt + mic + crc)
        if print_tx:
            print(Fore.MAGENTA + "TX ---> [Encrypted] " + pkt.summary()[7:])

    def _receive_encrypted(self, pkt):
        raw_pkt = bytearray(raw(pkt))
        header = raw_pkt[4]
        length = raw_pkt[5]
        crc = b'\x00\x00\x00'  # Fake CRC (Dongle automatically calculates it)
        if length == 0 or length<5:
            return pkt        # Empty PDU
        length -= 4           # subtract MIC
        
        pkt_count = bytearray(struct.pack("<Q", self.conn_tx_pkt_count)[:5])
        pkt_count[4] |= 0x7F  # set for S->M
        nonce = pkt_count + self.conn_iv

        aes = AES.new(self.conn_session_key, AES.MODE_CCM, nonce=nonce, mac_len=4) # amc=mic
        aes.update(chr(header & 0xE3)) # Calculate mic over header cleared of NES, SN and MD
        decrypt_pkt = aes.decrypt(raw_pkt[6:-4-3]) # get payload without CRC
        self.conn_rx_pkt_count += 1
        try:
            mic = raw_pkt[6+length:-3]
            aes.verify(mic)
        except Exception as e:
            print(Fore.RED + "MIC Wrong: " + str(e))
        # resamble the pkt
        return BTLE(self.access_addr + chr(header) + chr(length) + decrypt_pkt + crc)

    def set_sn_and_nesn(self, _sn, _nesn):
        if _sn==0 and _nesn==0:
            self.sn=0
            self.nesn=1
        elif _sn==0 and _nesn==1:
            self.sn=1
            self.nesn=1
        elif _sn==1 and _nesn==1:
            self.sn=1
            self.nesn=0
        elif _sn==1 and _nesn==0:
            self.sn=0
            self.nesn=0

    def save2wireshark(filename, pkt):
        wrpcap("logs/"+ filename +".pcap", pkt)
        
    def defragment_L2CAP(self, pkt):
        # Handle L2CAP fragment
        if L2CAP_Hdr in pkt and pkt[L2CAP_Hdr].len + 4 > pkt[BTLE_DATA].len:
            self.fragment_start = True
            self.fragment_left = pkt[L2CAP_Hdr].len
            self.fragment = raw(pkt)[:-3]
            return None
        elif self.fragment_start and BTLE_DATA in pkt and pkt[BTLE_DATA].LLID == 0x01:
            self.fragment_left -= pkt[BTLE_DATA].len + 4
            self.fragment += raw(pkt[BTLE_DATA].payload)
            if pkt[BTLE_DATA].len >= self.fragment_left:
                self.fragment_start = False
                pkt = BTLE(self.fragment + b'\x00\x00\x00')
                pkt.len = len(pkt[BTLE_DATA].payload)  # update ble header length
                return pkt
            else:
                return None
        else:
            self.fragment_start = False
            return pkt
        
    def bt_crypto_e(key, plaintext):
        aes = AES.new(key, AES.MODE_ECB)
        return aes.encrypt(plaintext)
    
    def build_pairing_confirm(self, mode):
        self.pairing_mode = mode
        confirm = "\x00" * 16
        if mode:
            # LESC
            pass
        else:
            # LELP
            pass
        return confirm
    
    def build_pairing_random(self, value):
        random = "\x00" * 16
        # TODO
        return random