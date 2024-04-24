import sys, os
sys.path.insert(0, os.getcwd() + '/libs')
from scapy.layers.bluetooth4LE import *
from scapy.utils import wrpcap
from threading import Timer
from scapy.compat import raw
from drivers.NRF52_dongle import NRF52Dongle
from colorama import Fore

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

        self.scan_timer = Timer(3, self.scan)
        self.scan_timer.daemon = True
        self.scan_timer.setName("scan_timer")

    def get_driver(self):
        return self.driver
    def get_none_count(self):
        return self.none_count
    def get_connected(self):
        return self.connected
    def get_connecting(self):
        return self.connecting
    def get_slave_addr(self):
        return self.slave_addr
    def get_slave_addr_type(self):
        return self.slave_addr_type
    def get_master_addr(self):
        return self.master_addr
    def get_master_addr_type(self):
        return self.master_addr_type

    def send(self, pkt, printTx=True):
        self.driver.raw_send(raw(pkt))
        if printTx:
            print(Fore.MAGENTA + "TX ---> " + pkt.summary()[7:])

    def crash(self):
        print(Fore.RED + "No advertisement from " + self.slave_addr.upper() +
            ' received\n The device may have crashed!')
        exit(0)

    def scan(self):
        if not self.connected:
            scan_req = BTLE() / BTLE_ADV(RxAdd=self.slave_addr_type) / BTLE_SCAN_REQ(
                ScanA=self.master_addr_type,
                AdvA=self.slave_addr)
            self.send(scan_req)

    def crash_start(self, interval=5.0):
        timeout = Timer(interval, self.crash)
        timeout.daemon = True
        timeout.start()

    def save2wireshark(filename, pkt):
        wrpcap("logs/"+ filename +".pcap", pkt)

    def send_empty_pkt(self):
        empty = BTLE(access_addr=self.access_addr) / BTLE_DATA(LLID=1, len=0) / BTLE_EMPTY_PDU()
        self.send(empty)

