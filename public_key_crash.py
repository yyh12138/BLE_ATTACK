import os
import sys
import binascii
from threading import Timer
from time import sleep

sys.path.insert(0, os.getcwd() + '/libs')
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from BlueShiro import BlueShiro
from colorama import Fore

phone_address = "fc:a9:f5:45:42:5a"
blueShiro = BlueShiro("70:a6:cc:b5:92:70", "/dev/ttyACM0", "a4:c1:38:7d:ab:b9")

scan_req = BTLE() / BTLE_ADV(RxAdd=blueShiro.slave_addr_type) / BTLE_SCAN_REQ(
    ScanA=blueShiro.master_addr,
    AdvA=blueShiro.slave_addr)
blueShiro.send(scan_req)
blueShiro.scan_timer.start()

print(Fore.GREEN + 'Waiting adv from ' + blueShiro.slave_addr)
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
        else:
            # process LL pkts
            ### BTLE/ADV/ ###
            if (BTLE_SCAN_RSP in pkt or BTLE_ADV in pkt) and pkt.AdvA == blueShiro.slave_addr.lower() and blueShiro.connecting == False:
                blueShiro.connecting = True
                blueShiro.scan_timer.cancel()
                blueShiro.slave_addr_type = pkt.TxAdd
                print(Fore.GREEN + blueShiro.slave_addr.upper() + ': ' + pkt.summary()[7:] + ' Detected')
                conn_req = BTLE() / BTLE_ADV(RxAdd=blueShiro.slave_addr_type, TxAdd=blueShiro.master_addr_type) / BTLE_CONNECT_REQ(
                    InitA=blueShiro.master_addr,
                    AdvA=blueShiro.slave_addr,
                    AA=blueShiro.access_addr,  
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
                blueShiro.send(conn_req)
            elif BTLE_DATA in pkt and blueShiro.connecting:
                blueShiro.connecting = False
                blueShiro.connected = True
                print(Fore.GREEN + 'Connected (L2Cap channel established)')

            ### BTLE/DATA/CTRL/ ###
            elif LL_VERSION_IND in pkt:
                print("LL_VERSION_IND")
            elif LL_LENGTH_REQ in pkt:
                length_rsp = BTLE(access_addr=blueShiro.access_addr) / BTLE_DATA() / BTLE_CTRL() / LL_LENGTH_RSP(
                    max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)
                blueShiro.driver.send(length_rsp) 
                print("LL_LENGTH_REQ")
            elif LL_LENGTH_RSP in pkt:
                print("LL_LENGTH_RSP")

            ### BTLE/DATA/L2CAP/ ###
            elif L2CAP_Connection_Parameter_Update_Request in pkt:
                print("L2CAP_Connection_Parameter_Update_Request")
            elif L2CAP_Connection_Parameter_Update_Response in pkt:
                print("L2CAP_Connection_Parameter_Update_Response")

            ### BTLE/DATA/L2CAP/SM/ ###
            elif SM_Pairing_Request in pkt:
                print("SM_Pairing_Request")
            elif SM_Pairing_Response in pkt:
                print("SM_Pairing_Response")
            elif SM_Public_Key in pkt:
                print("SM_Public_Key")
            elif SM_Failed in pkt:
                print("SM_Failed")

            elif BTLE_DATA in pkt and blueShiro.connected:
                print(binascii.hexlify(pkt.build()))

                
    sleep(0.01)


