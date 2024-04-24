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
            # print all CMD
            if BTLE_DATA in pkt:
                print(Fore.CYAN + "RX <--- " + pkt.summary()[7:])
            ### BTLE/ADV/ ###
            if (BTLE_SCAN_RSP in pkt or BTLE_ADV in pkt) and pkt.AdvA == blueShiro.slave_addr.lower() and blueShiro.connecting == False:
                blueShiro.connecting = True
                blueShiro.scan_timer.cancel()
                blueShiro.slave_addr_type = pkt.TxAdd
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
                # d6be898e05227092b5cca670b9ab7d38c1a47083329a9c9a1702020018000000f401ffffffff1f0558ffb8
                # Access Address: d6be898e 
                # Packet Header: 0522
                # Initiator Address: 7092b5cca670
                # Advertising Address: b9ab7d38c1a4
                ### Access Address: 7083329a
                ### CRC Init: 9c9a17
                ### Window Size: 02
                ### Window Offset: 0200
                ### Interval: 1800
                ### Latency: 0000
                ### Timeout: f401
                ### chM: ffffffff1f
                ### hop+SCA: 05
                # CRC: 58ffb8
                blueShiro.send(conn_req)
                blueShiro.version_updating = True
            elif BTLE_DATA in pkt and blueShiro.version_updating:
                version_ind = BTLE(access_addr=blueShiro.access_addr) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')
                # 7083329a03060c080000000084f06d
                # Access Address: 7083329a
                # Data Header: 0306
                # Control Opcode: 0c
                # Version Number: 08
                # Company ID+Subversion Number: 00000000
                # CRC: 84f06d
                blueShiro.send(version_ind)
                blueShiro.version_updating = False
                blueShiro.version_updated = True

            ### BTLE/DATA/CTRL/ ###
            elif LL_VERSION_IND in pkt and blueShiro.version_updating:
                conn_update_req = BTLE(access_addr=blueShiro.access_addr) / BTLE_DATA(LLID=3) / CtrlPDU() / LL_CONNECTION_UPDATE_REQ(
                    win_size=1,
                    win_offset=0,
                    interval=6,
                    latency=0,
                    timeout=500,
                    instant=15
                )
                # 7083329a030c0001000006000000f4010f003d199e
                # Access Address: 7083329a
                # Data Header: 030c
                # Control Opcode: 00
                # Window Size+Window Offset+Interval+Latency+Timeout+Instant: 01 0000 0600 0000 f401 0f00
                # CRC: 3d199e
                blueShiro.send(conn_update_req)
                
            elif LL_LENGTH_REQ in pkt:
                pass
            elif LL_LENGTH_RSP in pkt:
                pass

            ### BTLE/DATA/L2CAP/ ###
            elif L2CAP_Connection_Parameter_Update_Request in pkt:
                conn_param_update_req = BTLE(access_addr=blueShiro.access_addr) / BTLE_DATA() / L2CAP_Hdr() / L2CAP_CmdHdr(code=19, id=1) / L2CAP_Connection_Parameter_Update_Response(
                    move_result=0
                )
                # 7083329a020a060005001301020000003b1a7e
                # Access Address: 7083329a
                # Data Header: 020a
                ### Length: 0600
                ### CID: 0500
                ##### Command Code: 13
                ##### Command ID: 01
                ##### Command Length: 02
                ##### Move Result: 000000
                # CRC: 3b1a7e
                blueShiro.send(conn_param_update_req)
                blueShiro.connected = True
                blueShiro.connecting = False
                print(Fore.GREEN + 'Connected (L2Cap channel established)')
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

            elif BTLE_EMPTY_PDU in pkt and blueShiro.connected:
                blueShiro.send_empty_pkt()

    sleep(0.01)


