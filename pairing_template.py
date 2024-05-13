import os, sys
from binascii import hexlify
from time import sleep

sys.path.insert(0, os.getcwd() + '/libs')
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from BlueShiro import BlueShiro
from colorama import Fore

phone_address = "fc:a9:f5:45:42:5a"
temperature_sensor_address = "a4:c1:38:7d:ab:b9"
blinky_address = "d9:91:8a:6a:7a:ba"
running = 0
blueShiro = BlueShiro("70:a6:cc:b5:92:70", "/dev/ttyACM0", blinky_address)

blueShiro.set_pairing_iocap(0x04)                 # KeyboardDisplay
blueShiro.set_pairing_oob(0)
blueShiro.set_pairing_auth_request(0x01)          # LELP + Bounding

scan_req = BTLE() / BTLE_ADV(RxAdd=blueShiro.slave_addr_type) / BTLE_SCAN_REQ(
    ScanA=blueShiro.master_addr,
    AdvA=blueShiro.slave_addr)
blueShiro.send(scan_req)
blueShiro.scan_timer.start()

print(Fore.GREEN + 'Waiting adv from ' + blueShiro.slave_addr)
while running<77:
    pkt = None
    data = blueShiro.driver.raw_receive()
    if data:
        pkt = blueShiro.receive(BTLE(data))
        if pkt is None:
            blueShiro.none_count += 1
            if blueShiro.none_count >= 3:
                print(Fore.RED + 'NRF52 Dongle not detected')
                sys.exit(0)
            continue
        else: 
            if BTLE_DATA in pkt:
                # print all CMD
                print(Fore.CYAN + "RX <--- " + pkt.summary()[7:])
                bytes = pkt.build()
                binary_str = ''.join(format(byte, '08b') for byte in bytes)
                _sn =  int(binary_str[36])
                _nesn = int(binary_str[37])
                blueShiro.set_sn_and_nesn(_sn, _nesn)
            ### BTLE/ADV/ ###
            if (BTLE_SCAN_RSP in pkt or BTLE_ADV in pkt) and pkt.AdvA == blueShiro.slave_addr.lower() and blueShiro.connecting == False:
                if blueShiro.connected:
                    print(Fore.RED + blueShiro.slave_addr.upper() + ' Disconnect')
                    exit(0)
                blueShiro.connecting = True
                blueShiro.scan_timer.cancel()
                blueShiro.slave_addr_type = pkt.TxAdd
                print(Fore.GREEN + blueShiro.slave_addr.upper() + ' Detected')
                conn_req = BTLE() / BTLE_ADV(RxAdd=blueShiro.slave_addr_type, TxAdd=blueShiro.master_addr_type, PDU_type=5) / BTLE_CONNECT_REQ(
                    InitA=blueShiro.master_addr,
                    AdvA=blueShiro.slave_addr,
                    AA=blueShiro.access_addr,  
                    crc_init=0x179a9c,  
                    win_size=2,  
                    win_offset=23, 
                    interval=24,  
                    latency=0,  
                    timeout=500, 
                    chM=0x1FFFFFFFFF,
                    hop=5,  
                    SCA=0
                )
                blueShiro.send(conn_req)
                blueShiro.version_updating = True
            elif BTLE_DATA in pkt and blueShiro.version_updating:
                version_ind = BTLE(access_addr=blueShiro.access_addr) / BTLE_DATA(SN=blueShiro.sn, NESN=blueShiro.nesn) / CtrlPDU() / LL_VERSION_IND(version='4.2')
                blueShiro.send(version_ind)
                blueShiro.version_updating = False
                blueShiro.version_updated = True

            ### BTLE/DATA/CTRL/ ###
            elif LL_VERSION_IND in pkt and blueShiro.version_updated:
                feature_req = BTLE(access_addr=blueShiro.access_addr) / BTLE_DATA(SN=blueShiro.sn, NESN=blueShiro.nesn) / CtrlPDU() / LL_FEATURE_REQ(
                    feature_set='le_encryption+le_data_len_ext'
                )
                blueShiro.send(feature_req)
            elif LL_FEATURE_RSP in pkt:
                length_req = BTLE(access_addr=blueShiro.access_addr) / BTLE_DATA(SN=blueShiro.sn, NESN=blueShiro.nesn) / CtrlPDU() / LL_LENGTH_REQ(
                    max_tx_bytes=247 + 4, max_rx_bytes=247 + 4
                )
                blueShiro.send(length_req)
            elif LL_LENGTH_RSP in pkt:
                exchange_mtu_req = BTLE(access_addr=blueShiro.access_addr) / BTLE_DATA(SN=blueShiro.sn, NESN=blueShiro.nesn) / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Request(mtu=247)
                blueShiro.send(exchange_mtu_req)
            elif LL_ENC_RSP in pkt:
                blueShiro.conn_skd += pkt[LL_ENC_RSP].skds  # SKD = SKDm | SKDs
                blueShiro.conn_iv += pkt[LL_ENC_RSP].ivs    # IV  = IVm  | IVs
                blueShiro.conn_ltk = "\x00" * 16
                conn_session_key = blueShiro.bt_crypto_e(blueShiro.conn_ltk[::-1], blueShiro.conn_skd[::-1])
                print(Fore.GREEN + 'Received SKD: ' + hexlify(blueShiro.conn_skd))
                print(Fore.GREEN + 'Received  IV: ' + hexlify(blueShiro.conn_iv))
                print(Fore.GREEN + 'Assumed  LTK: ' + hexlify(blueShiro.conn_ltk))
                print(Fore.GREEN + 'AES-CCM  Key: ' + hexlify(conn_session_key))
            elif LL_START_ENC_REQ in pkt:
                print(Fore.YELLOW + "Start encryption")
                blueShiro.encryptable = True
                start_enc_rsp = BTLE(access_addr=blueShiro.access_addr) / BTLE_DATA(SN=blueShiro.sn, NESN=blueShiro.nesn) / CtrlPDU() / LL_START_ENC_RSP()
                blueShiro.send(start_enc_rsp)
            elif LL_START_ENC_RSP in pkt:
                pass
            elif LL_TERMINATE_IND in pkt:
                print(Fore.YELLOW + "Slave closes the connection.")
                break          
            elif LL_REJECT_IND in pkt:
                pass
            
            ### BTLE/DATA/L2CAP/ ###
            elif L2CAP_Connection_Parameter_Update_Request in pkt:
                conn_param_update_req = BTLE(access_addr=blueShiro.access_addr) / BTLE_DATA(SN=blueShiro.sn, NESN=blueShiro.nesn) / L2CAP_Hdr() / L2CAP_CmdHdr(code=19, id=1) / L2CAP_Connection_Parameter_Update_Response(
                    move_result=0
                )
                blueShiro.send(conn_param_update_req)
            elif L2CAP_Connection_Parameter_Update_Response in pkt:
                pass

            ### BTLE/DATA/L2CAP/SM/ ###
            elif SM_Pairing_Request in pkt:
                pass
            elif SM_Pairing_Response in pkt:
                sm_confirm = BTLE(access_addr=blueShiro.access_addr) / BTLE_DATA(SN=blueShiro.sn, NESN=blueShiro.nesn) / L2CAP_Hdr() / SM_Hdr() / SM_Confirm(
                    confirm=""
                )
                blueShiro.send(sm_confirm)
            elif SM_Confirm in pkt:
                sm_random = BTLE(access_addr=blueShiro.access_addr) / BTLE_DATA(SN=blueShiro.sn, NESN=blueShiro.nesn) / L2CAP_Hdr() / SM_Hdr() / SM_Random(
                    random=""
                )
                blueShiro.send(sm_random)
            elif SM_Random in pkt:
                enc_req = BTLE(access_addr=blueShiro.access_addr) / BTLE_DATA(SN=blueShiro.sn, NESN=blueShiro.nesn) / CtrlPDU() / LL_ENC_REQ(
                    rand="\x00",
                    ediv="\x00",
                    skdm=blueShiro.conn_skd,
                    ivm=blueShiro.conn_iv
                )
                blueShiro.send(enc_req)
            elif SM_Public_Key in pkt:
                pass
            elif SM_Encryption_Information in pkt:
                pass
            elif SM_Failed in pkt:
                pass

            ### BTLE/DATA/L2CAP/ATT/ ###
            elif ATT_Exchange_MTU_Response in pkt:
                blueShiro.connected = True
                blueShiro.connecting = False
                pairing_req = BTLE(access_addr=blueShiro.access_addr) / BTLE_DATA(SN=blueShiro.sn, NESN=blueShiro.nesn) / L2CAP_Hdr() / SM_Hdr() / SM_Pairing_Request(
                    iocap=blueShiro.pairing_iocap,
                    oob=blueShiro.pairing_oob,
                    authentication=blueShiro.pairing_auth_request,
                    max_key_size=16,
                    initiator_key_distribution=0x07,
                    responder_key_distribution=0x07
                )
                blueShiro.send(pairing_req)
            elif ATT_Read_Request in pkt:
                pass
            elif ATT_Read_Response in pkt:
                pass
            elif ATT_Read_By_Group_Type_Response in pkt:
                pass
            elif ATT_Write_Command in pkt:
                pass
            elif ATT_Write_Request in pkt:
                pass
            elif ATT_Write_Response in pkt:
                pass    
            
            # keep connection alive
            elif BTLE_EMPTY_PDU in pkt:
                empty_pdu = BTLE(access_addr=blueShiro.access_addr) / BTLE_DATA(SN=blueShiro.sn, NESN=blueShiro.nesn, LLID=1, len=0) / BTLE_EMPTY_PDU()
                blueShiro.send(empty_pdu)
                running += 1

    sleep(0.01)

terminate_req = BTLE(access_addr=blueShiro.access_addr) / BTLE_DATA(LLID=3) / CtrlPDU() / LL_TERMINATE_IND(code=0x13)
blueShiro.send(terminate_req)
blueShiro.driver.save_pcap(filename="nRF52Dongle_" + os.path.basename(__file__).split('.')[0] + ".pcap")
sleep(1)
print(Fore.YELLOW + "Master closes the connection. Script Ends")