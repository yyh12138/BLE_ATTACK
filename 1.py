from bluepy.btle import Scanner, Peripheral


# scanner = Scanner()
# devices = scanner.scan()
# for dev in devices:
#     print("Device %s (%s), RSSI=%d dB" % (dev.addr, dev.addrType, dev.rssi))
#     for (adtype, desc, value) in dev.getScanData():
#         print("  %s = %s" % (desc, value))

addr = "a4:c1:38:7d:ab:b9"
conn = Peripheral(addr)
services = conn.getServices()
for service in services:
    print("[+] Service: ", service.uuid)  
    # characteristics = service.getCharacteristics()
    # for characteristic in characteristics:
    #     print("    characteristic: ", characteristic.uuid)
    #     print("    Properties: ", characteristic.propertiesToString())
    #     print("")
# conn.disconnect()
