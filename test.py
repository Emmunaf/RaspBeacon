from beacon import BeaconPi
a = BeaconPi()
sock = a.open_socket()
a.hci_le_set_scan_parameters()
a.start_le_scan()
a.hci_set_advertising_parameters()
a.le_set_advertising_status(enable=True)
print("Le scan enabled")
while True:
    a.send_ack(0, 0)
    a.parse_events(5)
    

