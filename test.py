from beacon import BeaconPi
a = BeaconPi()
a.open_socket()
a.hci_le_set_scan_parameters()
a.start_le_scan()
print("Le scan enabled")
a.parse_events(10)

