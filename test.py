from beacon import BeaconPi
a = BeaconPi()
a.open_socket()
a.start_le_scan()
print("Le scan enabled")
a.parse_events(10)

