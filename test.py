from beacon import BeaconPi
a = BeaconPi()
a.open_socket()
a.start_le_scan()
a.parse_events()
