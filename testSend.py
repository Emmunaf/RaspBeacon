from beacon import BeaconPi
a = BeaconPi()
sock = a.open_socket()
print("Le advertising test")
a.hci_set_advertising_parameters()
a.le_set_advertising_status(enable=True)
while True:
    a.send_ack(0, 0)
    #a.parse_events(5)
    

