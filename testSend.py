from beacon import BeaconPi
a = BeaconPi()
sock = a.open_socket()
print("Le advertising test")
while True:
    a.send_ack(0, 0)
    a.le_set_advertising_status(enable=True)
    #a.parse_events(5)
    

