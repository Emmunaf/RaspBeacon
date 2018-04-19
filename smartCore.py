from smartObject import SmartObject, SmartCommands
from beacon import BeaconPi
import struct
import string
import os

class SmartCore(SmartObject):

    def __init__(self, object_id=-1, hci_device=0, wlan_device=0):
        """An extended SmartObject
        
        The status is defined also by:
        iv: the iv ready to use for the next communication        
        wifi_psk: the wifi password of the current hotspot
        wlan_device: the device used for the current wlan hotspot
        """

        super().__init__(object_id, hci_device)
        # Generate a new iv and wifi_password
        self.partial_iv = BeaconPi.generate_random_bytes(12)
        self.wifi_psk = BeaconPi.generate_random_bytes(16)
        self.wlan_device = wlan_device

    def new_iv(self):
        self.partial_iv = BeaconPi.generate_random_bytes(12)

    def new_password(self):
        length = 16
        chars = string.ascii_letters + string.digits + '!@#$%^&*()'
        psk = ""
        for x in range(length):
            psk += chars[ord(BeaconPi.generate_random_bytes(1)) % len(chars)]
        self.wifi_psk = psk.encode("ascii")
        # TODO: CHANGE WIFI PASSWORD

    def send_wifi_password(self, user_id):
        adv_data = {
            "wifipassword":self.wifi_psk,
            "obj_id": self.object_id,
            "user_id": user_id}
        enc_params = {
            "aes_key": self.get_token,
            "aes_iv": self.get_iv
        }
        print("**** HelloBroadcastACK received ****")
        print(adv_data)
        print(enc_params)
        self.beacon.le_set_wifi_password_broadcast(adv_data, enc_params)

    def send_hellobroadcast(self):
        adv_data = {
            "partial_iv": self.partial_iv,
            "obj_id": self.object_id}
        self.iv = self.beacon.le_set_hello_broadcast(adv_data)
        print(self.iv)

    def check_for_hello_ack(self, report):
        """Check and do some action if an HelloBroadcast is received
        
        Note: the format of the HelloBroadcast ACK is different
              like the HelloBroadcast packet itself.
        """
        is_ack = False
        clear_report = report["payload_encrypted_data"]
        # Note: hello and hello_ack are in cleartext
        cmd_id, = struct.unpack(">I", clear_report[0:4])
        recv_iv = report["payload_binary"][4:]
        user_id = report['major']
        HELLO_BROADCAST_ACK_CMD_ID = 0xFFFFFFFF
        print(cmd_id)
        if cmd_id == HELLO_BROADCAST_ACK_CMD_ID:
            print("recv_iv:")
            print(recv_iv)
            if recv_iv == self.iv:  # It's a real HelloB ACK
                self.new_password()
                self.new_iv()
                self.send_wifi_password(user_id)
                is_ack = True
        return is_ack


    def start_listen(self):
        beacon = BeaconPi(self.hci_device)  # HCIDEVICE
        self.beacon = beacon
        sock = beacon.open_socket()
        beacon.hci_le_set_scan_parameters()
        beacon.start_le_scan()
        beacon.hci_set_advertising_parameters()
        beacon.le_set_advertising_status(enable=True)  # Start adv.
        self.send_hellobroadcast()
        print("Waiting for smartbeacon(SC Edition)")
        smart_command_handler = SmartCommands("command_list.json")
        sending_ack = False
        while True:
            smartbeacon_list = beacon.parse_events()
            self.remove_duplicates_list(smartbeacon_list)
            for smartbeacon in smartbeacon_list:
                if smartbeacon['minor'] == self.object_id:  # minor is id_obj
                    clear_user_id = smartbeacon['major']  # clear, not inside encr. payload
                    # print(smartbeacon)
                    if self.parse_smartbeacon(smartbeacon):
                        if not smartbeacon['smartbeacon']['is_ack']:
                            # Get encryption data of the user
                            aes_key = self.get_token(clear_user_id)
                            aes_iv = self.get_iv(clear_user_id)
                            beacon.send_ack(clear_user_id, self.get_counter(clear_user_id), aes_key, aes_iv)
                            print("Sent ack to" + str(clear_user_id))
                            # print(smartbeacon)
                            sending_ack = True
                            # Execute action
                            smart_command_handler.parse_command(smartbeacon['smartbeacon'])

    def parse_smartbeacon(self, report):
        # Unpack all field and return True if packet is valid, and update report dict
        if self.check_for_hello_ack(report):
                return True
        if len(report["payload_encrypted_data"]) == 16:
            report["decrypted_payload"] = self.decrypt_payload(report["payload_encrypted_data"], report['major'])
            dec_payload = report["decrypted_payload"]
            counter, = struct.unpack(">Q", dec_payload[0:8])
            cmd_type, cmd_class, cmd_opcode, cmd_params, cmd_bitmask = struct.unpack(">BBBhB", dec_payload[8:14])
            res1, res2 = struct.unpack(">BB", dec_payload[14:16])
            report['smartbeacon'] = {'counter': counter, 'cmd_type': cmd_type, 'cmd_class': cmd_class,
                                     'cmd_bitmask': cmd_bitmask,
                                     'cmd_opcode': cmd_opcode, 'cmd_params': cmd_params, 'res1': res1, 'res2': res2,
                                     'is_ack': False, 'user_id': report['major']}
            if not self.verify_ack(report['smartbeacon']):  # is an ack?
                user_id = report['smartbeacon']['user_id']
                counter_received = report['smartbeacon']['counter']
                if counter_received == self.get_counter(user_id):
                    # New packet
                    print("Counter is ok")
                    self.increase_counter(user_id)
                elif report['smartbeacon']['counter'] == self.get_counter(report['smartbeacon']['user_id']) - 1:
                    # Duplicated packet
                    print("Duplicated packet")
                    return False
                else:  # Counter not sincronized
                    return False
                    # If it is an ack, need to increase counter: if not already done:
            # TODO: Valid check, if counter_received == counter_smart_object, else return False
            else:
                report['smartbeacon']['is_ack'] = True
            return True