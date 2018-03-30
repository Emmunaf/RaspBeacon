from collections import OrderedDict
import struct
import json


from beacon import BeaconPi
from AESCipher import AESCipher
import smartbeacon_command

#atexit.register
class SmartObject(object):
    """A class used for handling SmartObjects"""

    def __init__(self, object_id=-1, hci_device=0):
        if object_id == -1:  # Check configurationFile TODO
            object_id = self.register_object
        self.object_id = object_id
        self.last_users = UpdateOrderedDict()
        self.hci_device = hci_device

    def get_token(self, user_id):
        if user_id not in self.last_users:
            self.parse_token(user_id)
        elif not self.last_users[user_id].get('token'):
            self.parse_token(user_id)
        return self.last_users[user_id]['token']

    def get_counter(self, user_id):
        if user_id not in self.last_users:
            self.parse_counter(user_id)
        elif not self.last_users[user_id].get('counter'):
            self.parse_counter(user_id)
        return self.last_users[user_id]['counter']

    def get_iv(self, user_id):
        if user_id not in self.last_users:
            self.parse_iv(user_id)
        elif not self.last_users[user_id].get('iv', False):
            self.parse_iv(user_id)
        return self.last_users[user_id]['iv']

    def register_object(self):
        """A method used for register an object for the first time.
            After this phase the object should use the same obj_id for ever.
        """

        object_id = 0  # get id from SmartCore, will last a lifetime
        # Save object_id to file for later restoring TODO
        return object_id

    def parse_token(self, user_id):
        """A method that asks to SmartCore (DB) a specified token from a user_id"""
        if user_id not in self.last_users:
            self.last_users[user_id] = {}
        token = b'\x9b\xd9\xcd\xf6\xbe+\x9dX\xfb\xd2\xef>\xd87i\xa0\xca\xf5o\xd0\xac\xc3\xe0R\xf0z\xfa\xb8\xdd\x01?E'  # TODO
        self.last_users[user_id]['token'] = token
        return token  # TODO

    def parse_counter(self, user_id):
        """A method that asks to SmartCore (DB) a specified counter from a user_id"""
        if user_id not in self.last_users:  # Add to last users list if new
            self.last_users[user_id] = {}
        if 'counter' not in self.last_users[user_id]:  # Add counter key if not exist
            # If not in cache_dict, get from DB
            counter = 0 # TODO
            self.last_users[user_id]['counter'] = counter
        return self.last_users[user_id]['counter']

    def parse_iv(self, user_id):
        """A method that asks to SmartCore (DB) the iv for a known user_id
        :rtype: bytearray
        """
        if user_id not in self.last_users:
            self.last_users[user_id] = {}
        iv = b'\xef\xaa)\x9fHQ\x0f\x04\x18\x1e\xb5;B\xff\x1c\x01'  # TODO
        self.last_users[user_id]['iv'] = iv
        return iv

    def set_token_from_uid(self, user_id, token):
        """Method for setting token with a known user_id """

        user_dict = {'token': token}
        # If the user_dict already exist, update it with new info (tokens value)
        if user_id in self.last_users:
            self.last_users[user_id].update(user_dict)
        else:
            self.last_users[user_id] = user_dict

    def set_iv_from_uid(self, user_id, iv):
        """Method for setting iv with a known user_id """

        user_dict = {'iv': iv}
        if user_id in self.last_users:
            self.last_users[user_id].update(user_dict)
        else:
            self.last_users[user_id] = user_dict

    def _set_counter_from_uid(self, user_id, counter):
        """Method for setting counter with a known user_id """

        user_dict = {'counter': counter}
        if user_id in self.last_users:
            self.last_users[user_id].update(user_dict)
        else:
            self.last_users[user_id] = user_dict
            # In every case send update to DB

    def increase_counter(self, user_id):
        """Increase counter by 1, handle 8byte counter"""
        old_counter = self.get_counter(user_id)
        if old_counter == 0xFFFFFFFFFFFFFFFF:
            new_counter = 0x00
        else:
            new_counter = old_counter+1
        self._set_counter_from_uid(user_id, new_counter)

    def start_listen(self):
        beacon = BeaconPi(self.hci_device)  # HCIDEVICE
        sock = beacon.open_socket()
        beacon.hci_le_set_scan_parameters()
        beacon.start_le_scan()
        beacon.hci_set_advertising_parameters()
        beacon.le_set_advertising_status(enable=True)  # Start adv.
        print("Waiting for smartbeacon")
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
                            beacon.send_ack(clear_user_id, self.get_counter(clear_user_id))
                            print("Sent ack to" + str(clear_user_id))
                            # print(smartbeacon)
                            sending_ack = True
                            # Execute action
                            smart_command_handler.parse_command(smartbeacon['smartbeacon'])

    def parse_smartbeacon(self, report):
        # Unpack all field and return True if packet is valid, and update report dict
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


    @staticmethod
    def verify_ack(smartbeacon):
        """Return true if the smartbeacon is an ACK.

        Note: If it's an ack, smartbeacon['params'] contains the user_id"""
        return (smartbeacon['cmd_type'], smartbeacon['cmd_class'], smartbeacon['cmd_opcode']) == (0xFF, 0xFF, 0xFF)

    @staticmethod
    def remove_duplicates_list(target_list):
        """Remove duplicates dict from a list of dict"""

        used_key = []
        for dictionary in target_list:
            if dictionary['payload'] in used_key:
                target_list.remove(dictionary)
            else:
                used_key.append(dictionary['payload'])

    def decrypt_payload(self, encrypt_payload, user_id):
        aeskey = self.get_token(user_id)
        aesiv = self.get_iv(user_id)
        aesc = AESCipher(aeskey)
        aesc.set_iv(aesiv)
        decrypted_bytes = aesc.decrypt(encrypt_payload)
        # decrypted_bytes.hex()
        return decrypted_bytes

    def encrypt_payload(self, decrypted_payload, user_id):
        aeskey = self.get_token(user_id)
        aesiv = self.get_iv(user_id)
        aesc = AESCipher(aeskey)
        aesc.set_iv(aesiv)
        encrypted_bytes = aesc.encrypt(decrypted_payload)
        return encrypted_bytes


class UpdateOrderedDict(OrderedDict):
    """Store items in the order the keys were last added.

    Note: when max_len is reached, the oldest entry will be removed.
    """

    def __setitem__(self, key, value):
        max_len = 40
        if key in self:
            del self[key]
        if len(self) > max_len:  # If max capacity is reached (avoid mem overhead)
            # Select the first added item and delete this one
            # for obviously reason
            first_added_key = list(self.keys())[0]
            self.pop(first_added_key)
        OrderedDict.__setitem__(self, key, value)


        # lastusers= UpdateOrderedDict{id_user: [userdict]}
        # userdict = {'token': , 'iv': , 'counter'}

class SmartCommands(object):

    def __init__(self, json_file):
        with open(json_file) as json_fp:
            self.commands = json.load(json_fp)
        # print(self.commands)
    
    def check_command_type(self, command_type):
        """Return True if a command type is available"""
        if not isinstance(command_type, str):
            command_type = self.int_to_hex_with0(command_type)
        return command_type in self.commands
    
    def check_command_class(self, command_type, command_class):
        """Return True if a command class is available"""
        if not isinstance(command_class, str):
            command_class = self.int_to_hex_with0(command_class)
        if not isinstance(command_type, str):
            command_type = self.int_to_hex_with0(command_type)
        if self.check_command_type(command_type):
            return command_class in self.commands[command_type]
        else:
            return False

    def parse_command(self, smartbeacon):
        cmd_type = self.int_to_hex_with0(smartbeacon.get("cmd_type"))
        cmd_class = self.int_to_hex_with0(smartbeacon.get("cmd_class"))
        cmd_opcode = self.int_to_hex_with0(smartbeacon.get("cmd_opcode"))
        cmd_params = smartbeacon.get("cmd_params")
        cmd_bitmask = smartbeacon.get("cmd_bitmask")

        function_name = self.commands[cmd_type][cmd_class][cmd_opcode]
        if self.check_command_class(cmd_type, cmd_class):
            function_name = self.commands[cmd_type][cmd_class][cmd_opcode]
            # print(function_name)
            result = getattr(smartbeacon_command, function_name)()
        else:
            pass  # Send_invalid_command_packet()

    @staticmethod
    def int_to_hex_with0(int_16):
        """Return string Hex form (with prefix0)from int.
        
        Example: 1 -> 0x01"""
        return "0x%0.2X" % int_16