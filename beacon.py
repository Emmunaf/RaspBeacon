import os
import sys
import struct
import bluetooth._bluetooth as bluez

from AESCipher import AESCipher

"""
BlueZ usage resource:
https://people.csail.mit.edu/albert/bluez-intro/x682.html"""

# Dict:
# hci_sock is an open HCI socket
# OGF is the Opcode Group Field
# OCF is the Opcode Command Field
# cmd_pkt contains the command parameters
# Note1: For the Link Control commands, the OGF is defined as 0x01. For the LE Controller Commands, the OGF code is defined as 0x08.
# Note2:  the reversed byte order (multibyte values in BLE packets are in little-endian order).
LE_META_EVENT = 0x3e
LE_PUBLIC_ADDRESS = 0x00
LE_RANDOM_ADDRESS = 0x01
LE_SET_SCAN_PARAMETERS_CP_SIZE = 7
OGF_LE_CTL = 0x08
OCF_LE_SET_SCAN_PARAMETERS = 0x000B
OCF_LE_SET_SCAN_ENABLE = 0x000C
OCF_LE_CREATE_CONN = 0x000D
OCF_LE_SET_ADVERTISING_DATA = 0x0008
OCF_LE_SET_ADVERTISING_ENABLE = 0x000A
LE_ROLE_MASTER = 0x00
LE_ROLE_SLAVE = 0x01

# The host computer can send commands to the microcontroller, and the microcontroller generates events to indicate command responses and other status changes.
# Subevents of LE_META_EVENT
EVT_LE_CONN_COMPLETE = 0x01
EVT_LE_ADVERTISING_REPORT = 0x02
EVT_LE_CONN_UPDATE_COMPLETE = 0x03
EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE = 0x04

# Advertisment event types
# Glossary:
# connectable: a scanner can start a connection after be notified by this event
# scannable: a scanner can start a scan request after receving one of these
# undirected: broadcast trasmission, no Bluetooth address is specified
# payload: can contain user-defined data in payload unlike a directed packet
ADV_IND = 0x00  # connectable undirected advertising event
ADV_DIRECT_IND = 0x01  # connectable directed advertising event
ADV_NONCONN_IND = 0x02  # non-connectable undirected advertising event
SCAN_REQ = 0x03  # scan request
ADV_SCAN_RSP = 0x04  # scan response
CONNECT_REQ = 0x05  # connection request
ADV_DISCOVER_IND = 0x06  # scannable undirected advertising
BEACON_TYPE_CODE = 0xBEAC # Alt Beacon identifier

ADV_TYPE_MANUFACTURER_SPECIFIC_DATA = 0xFF
COMPANY_ID = 0x8888
ADV_RSSI_VALUE = -59

class BeaconPi(object):
    """A general class useful for handling beacon"""

    def __init__(self, device_id=0):
        self.device_id = device_id

    def open_socket(self):
        self.hci_sock = bluez.hci_open_dev(self.device_id)
        print("socket opened")
        return self.hci_sock

    @staticmethod
    def printpacket(pkt):
        """Print the packet in readable hex format"""
        ret_str = ""
        for byte in pkt:
            ret_str += ("%02x " % struct.unpack("B", bytes([byte]))[0])
        return (ret_str)
        # print("%02x " %i for i in struct.unpack("B", bytes([byte])))

    @staticmethod
    def packet2str(pkt):
        """TODO the packet in readable hex format"""
        return ("%02x " % byte for byte in struct.unpack("B", bytes([byte])))

    def start_le_scan(self):
        """Enable LE scan."""
        self._switch_le_scan_enable(0x01)

    def stop_le_scan(self):
        """Disable LE scan."""
        self._switch_le_scan_enable(0x00)

    def _switch_le_scan_enable(self, LE_Scan_Enable, filter_duplicates=0x00):
        """Send LE SET SCAN ENABLE hci command to the current hci_socket.
        
            @params
            LE_Scan_Enable: 0x00 to disable or 0x01 to enable
            filter_duplicates: 0x00 duplicate filtering disabled, 0x01 duplicate filtering enabled
            Note: when filtering is turned on, the scanner only filters advertisements by DEVICE ADDRESS,
                  so even if the advertising data is changed, it will not get passed to the application.
        """

        if LE_Scan_Enable != 0x00 and LE_Scan_Enable != 0x01:
            raise ValueError("The argument enable_byte can assume just two values: 0x01 or 0x00")
        if filter_duplicates != 0x00 and filter_duplicates != 0x01:
            raise ValueError("The argument filter_duplicates can assume just two values: 0x01 or 0x00")
        # Create the structure needed for the parameters of the LE SET SCAN ENABLE hci command
        cmd_pkt = struct.pack("<BB", LE_Scan_Enable, filter_duplicates)  # LittleEndian(unsigned char, unsigned char)
        # In BlueZ, hci_send_cmd is used to transmit a command to the microcontroller.
        # A command consists of a Opcode Group Field that specifies the general category the command falls into, an Opcode Command Field that specifies the actual command, and a series of command parameters.
        bluez.hci_send_cmd(self.hci_sock, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, cmd_pkt)
        # Response? return status: 0x00 if command was successful!

    def hci_le_set_scan_parameters(self):
        """Set the parameters needed for a scan"""

        # old_filter = hci_sock.getsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, 14)  # when restore the filter? somethign like hci_le_restore_scan_parameters()? not needed?
        LE_Scan_Type = 0x00  # Passive Scanning. No scanning PDUs shall be sent (default)
        LE_Scan_Interval = 0x0010  # Range: 0x0004 to 0x4000 Default: 0x0010 (10 ms), Time = N * 0.625 ms, Time Range: 2.5 ms to 10.24 s
        LE_Scan_Window = 0x0010  # Duration of the LE scan. LE_Scan_Window shall be less than or equal to LE_Scan_Interval
        Own_Address_Type = 0x01  # 0x01 - Random Device Address, 0x00 - Public Device Address (default)
        Scanning_Filter_Policy = 0x00  # Accept all adv packets except directed adv packets not addressed to this device (default)
        cmd_pkt = struct.pack("<BBBBB", LE_Scan_Type, LE_Scan_Interval, LE_Scan_Window, Own_Address_Type,
                              Scanning_Filter_Policy)  # LittleEndian(unsigned char, unsigned char, ..)
        return bluez.hci_send_cmd(self.hci_sock, OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS, cmd_pkt)
        # Response?return status: 0x00LE_Set_Scan_Parameters command succeeded.
        # Note: when the user needs to receive the data as fast as possible, make sure that scanning window is more than the advertising interval + 10ms to guarantee discovery.

    def read(self):
        """Calling read on an open HCI hci_socket waits for and receives the next event from the microcontroller. An event consists of a header field specifying the event type, and the event parameters. A program that requires asynchronous device detection would, for example, send a command with ocf of OCF_INQUIRY and wait for events of type EVT_INQUIRY_RESULT and EVT_INQUIRY_COMPLETE. The specific codes to use for each command and event are defined in the specifications and in the BlueZ source code."""
        pass

    def le_handle_connection_complete(self, pkt):
        status, handle, role, peer_bdaddr_type = struct.unpack("<BHBB", pkt[0:5])
        device_address = self.packed_bdaddr_to_string(pkt[5:11])
        interval, latency, supervision_timeout, master_clock_accuracy = struct.unpack("<HHHB", pkt[11:])
        # print "le_handle_connection output"
        # print "status: 0x%02x\nhandle: 0x%04x" % (status, handle)
        # print "role: 0x%02x" % role
        # print "device address: ", device_address

    def get_packed_bdaddr(self, address_str):
        """Return a byte packed address from a string form(AA:BB:..)"""

        address_bytelist = []
        addr = address_str.split(':')
        addr.reverse()  # Needed for LittleEndian encoding. TODO should i try BigEndian and not reverse?
        for b in addr:
            address_bytelist.append(int(b, 16))
        return struct.pack("<BBBBBB", *address_bytelist)

    def packed_bdaddr_to_string(self, address_byte):
        """Return a MAC address in str form, from a byte object"""
        return ':'.join('%02x' % i for i in struct.unpack("<BBBBBB", bytes(address_byte[::-1])))  # TODO controlla
        # TODO maybe use: bluez.ba2str, str2ba ?

    def hci_le_parse_event(self, pkt):
        """Parse a BLE packet.
            Returns a dictionary which contains the event id, length and packet type,
            and others additional key/value pairs that represent the parsed content
            of the packet in binary and string form.
        """

        # print("hci_le_parse_event called")
        result = {}
        # (HCI packetype, Event, parameterLenght)
        # HCI packettype codes (ptype):HCI Command = 0x01, syncronous Data = 0x02, Event = 0x04
        hci_packet_type, event, param_len = struct.unpack("<BBB", pkt[:3])
        result["packet_type"] = hci_packet_type
        result["bluetooth_event_id"] = event
        result["packet_length"] = param_len
        result["full_packet_str"] = self.packet_as_hex_string(pkt)
        result["full_packet_bin"] = pkt
        # print(result)

        # We check only for BLE events
        if event == LE_META_EVENT:
            # We are looking for a beacon( BLE Advertisement) 
            # EVT_LE_META_EVENT is the event name related to it
            result["bluetooth_event_name"] = "EVT_LE_META_EVENT"
            result.update(self._handle_le_meta_event(pkt[3:]))

        elif event == bluez.EVT_NUM_COMP_PKTS:
            result["bluetooth_event_name"] = "EVT_NUM_COMP_PKTS"
            # result.update(_handle_num_completed_packets(pkt[3:]))

        elif event == bluez.EVT_INQUIRY_RESULT_WITH_RSSI:
            result["bluetooth_event_name"] = "EVT_INQUIRY_RESULT_WITH_RSSI"
            # result.update(_handle_inquiry_result_with_rssi(pkt[3:]))

        elif event == bluez.EVT_INQUIRY_RESULT:
            result["bluetooth_event_name"] = "EVT_INQUIRY_RESULT"
            # result.update(_handle_inquiry_result(pkt[3:]))

        elif event == bluez.EVT_DISCONN_COMPLETE:
            result["bluetooth_event_name"] = "EVT_DISCONN_COMPLETE"
            # result.update(_handle_disconn_complete(pkt[3:]))

        elif event == bluez.EVT_CMD_STATUS:
            result["bluetooth_event_name"] = "EVT_CMD_STATUS"
            # result.update(_handle_command_status(pkt[3:]))

        elif event == bluez.EVT_CMD_COMPLETE:
            result["bluetooth_event_name"] = "EVT_CMD_COMPLETE"
            # result.update(_handle_command_complete(pkt[3:]))

        elif event == bluez.EVT_INQUIRY_COMPLETE:
            result["bluetooth_event_name"] = "EVT_INQUIRY_COMPLETE"

        else:
            result["bluetooth_event_name"] = "UNKNOWN"

        return result

    def _handle_le_meta_event(self, pkt):
        result = {}
        subevent, = struct.unpack("B", bytes([pkt[0]]))
        result["bluetooth_le_subevent_id"] = subevent
        pkt = pkt[1:]
        if subevent == EVT_LE_ADVERTISING_REPORT:
            result["bluetooth_le_subevent_name"] = "EVT_LE_ADVERTISING_REPORT"
            result.update(self._handle_le_advertising_report(pkt))

        elif subevent == EVT_LE_CONN_COMPLETE:
            result["bluetooth_le_subevent_name"] = "EVT_LE_CONN_COMPLETE"
            # result.update(_handle_le_connection_complete(pkt))

        elif subevent == EVT_LE_CONN_UPDATE_COMPLETE:
            result["bluetooth_le_subevent_name"] = "EVT_LE_CONN_UPDATE_COMPLETE"
            # raise NotImplementedError("EVT_LE_CONN_UPDATE_COMPLETE")

        elif subevent == EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE:
            result["bluetooth_le_subevent_name"] = \
                "EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE"
            # result.update(_handle_le_read_remote_used_features(pkt))

        else:
            result["bluetooth_le_subevent_name"] = "UNKNOWN"

        return result

    def _handle_le_advertising_report(self, pkt):
        result = {}
        # 
        num_reports = struct.unpack("<B", bytes([pkt[0]]))[0]
        report_pkt_offset = 0
        result["number_of_advertising_reports"] = num_reports
        result["advertising_reports"] = []

        for i in range(0, num_reports):
            report = {}
            report_event_type = struct.unpack("<B", bytes([pkt[report_pkt_offset + 1]]))[0]
            report["report_type_id"] = report_event_type

            bdaddr_type = struct.unpack("<B", bytes([pkt[report_pkt_offset + 2]]))[0]
            report["peer_bluetooth_address_type"] = bdaddr_type

            device_addr = self.packed_bdaddr_to_string(
                pkt[report_pkt_offset + 3:report_pkt_offset + 9])
            report["peer_bluetooth_address"] = device_addr.upper()
            report["peer_bluetooth_address_s"] = \
                self.space_bt_address(report["peer_bluetooth_address"])

            report_data_length, = struct.unpack("<B", bytes([pkt[report_pkt_offset + 9]]))
            report["report_metadata_length"] = report_data_length

            if report_event_type == ADV_IND:
                report["report_type_string"] = "LE_ADV_IND"

            elif report_event_type == ADV_DIRECT_IND:
                report["report_type_string"] = "LE_ADV_DIRECT_IND"

            elif report_event_type == ADV_DISCOVER_IND:
                report["report_type_string"] = "LE_ADV_SCAN_IND"

            elif report_event_type == ADV_NONCONN_IND:
                report["report_type_string"] = "LE_ADV_NONCONN_IND"

            elif report_event_type == ADV_SCAN_RSP:
                report["report_type_string"] = "LE_ADV_SCAN_RSP"

            else:
                report["report_type_string"] = "UNKNOWN"

            if report_data_length > 0:
                report["payload_binary"] = \
                    (pkt[report_pkt_offset +
                         10:report_pkt_offset +
                            10 + report_data_length + 1])
                report["payload"] = self.packet_as_hex_string(
                    report["payload_binary"], True, True)
                # Parse the data payload after proximity_type
                report["payload_data"] = report["payload_binary"][6:]
                report["payload_encrypted_data"] = report["payload_data"][:report_pkt_offset - 7]
                major, = struct.unpack(">H", bytes(pkt[report_pkt_offset - 7: report_pkt_offset - 5]))
                minor, = struct.unpack(">H", bytes(pkt[report_pkt_offset - 5: report_pkt_offset - 3]))
                report["major"] = major
                report["minor"] = minor
                if len(report["payload_encrypted_data"]) == 16:
                    report["decrypted_payload"] = self.decrypt_payload(report["payload_encrypted_data"])
                # print("MAC address: ", self.packed_bdaddr_to_string(pkt[report_pkt_offset + 3:report_pkt_offset + 9]))
                txpower_2_complement, = struct.unpack("b", bytes([pkt[report_pkt_offset - 2]]))
                # print("(Unknown):", txpower)
            # Each report length is (2 (event type, bdaddr type) + 6 (the address)
            #    + 1 (data length field) + data length + 1 (rssi)) bytes long.
            report_pkt_offset = report_pkt_offset + 10 + report_data_length + 1
            rssi, = struct.unpack("<b", bytes([pkt[report_pkt_offset - 1]]))
            report["rssi"] = rssi
            #result["advertising_reports"].append(report)
            if self.verify_beacon_packet(report):
                result["advertising_reports"].append(report)
                print(report["decrypted_payload"].hex())
        return result

    def get_companyid(self, pkt):
        # 2 bytes as Little Endian 
        return (struct.unpack("<H", bytes(pkt))[0])

    def get_beacon_type(self, pkt):
        # 2 bytes Big Endian 
        return (struct.unpack(">H", bytes(pkt))[0])

    def verify_beacon_packet(self, report):
        result = False
        # check payload length (28byte)
        if (report["report_metadata_length"] != 28):
            return result
        # check Company ID (LEL = 0x8888) $4,5:7 
        if (struct.unpack("<B", bytes([report["payload_binary"][1]]))[0] !=
                ADV_TYPE_MANUFACTURER_SPECIFIC_DATA):
            return result
        if (self.get_companyid(report["payload_binary"][2:4]) != COMPANY_ID):
            return result

        if (self.get_beacon_type(report["payload_binary"][4:6]) != BEACON_TYPE_CODE):
            return result

        if len(report["payload_encrypted_data"]) != 16: #  AES blocksize
            return result
        # 6:28 DataPayload

        result = True
        return result

    def parse_events(self, loop_count=10):
        # Save the current filter, for restoring later.
        old_filter = self.hci_sock.getsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, 14)
        flt = bluez.hci_filter_new()
        bluez.hci_filter_all_events(flt)
        bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
        self.hci_sock.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, flt)
        #print("Waiting for socket")
        pkt = self.hci_sock.recv(255)
        
        debug = False
        # Analyze what is received and parse usefull data
        parsed_packet = self.hci_le_parse_event(pkt)
        if "bluetooth_le_subevent_name" in parsed_packet and \
            (parsed_packet["bluetooth_le_subevent_name"] == 'EVT_LE_ADVERTISING_REPORT'):
            if debug:
                for report in parsed_packet["advertising_reports"]:
                    self.print_report(report, pkt)

            for report in parsed_packet["advertising_reports"]:
                # if (self.verify_smart_beacon_packet(report)):
                # If match our format we should do something
                if self.verify_beacon_packet(report):
                    self.print_report(report, pkt)
                pass
        self.hci_sock.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, old_filter)

    def decrypt_payload(self, pkt):
        AESkey = b'\x9b\xd9\xcd\xf6\xbe+\x9dX\xfb\xd2\xef>\xd87i\xa0\xca\xf5o\xd0\xac\xc3\xe0R\xf0z\xfa\xb8\xdd\x01?E'
        AESiv = b'\xef\xaa)\x9fHQ\x0f\x04\x18\x1e\xb5;B\xff\x1c\x01'
        aesc = AESCipher(AESkey)
        aesc.set_iv(AESiv)
        decrypted_bytes = aesc.decrypt(pkt)
        # decrypted_bytes.hex()
        return decrypted_bytes

    def encrypt_payload(self, pkt):
        AESkey = b'\x9b\xd9\xcd\xf6\xbe+\x9dX\xfb\xd2\xef>\xd87i\xa0\xca\xf5o\xd0\xac\xc3\xe0R\xf0z\xfa\xb8\xdd\x01?E'
        AESiv = b'\xef\xaa)\x9fHQ\x0f\x04\x18\x1e\xb5;B\xff\x1c\x01'
        aesc = AESCipher(AESkey)
        aesc.set_iv(AESiv)
        encrypted_bytes = aesc.encrypt(pkt)
        return encrypted_bytes

    def packet_as_hex_string(self, pkt, spacing=False,
                             capitalize=False):
        packet = ""
        space = ""
        if spacing:
            space = " "
        for b in pkt:
            packet = packet + "%02x" % struct.unpack("<B", bytes([b]))[0] + space
        if capitalize:
            packet = packet.upper()
        return packet

    def space_bt_address(self, bt_address):
        return ''.join(bt_address.split(':'))

    def print_report(self, report, pkt):
        print("----------------------------------------------------")
        print("Found BLE device:", report['peer_bluetooth_address'])
        print("Raw Advertising Packet:")
        print(self.packet_as_hex_string(pkt, True, True))
        print("")
        for k, v in report.items():
            if k == "payload_binary":
                continue
            print("\t%s: %s" % (k, v))
        print("")
    
    def le_set_advertising_data(self, adv_data):
        # Change filter/mode TODO
        # LE Set Advertising Data ->
        # Advertising Data Flags (not part of AltBeacon standard)
        AD_LENGHT_FLAG = 0x02   # Number of AD flag structure
        AD_TYPE_FLAG = 0x01     # Type of AD structure as Flags type
        AD_DATA_FLAG = 0x1a    # Flags data LE General Discoverable
        
        adv_header_flags = struct.pack(">BBB", AD_LENGHT_FLAG, AD_TYPE_FLAG, AD_DATA_FLAG)

        AD_DATA_LEN = 27 # Lenght of advertisement (for ALTBeaconstandard = 0x1b)
        cmd_pkt = struct.pack(">BB", AD_DATA_LEN, ADV_TYPE_MANUFACTURER_SPECIFIC_DATA)
        cmd_pkt += struct.pack("<H", COMPANY_ID)
        cmd_pkt += struct.pack(">H", BEACON_TYPE_CODE)
        # Custom values begins here
        cmd_data_payload = struct.pack(">Q", adv_data["counter"])
        cmd_data_payload += struct.pack(">BBBh", adv_data["cmd_type"], adv_data["cmd_class"], adv_data["cmd_opcode"], adv_data["cmd_params"])
        cmd_data_payload += adv_data.get("bitmap", struct.pack("B", (0xFF)))
        cmd_data_payload += struct.pack(">B", adv_data.get("RES1", 0x00))
        cmd_data_payload += struct.pack(">B", adv_data.get("RES2", 0x00))
        cmd_data_payload_enc = self.encrypt_payload(cmd_data_payload)
        # Add the encrypted payload
        cmd_pkt += cmd_data_payload_enc
        cmd_pkt += struct.pack(">H", adv_data["user_id"])
        cmd_pkt += struct.pack(">BB", adv_data["obj_category"], adv_data["obj_id"])
        cmd_pkt += struct.pack(">bB", ADV_RSSI_VALUE, 0x00)  # Last byte is manufacturer reserved
        cmd_pkt = adv_header_flags + cmd_pkt
        # In BlueZ, hci_send_cmd is used to transmit a command to the microcontroller.
        # A command consists of a Opcode Group Field that specifies the general category the command falls into, an Opcode Command Field that specifies the actual command, and a series of command parameters.
        print(cmd_pkt.hex())
        return bluez.hci_send_cmd(self.hci_sock, OGF_LE_CTL, OCF_LE_SET_ADVERTISING_DATA, cmd_pkt)

    def le_set_advertising_status(self, enable = True):
        
        if enable:
            enable_byte = 0x01
        else:
            enable_byte = 0x00
        # Create the structure needed for the parameters of the LE SET SCAN ENABLE hci command
        cmd_pkt = struct.pack("<B", enable_byte)  # LittleEndian(unsigned char, unsigned char)
        # In BlueZ, hci_send_cmd is used to transmit a command to the microcontroller.
        # A command consists of a Opcode Group Field that specifies the general category the command falls into, an Opcode Command Field that specifies the actual command, and a series of command parameters.
        return bluez.hci_send_cmd(self.hci_sock, OGF_LE_CTL, OCF_LE_SET_ADVERTISING_ENABLE, cmd_pkt)
        # Response? return status: 0x00 if command was successful!

    def send_ack(self, user_id, counter):
        adv_data = {"counter": counter, "cmd_type": 0xFF, "cmd_class": 0xFF, "cmd_opcode":0xFF, "cmd_params": user_id, "user_id": user_id, "obj_category": 0x00, "obj_id": 0x00}
        # Need to disable scan?
        self.le_set_advertising_data(adv_data)
        # Need to reenable scan?

# getsockopt(level, optname[, buflen]) -- get socket options\n\
"""
 * params:  (int) device number
 * effect: opens and binds a new HCI socket
 * return: a PySocketSockObject, or NULL on failure
"""
# http://dev.ti.com/tirex/content/simplelink_academy_cc2640r2sdk_1_12_01_16/modules/ble_scan_adv_basic/ble_scan_adv_basic.html
# https://raw.githubusercontent.com/jmleglise/mylittle-domoticz/master/Presence-detection-beacon/check_beacon_presence.py
# https://books.google.it/books?id=3nCuDgAAQBAJ&pg=PA198&lpg=PA198&dq=hci+protocol+META+EVENT&source=bl&ots=rLU4o_v7na&sig=4IE82kPP5vfr-ShewNbIuqD_K3g&hl=it&sa=X&ved=0ahUKEwiZldihnuzZAhWiDcAKHZPmAD4Q6AEILDAA#v=onepage&q=hci%20protocol%20META%20EVENT&f=false
# http://rrbluetoothx.blogspot.it/2016/


"""
 /*
        IBeacon format found at http://stackoverflow.com/questions/18906988/what-is-the-ibeacon-bluetooth-profile
        02 # Number of bytes that follow in first AD structure  # Just iBeacon
        01 # Flags AD type # Just iBeacon
        1A # Flags value 0x1A = 000011010 # Just iBeacon
        # Alt beacon begins here
        bit 0 (OFF) LE Limited Discoverable Mode
        bit 1 (ON) LE General Discoverable Mode
        bit 2 (OFF) BR/EDR Not Supported
        bit 3 (ON) Simultaneous LE and BR/EDR to Same Device Capable (controller)
        bit 4 (ON) Simultaneous LE and BR/EDR to Same Device Capable (Host)
        1A # Number of bytes that follow in second (and last) AD structure
        FF # Manufacturer specific data AD type
        4C 00 # Company identifier code (0x004C == Apple)
        02 # Byte 0 of iBeacon advertisement indicator
        15 # Byte 1 of iBeacon advertisement indicator
        e2 c5 6d b5 df fb 48 d2 b0 60 d0 f5 a7 10 96 e0 # iBeacon proximity uuid
        00 00 # major
        00 00 # minor
        c5 # The 2's complement of the calibrated Tx Power
    */
"""

"""
# Raw avertise packet data from Bluez scan
        # Packet Type (1byte) + BT Event ID (1byte) + Packet Length (1byte) +
        # BLE sub-Event ID (1byte) + Number of Advertising reports (1byte) +
        # Report type ID (1byte) + BT Address Type (1byte) + BT Address (6byte) +
        # Data Length (1byte) + Data ((Data Length)byte) + RSSI (1byte)
        #
        # Packet Type = 0x04
        # BT Event ID = EVT_LE_META_EVENT = 0x3E (BLE events)
        # (All LE commands result in a metaevent, specified by BLE sub-Event ID)
        # BLE sub-Event ID = {
        #                       EVT_LE_CONN_COMPLETE = 0x01
        #                       EVT_LE_ADVERTISING_REPORT = 0x02
        #                       EVT_LE_CONN_UPDATE_COMPLETE = 0x03
        #                       EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE = 0x04
        #                       EVT_LE_LTK_REQUEST = 0x05
        #                     }
        # Number of Advertising reports = 0x01 (normally)
        # Report type ID = {
        #                       LE_ADV_IND = 0x00
        #                       LE_ADV_DIRECT_IND = 0x01
        #                       LE_ADV_SCAN_IND = 0x02
        #                       LE_ADV_NONCONN_IND = 0x03
        #                       LE_ADV_SCAN_RSP = 0x04
        #                   }
        # BT Address Type = {
        #                       LE_PUBLIC_ADDRESS = 0x00
        #                       LE_RANDOM_ADDRESS = 0x01
        #                    }
        # Data Length = 0x00 - 0x1F
        # * Maximum Data Length of an advertising packet = 0x1F
"""
