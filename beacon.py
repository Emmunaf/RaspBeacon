import os
import sys
import struct
import bluetooth._bluetooth as bluez

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


class BeaconPi(object):
    """A general class useful for handling beacon"""

    def __init__(self, device_id=0):
        self.device_id = device_id

    def open_socket(self):
        self.hci_sock = bluez.hci_open_dev(self.device_id)

    @staticmethod
    def printpacket(pkt):
        """Print the packet in readable hex format"""

        for byte in pkt:
            sys.stdout.write("%02x " % struct.unpack("B", bytes([byte]))[0])
        print()
        # print("%02x " %i for i in struct.unpack("B", bytes([byte])))


    def start_le_scan(self):
        """Enable LE scan."""
        self._switch_le_scan_enable(self.hci_sock, 0x01)

    def stop_le_scan(self):
        """Disable LE scan."""
        self._switch_le_scan_enable(self.hci_sock, 0x00)

    def _switch_le_scan_enable(self, LE_Scan_Enable, filter_duplicates = 0x00):
        """Send LE SET SCAN ENABLE hci command to the current hci_socket.
        
            @params
            LE_Scan_Enable: 0x00 to disable or 0x01 to enable
            filter_duplicates: 0x00 duplicate filtering disabled, 0x01 duplicate filtering enabled
            Note: when filtering is turned on, the scanner only filters advertisements by DEVICE ADDRESS,
                  so even if the advertising data is changed, it will not get passed to the application.
        """

        # hci_sock = self.hci_sock
        print(LE_Scan_Enable)
        #if LE_Scan_Enable != 0x00 and LE_Scan_Enable != 0x01:
        #    raise ValueError("The argument enable_byte can assume just two values: 0x01 or 0x00")
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
        LE_Scan_Interval =  0x0010 # Range: 0x0004 to 0x4000 Default: 0x0010 (10 ms), Time = N * 0.625 ms, Time Range: 2.5 ms to 10.24 s
        LE_Scan_Window = 0x0010  # Duration of the LE scan. LE_Scan_Window shall be less than or equal to LE_Scan_Interval
        Own_Address_Type = 0x01  # 0x01 - Random Device Address, 0x00 - Public Device Address (default)
        Scanning_Filter_Policy = 0x00  # Accept all adv packets except directed adv packets not addressed to this device (default)
        cmd_pkt = struct.pack("<BBBBB", LE_Scan_Type, LE_Scan_Interval, LE_Scan_Window, Own_Address_Type, Scanning_Filter_Policy)  # LittleEndian(unsigned char, unsigned char, ..)
        bluez.hci_send_cmd(self.hci_sock, OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS, cmd_pkt)
        # Response?return status: 0x00LE_Set_Scan_Parameters command succeeded.
        #Note: when the user needs to receive the data as fast as possible, make sure that scanning window is more than the advertising interval + 10ms to guarantee discovery. 

    def read(self):
        """Calling read on an open HCI hci_socket waits for and receives the next event from the microcontroller. An event consists of a header field specifying the event type, and the event parameters. A program that requires asynchronous device detection would, for example, send a command with ocf of OCF_INQUIRY and wait for events of type EVT_INQUIRY_RESULT and EVT_INQUIRY_COMPLETE. The specific codes to use for each command and event are defined in the specifications and in the BlueZ source code."""
        pass

    def le_handle_connection_complete(self, pkt):
        status, handle, role, peer_bdaddr_type = struct.unpack("<BHBB", pkt[0:5])
        device_address = self.packed_bdaddr_to_string(pkt[5:11])
        interval, latency, supervision_timeout, master_clock_accuracy = struct.unpack("<HHHB", pkt[11:])
        #print "le_handle_connection output"
        #print "status: 0x%02x\nhandle: 0x%04x" % (status, handle)
        #print "role: 0x%02x" % role
        #print "device address: ", device_address
        
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
        #bluez.ba2str, str2ba

    def hci_le_parse_event(self, pkt):
        """Parse a BLE packet.
            Returns a dictionary which contains the event id, length and packet type,
            and possibly additional key/value pairs that represent the parsed content
            of the packet.
        """

        result = {}
        hci_packet_type, event, param_len = struct.unpack("<BBB", pkt[:3])
        result["packet_type"] = hci_packet_type
        result["bluetooth_event_id"] = event
        result["packet_length"] = param_len
        result["full_packet_str"] = self.packet_as_hex_string(pkt)
        result["full_packet_bin"] = pkt

        # We check only for BLE events
        if event == LE_META_EVENT:
            result["bluetooth_event_name"] = "EVT_LE_META_EVENT"
            result.update(self._handle_le_meta_event(pkt[3:]))

        elif event == bluez.EVT_NUM_COMP_PKTS:
            result["bluetooth_event_name"] = "EVT_NUM_COMP_PKTS"
            #result.update(_handle_num_completed_packets(pkt[3:]))

        elif event == bluez.EVT_INQUIRY_RESULT_WITH_RSSI:
            result["bluetooth_event_name"] = "EVT_INQUIRY_RESULT_WITH_RSSI"
            #result.update(_handle_inquiry_result_with_rssi(pkt[3:]))

        elif event == bluez.EVT_INQUIRY_RESULT:
            result["bluetooth_event_name"] = "EVT_INQUIRY_RESULT"
            #result.update(_handle_inquiry_result(pkt[3:]))

        elif event == bluez.EVT_DISCONN_COMPLETE:
            result["bluetooth_event_name"] = "EVT_DISCONN_COMPLETE"
            #result.update(_handle_disconn_complete(pkt[3:]))

        elif event == bluez.EVT_CMD_STATUS:
            result["bluetooth_event_name"] = "EVT_CMD_STATUS"
            #result.update(_handle_command_status(pkt[3:]))

        elif event == bluez.EVT_CMD_COMPLETE:
            result["bluetooth_event_name"] = "EVT_CMD_COMPLETE"
            #result.update(_handle_command_complete(pkt[3:]))

        elif event == bluez.EVT_INQUIRY_COMPLETE:
            pass
            #raise NotImplementedError("EVT_CMD_COMPLETE")

        else:
            result["bluetooth_event_name"] = "UNKNOWN"

        return result

    def _handle_le_meta_event(self, pkt):
        result = {}
        subevent, = struct.unpack("B", bytes(pkt[0]))
        result["bluetooth_le_subevent_id"] = subevent
        pkt = pkt[1:]
        if subevent == EVT_LE_ADVERTISING_REPORT:
            result["bluetooth_le_subevent_name"] = "EVT_LE_ADVERTISING_REPORT"
            result.update(self._handle_le_advertising_report(pkt))

        elif subevent == EVT_LE_CONN_COMPLETE:
            result["bluetooth_le_subevent_name"] = "EVT_LE_CONN_COMPLETE"
            #result.update(_handle_le_connection_complete(pkt))

        elif subevent == EVT_LE_CONN_UPDATE_COMPLETE:
            result["bluetooth_le_subevent_name"] = "EVT_LE_CONN_UPDATE_COMPLETE"
            #raise NotImplementedError("EVT_LE_CONN_UPDATE_COMPLETE")

        elif subevent == EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE:
            result["bluetooth_le_subevent_name"] = \
                "EVT_LE_READ_REMOTE_USED_FEATURES_COMPLETE"
            # result.update(_handle_le_read_remote_used_features(pkt))

        else:
            result["bluetooth_le_subevent_name"] = "UNKNOWN"

        return result

    def _handle_le_advertising_report(self, pkt):
        result = {}
        num_reports = struct.unpack("<B", pkt[0])[0]
        report_pkt_offset = 0
        result["number_of_advertising_reports"] = num_reports
        result["advertising_reports"] = []
        
        for i in range(0, num_reports):
            report = {}
            report_event_type = struct.unpack("<B", pkt[report_pkt_offset + 1])[0]
            report["report_type_id"] = report_event_type

            bdaddr_type = struct.unpack("<B", pkt[report_pkt_offset + 2])[0]
            report["peer_bluetooth_address_type"] = bdaddr_type

            device_addr = self.packed_bdaddr_to_string(
                pkt[report_pkt_offset + 3:report_pkt_offset + 9])
            report["peer_bluetooth_address"] = device_addr.upper()
            report["peer_bluetooth_address_s"] = \
                self.space_bt_address(report["peer_bluetooth_address"])

            report_data_length, = struct.unpack("<B", pkt[report_pkt_offset + 9])
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

            # Each report length is (2 (event type, bdaddr type) + 6 (the address)
            #    + 1 (data length field) + data length + 1 (rssi)) bytes long.
            report_pkt_offset = report_pkt_offset + 10 + report_data_length + 1
            rssi, = struct.unpack("<b", pkt[report_pkt_offset - 1])
            report["rssi"] = rssi
            result["advertising_reports"].append(report)

        return result

    def parse_events(self, loop_count=100):
        return True
        # Save the current filter, for restoring later.
        old_filter = self.hci_sock.getsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, 14)

        # perform a device inquiry on bluetooth device #0
        # The inquiry should last 8 * 1.28 = 10.24 seconds
        # before the inquiry is performed, bluez should flush its cache of
        # previously discovered devices
        flt = bluez.hci_filter_new()
        bluez.hci_filter_all_events(flt)
        bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
        self.hci_sock.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, flt)
        done = False
        myFullList = []
        for i in range(0, loop_count):
            #Adv PDU type: ADV_NONCONN_IND (0x02): Non-connectable undirected advertising which cannot be connected to and cannot respond to a scan request.
            pkt = self.hci_sock.recv(255)
            # print("Received from socket: ", pkt)
            # HCI packet type codes (ptype):HCI Command = 0x01, syncronous Data = 0x02, Event = 0x04
            # (HCI packetype, Event, parameterLenght)
            # http://rrbluetoothx.blogspot.it/2016/05/rr-bluetooth-gatttool-what-hci-commands.html
            ptype, event, plen = struct.unpack("<BBB", bytes(pkt[:3]))
            # print("--------------"
            if event == bluez.EVT_INQUIRY_RESULT_WITH_RSSI:
                pass
            elif event == bluez.EVT_NUM_COMP_PKTS:
                pass
            elif event == bluez.EVT_DISCONN_COMPLETE:
                pass
            elif event == LE_META_EVENT:
                subevent, = struct.unpack("B", bytes([pkt[3]]))
                pkt = pkt[4:]
                if subevent == EVT_LE_CONN_COMPLETE:
                    #le_handle_connection_complete(pkt)
                    pass
                elif subevent == EVT_LE_ADVERTISING_REPORT:
                    # print("advertising report"
                    # First byte of packet is the....
                    num_reports = struct.unpack("B", bytes([pkt[0]]))[0]
                    report_pkt_offset = 0
                    # When there are more (Num_Reports > 1) advertising reports packed into one event
                    # https://stackoverflow.com/questions/26275679/ble-hci-le-advertising-report-event-data-format
                    for i in range(0, num_reports):
                        if DEBUG:
                            print("-------------")
                            # print("\tfullpacket: ", printpacket(pkt)
                            print("\tUDID: ", printpacket(pkt[report_pkt_offset - 22: report_pkt_offset - 6]))
                            print("\tMAJOR: ", printpacket(pkt[report_pkt_offset - 6: report_pkt_offset - 4]))
                            print("\tMINOR: ", printpacket(pkt[report_pkt_offset - 4: report_pkt_offset - 2]))
                            print("\tMAC address: ", self.packed_bdaddr_to_string(pkt[report_pkt_offset + 3:report_pkt_offset + 9]))
                            # commented out - don't know what this byte is.  It's NOT TXPower
                            txpower, = struct.unpack("b", bytes([pkt[report_pkt_offset - 2]]))
                            print("\t(Unknown):", txpower)

                            rssi, = struct.unpack("b", bytes([pkt[report_pkt_offset - 1]]))
                            print("\tRSSI:", rssi)
                    # build the return string
                    Adstring = self.packed_bdaddr_to_string(pkt[report_pkt_offset + 3:report_pkt_offset + 9])
                    Adstring += ","
                    Adstring += returnstringpacket(pkt[report_pkt_offset - 22: report_pkt_offset - 6])
                    Adstring += ","
                    Adstring += "%i" % returnnumberpacket(pkt[report_pkt_offset - 6: report_pkt_offset - 4])
                    Adstring += ","
                    Adstring += "%i" % returnnumberpacket(pkt[report_pkt_offset - 4: report_pkt_offset - 2])
                    Adstring += ","
                    Adstring += "%i" % struct.unpack("b", bytes([pkt[report_pkt_offset - 2]]))
                    Adstring += ","
                    Adstring += "%i" % struct.unpack("b", bytes([pkt[report_pkt_offset - 1]]))

                    # print("\tAdstring=", Adstring
                    myFullList.append(Adstring)
                done = True
        self.hci_sock.setsockopt(bluez.SOL_HCI, bluez.HCI_FILTER, old_filter)
        return myFullList

    def packet_as_hex_string(self, pkt, spacing=False,
                        capitalize=False):
        packet = ""
        space = ""
        if (spacing):
            space = " "
        for b in pkt:
            packet = packet + "%02x" % struct.unpack("<B", b)[0] + space
        if (capitalize):
            packet = packet.upper()
        return packet

    def space_bt_address(self, bt_address):
        return ''.join(bt_address.split(':'))
    '''
    # verify received beacon packet format
    def verify_beacon_packet(report):
        result = False
        # check payload length (31byte)
        if (report["report_metadata_length"] != 31):
            return result
        # check Company ID (OMRON = 0x02D5)
        if (struct.unpack("<B", report["payload_binary"][4])[0] !=
                ADV_TYPE_MANUFACTURER_SPECIFIC_DATA):
            return result
        if (get_companyid(report["payload_binary"][5:7]) != COMPANY_ID):
            return result
        # check shortened local name ("IM")
        if (struct.unpack("<B", report["payload_binary"][28])[0] !=
                ADV_TYPE_SHORT_LOCAL_NAME):
            return result
        if ((report["payload_binary"][29:31] != "IM") and
                (report["payload_binary"][29:31] != "EP")):
            return result

        result = True
        return result


    # classify beacon type sent from the sensor
    def classify_beacon_packet(report):
        if (report["payload_binary"][29:31] == "IM"):
            return "IM"
        elif (report["payload_binary"][29:31] == "EP"):
            return "EP"
        else:
            return "UNKNOWN"
            '''
#getsockopt(level, optname[, buflen]) -- get socket options\n\
"""
 * params:  (int) device number
 * effect: opens and binds a new HCI socket
 * return: a PySocketSockObject, or NULL on failure
"""
#http://dev.ti.com/tirex/content/simplelink_academy_cc2640r2sdk_1_12_01_16/modules/ble_scan_adv_basic/ble_scan_adv_basic.html
#https://raw.githubusercontent.com/jmleglise/mylittle-domoticz/master/Presence-detection-beacon/check_beacon_presence.py
# https://books.google.it/books?id=3nCuDgAAQBAJ&pg=PA198&lpg=PA198&dq=hci+protocol+META+EVENT&source=bl&ots=rLU4o_v7na&sig=4IE82kPP5vfr-ShewNbIuqD_K3g&hl=it&sa=X&ved=0ahUKEwiZldihnuzZAhWiDcAKHZPmAD4Q6AEILDAA#v=onepage&q=hci%20protocol%20META%20EVENT&f=false
# http://rrbluetoothx.blogspot.it/2016/