from log_parsers import LogParser
from protocol_structures import ModbusPacket
import os
from pathlib import Path
from typing import List, Dict
from protocol_structures import ModbusPacket
from log_parsers.constants.modbus_function_codes import function_codes, mei_type_codes, umas_codes
import logging

class ModbusZeekParser(LogParser):

    @staticmethod
    def parse_directory(directory: Path) -> list[ModbusPacket]:
        """
        Parses all relevant Zeek log files (modbus.log, modbus_detailed.log,
        modbus_read_device_identification.log, modbus_umas.log and conn.log) in the specified
        directory, converting them into a list of ModbusPacket instances.
        Subdirectories are not searched: main.py already hands every log directory to the parser.
        """
        packets = []

        logger = logging.getLogger("Modbus Zeek Parser")

        # Only look at this directory; nested directories are passed separately by main.py
        base_logs = list(directory.glob('modbus.log'))

        for base_log in base_logs:
            # Find the corresponding detailed and identification logs in the same directory
            detailed_log = base_log.parent / 'modbus_detailed.log'
            identification_log = base_log.parent / 'modbus_read_device_identification.log'
            conn_log = base_log.parent / 'conn.log'
            umas_log = base_log.parent / 'modbus_umas.log'
            # Check if both the detailed and identification logs exist
            if not (detailed_log.exists()):
                logger.warning(f"Missing \"modbus_detailed.log\" in: {base_log.parent}. Note that the packets parsed in this folder may not contain all necessary Modbus fingerprinting information.")
            if not (identification_log.exists()):
                logger.warning(f"Missing \"modbus_read_device_identification.log\" Zeek logs in: {base_log.parent}. Note that the packets parsed in this folder may not contain all necessary Modbus fingerprinting information.")
            if not (conn_log.exists()):
                logger.warning(f"Missing \"conn.log\" Zeek logs in: {base_log.parent}. Packet loss cannot be detected for the packets parsed in this folder.")
            if not (umas_log.exists()):
                logger.warning(f"Missing \"modbus_umas.log\" Zeek logs in: {base_log.parent}. Note that the packets parsed in this folder may not contain all necessary Modbus fingerprinting information.")

            packets.extend(
                ModbusZeekParser.parse_zeek_logs(str(base_log), str(detailed_log), str(identification_log), str(conn_log), str(umas_log))
            )


        return packets
    

    
    @staticmethod
    def parse_zeek_log(filename: str) -> List[Dict[str, str]]:
        """
        Parses a Zeek log file and returns a list of dictionaries, each representing a log entry.

        Args:
            filename (str): Path to the Zeek log file.

        Returns:
            List[Dict[str, str]]: A list of dictionaries representing log entries.
        """
        entries = []
        if not os.path.exists(filename):
            # Warning about this is already logged somewhere else
            return entries

        with open(filename, 'r') as f:
            field_names = []
            for line in f:
                line = line.strip()
                if line.startswith('#fields'):
                    field_names = line.split()[1:]
                elif line.startswith('#') or not line:
                    continue
                else:
                    values = line.split('\t')
                    entry = dict(zip(field_names, values))
                    # Ensure all fields are present in the entry
                    for field in field_names:
                        if field not in entry:
                            entry[field] = None

                    entries.append(entry)
        return entries
    


    @staticmethod
    def parse_zeek_logs(base_log: str, detailed_log: str, identification_log: str, conn_log: str, umas_log: str) -> List[ModbusPacket]:
        """
        Converts Zeek logs to a list of ModbusPackets instances, using the base modbus.log as the primary
        log, and adding extra details from modbus_detailed.log and modbus_read_device_identification.log
        if a match is found.
        """
        logger = logging.getLogger("Modbus Zeek Parser")

        modbus_base_entries = ModbusZeekParser.parse_zeek_log(base_log)
        modbus_detailed_entries = ModbusZeekParser.parse_zeek_log(detailed_log)
        modbus_identification_entries = ModbusZeekParser.parse_zeek_log(identification_log)
        conn_log = ModbusZeekParser.parse_zeek_log(conn_log)

        conn_log_dict = {
            entry['uid']: int(entry['missed_bytes']) if entry.get('missed_bytes') not in (None, '-') else 0
            for entry in conn_log
        }


        modbus_umas_entries = ModbusZeekParser.parse_zeek_log(umas_log)

        modbus_detailed_dict: dict[tuple[str, str, str ,str, str], list] = {}
        for entry in modbus_detailed_entries:
            modbus_detailed_dict.setdefault((entry['ts'], entry['id.orig_h'], entry['id.orig_p'], entry['id.resp_h'], entry['id.resp_p'], entry['request_response']), []).append(entry)

        modbus_identification_dict: dict[tuple[str, str, str ,str, str], list] = {}
        for entry in modbus_identification_entries:
            modbus_identification_dict.setdefault((entry['ts'], entry['id.orig_h'], entry['id.orig_p'], entry['id.resp_h'], entry['id.resp_p'], entry['request_response']), []).append(entry)

        # added the modbus umas log to the parser
        modbus_umas_dict = {
            (entry['ts'], entry['id.orig_h'], entry['id.orig_p'], entry['id.resp_h'], entry['id.resp_p'], entry['request_response']): entry
            for entry in modbus_umas_entries
        }

        modbus_logs = []

        for base_entry in modbus_base_entries:
            tainted = conn_log_dict.get(base_entry['uid'], 0) > 0

            request_response_key = ""

            if base_entry['pdu_type'] == "REQ":
                request_response_key = "REQUEST"
            elif base_entry['pdu_type'] == "RESP":
                request_response_key = "RESPONSE"
            else:
                raise IndexError("no correct request or response pdu type identified in logs, cannot create a match key to link detailed logs to base logs")


            match_key = (base_entry['ts'], base_entry['id.orig_h'], base_entry['id.orig_p'], base_entry['id.resp_h'], base_entry['id.resp_p'], request_response_key)
            
            # Extract fields from base log
            timestamp = base_entry['ts']
            uid = base_entry['uid']



            # IP data
            pdu_type = base_entry['pdu_type'] if base_entry['pdu_type'] and base_entry['pdu_type'] != '-' else None
            request_response = "request" if pdu_type == "REQ" else "response"
            zeek_origin_ip = base_entry['id.orig_h']
            zeek_origin_port = int(base_entry['id.orig_p']) if base_entry['id.orig_p'] and base_entry['id.orig_p'] != '-' else None
            zeek_target_ip = base_entry['id.resp_h']
            zeek_target_port = int(base_entry['id.resp_p']) if base_entry['id.resp_p'] and base_entry['id.resp_p'] != '-' else None

            # Zeek's modbus.log always sets the origin IP to the requester and response IP to the Modbus device, even if it is a response packet
            # This is corrected here, ensuring that the source IP & port always relates to the packet source and visa versa
            src_ip = zeek_origin_ip if request_response == "request" else zeek_target_ip
            src_port = zeek_origin_port if request_response == "request" else zeek_target_port
            dst_ip = zeek_target_ip if request_response == "request" else zeek_origin_ip
            dst_port = zeek_target_port if request_response == "request" else zeek_origin_port
            
            # Modbus data
            modbus_function_name = base_entry['func']
            trans_id = int(base_entry['tid']) if base_entry['tid'] and base_entry['tid'] != '-' else None
            unit_id = int(base_entry['unit']) if base_entry['unit'] and base_entry['unit'] != '-' else None


            modbus_function_code = -1
            if modbus_function_name.startswith('unknown-'):
                modbus_function_code = int(modbus_function_name.split('-')[1])
                logger.debug(f"Found unknown Modbus function code: {modbus_function_code}, pay attention to this packet")
            elif modbus_function_name in function_codes:
                modbus_function_code = function_codes[modbus_function_name]
            else:
                logger.debug(f"Found unknown Modbus function name: {modbus_function_name}, pay attention to this packet")

            is_exception = modbus_function_code >= 128
            if is_exception:
                modbus_function_code -= 128

            # Extract additional details from detailed and identification logs
            address = quantity = values = mei_type = None
            conformity_level_code = conformity_level = device_id_code = None
            object_id_code = object_id = object_value = is_orig = None



            function_specific_data = {}

            if match_key in modbus_identification_dict:
                for entry in modbus_identification_dict[match_key]:
                    #identification_entry = modbus_identification_dict[match_key]
                    mei_type_raw = entry.get('mei_type', '-')
                    mei_type = mei_type_codes.get(mei_type_raw) if mei_type_raw != '-' else None
                    if mei_type is None and mei_type_raw != '-':
                        try:
                            mei_type = int(mei_type_raw, 0)  # Corrected to handle hex values like '0x00'
                        except ValueError:
                            mei_type = None
                    
                    function_specific_data["mei type"] = mei_type

                    function_specific_data["Read Device ID"] = int(entry['device_id_code'], 0) if entry.get('device_id_code', '-') != '-' else None
                    object_id = entry.get('object_id', '-') if entry.get('object_id', '-') != '-' else None
                    if object_id is not None:
                        function_specific_data[object_id] = entry.get('object_value', '-') if entry.get('object_value', '-') != '-' else None

            
            if match_key in modbus_umas_dict:
                umas_entry = modbus_umas_dict[match_key]
                umas_func = umas_entry.get('umas_func', '-') if umas_entry.get('umas_func', '-') != '-' else None
                if umas_func in umas_codes:
                    umas_func = umas_codes[umas_func]
                elif umas_func is not None and umas_func.startswith("unknown-"):
                    umas_func = int(umas_func[len("unknown-"):])

                function_specific_data["umas function code"] = umas_func
                function_specific_data["umas session key"] = umas_entry.get('session_key', '-') if umas_entry.get('session_key', '-') != '-' else None

            if match_key in modbus_detailed_dict:
                for detailed_entry in modbus_detailed_dict[match_key]:
                    if detailed_entry['address'] and detailed_entry['address'] != '-':
                        function_specific_data["address"] = int(detailed_entry['address'])

                    if detailed_entry['quantity'] and detailed_entry['quantity'] != '-':
                        function_specific_data["quantity"] = int(detailed_entry['quantity'])

                    if detailed_entry['values'] and detailed_entry['values'] != '-' and ".log" not in detailed_entry['values']:
                        function_specific_data["values"] = detailed_entry['values']

                    modbus_log = ModbusPacket(
                    timestamp=timestamp,
                    sessionId=uid,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    request_response=request_response,
                    modbus_function=modbus_function_code,
                    unit_id=unit_id,
                    transaction_id=trans_id,
                    is_exception=is_exception,
                    function_specific_data=function_specific_data,
                    tainted=tainted,
                    tool_matches=[]
                )

                modbus_logs.append(modbus_log)
            else:
                modbus_log = ModbusPacket(
                    timestamp=timestamp,
                    sessionId=uid,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    request_response=request_response,
                    modbus_function=modbus_function_code,
                    unit_id=unit_id,
                    transaction_id=trans_id,
                    is_exception=is_exception,
                    function_specific_data=function_specific_data,
                    tainted=tainted,
                    tool_matches=[]
                )

                modbus_logs.append(modbus_log)
        return modbus_logs