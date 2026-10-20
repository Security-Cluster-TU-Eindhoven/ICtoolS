from typing import List
from fingerprints import Fingerprint
from protocol_structures import ModbusPacket, UnifiedPacket


class MarcomModbusFingerprint(Fingerprint):
    protocol_packet_types = [ModbusPacket]
    tool_name = "Marcom Modbus Scanner"


    @classmethod
    def run(cls, packets: list[UnifiedPacket]) -> list[UnifiedPacket]:
        matched_packets = []
        # Port behaviour: same for every request => Group all packets that come from the same port
        potential_packet_matches: dict[int, list[UnifiedPacket]] = {}
        for packet in packets:
            if packet.request_response == "request":
                potential_packet_matches.setdefault(packet.src_port, []).append(packet)
            else:
                potential_packet_matches.setdefault(packet.dst_port, []).append(packet)

        for _, potential_match_packets in potential_packet_matches.items():
            # TCP stream behavior: All from same stream.
            # If a set of potential packet matches contains more than one session ID, it is a mismatch
            if len(set(packet.sessionId for packet in potential_match_packets)) > 1:
                continue
            
            # The request is either not Modbus, or 
            # the request is missing from the interaction. Discard this set as potential match
            if potential_match_packets[0].request_response == "response":
                continue

            # Require at least 2 request-responses to reduce false positives that happen to match a start of this tool
            if len(potential_match_packets) < 4:
                continue

            # Ensure that at least one packet is processed, in case of incomplete interactions that only consist of responses
            if len([packet for packet in potential_match_packets if packet.request_response == "request"]) == 0:
                continue

            # Check for all groups of packets coming from the same port if they match the tool fingerprint
            if cls.is_valid_sequence(potential_match_packets):  
                matched_packets += potential_match_packets

        return matched_packets
    
    @classmethod
    def is_valid_sequence(cls, packets: list[ModbusPacket]) -> bool:
        expected_function_code = packets[0].modbus_function
        expected_unit_id = packets[0].unit_id
        expected_transaction_id = packets[0].transaction_id

        for packet in packets:
            # This tool does not branch requests based on responses, thus filter the set of packets to only request packets
            if packet.request_response == "response":
                continue
            
            # Function code behavior: Always 0, 1, 3, or 4
            # Unit ID behavior: always <= 255
            # Transaction ID behavior: always <= 255
            if packet.modbus_function not in [0, 1, 3, 4] or packet.unit_id > 255 or packet.transaction_id > 255:
                return False
            
            # Function code behavior: Loops at Unit ID loop.
            # Transaction ID behavior: increases by one every request. Loops at 255 to 0
            # Unit ID behavior: increases by one every request. Loops at 255 to 1
            if packet.modbus_function == expected_function_code and packet.transaction_id == expected_transaction_id and packet.unit_id == expected_unit_id:
                expected_transaction_id += 1
                expected_unit_id += 1

                if expected_transaction_id > 255:
                    expected_transaction_id = 0

                if expected_unit_id > 255:
                    expected_unit_id = 1
                    expected_function_code = cls.get_next_function_id(expected_function_code)
            else:
                return False
        
        return True
    
    @classmethod
    def get_next_function_id(cls, current_function_code: int) -> int:
        """
            Returns the next function code in the function code loop.
        """
        if current_function_code == 0:
            return 1
        elif current_function_code == 1:
            return 3
        elif current_function_code == 3:
            return 4
        elif current_function_code == 4:
            return 0
        
        raise Exception(f"Unexpected function code: {current_function_code}")
