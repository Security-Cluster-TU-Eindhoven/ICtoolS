from typing import List
from fingerprints import Fingerprint
from protocol_structures import ModbusPacket, UnifiedPacket
import logging
from typing import Tuple


class MATRIXModbusDosAttackFingerprint(Fingerprint):
    protocol_packet_types = [ModbusPacket]
    tool_name = "karlvbiron - MATRIX - Modbus DoS attack" # Checks unit ids regardless if a correct unit id has been found

    def run(self):
        matched_packets = []
        
        # Port behaviour: same for every thread started by the tool => Group all packets that come from the same port
        potential_packet_matches: dict[tuple[str, str], list[UnifiedPacket]] = {}
        for packet in self.packets:
            if packet.request_response == "request":
                potential_packet_matches.setdefault(packet.src_port, []).append(packet)
            else:
                potential_packet_matches.setdefault(packet.dst_port, []).append(packet)

        matched_sets_count = 0
        for _, potential_match_packets in potential_packet_matches.items():
            # TCP stream behavior: All from same stream.
            # If a set of potential packet matches contains more than one session ID, it is a mismatch
            if len(set(packet.sessionId for packet in potential_match_packets)) > 1:
                continue

            # The request is either not Modbus, or 
            # the request is missing from the interaction. Discard this set as potential match
            if potential_match_packets[0].request_response == "response":
                continue

            # Ensure that at least one packet is processed, in case of incomplete interactions that only consist of responses
            if len([packet for packet in potential_match_packets if packet.request_response == "request"]) == 0:
                continue

            # To reduce false positives, check if the set of potential packets is larger than 2 (i.e., more than 5 requests, reduce potential false positives)
            if len(potential_match_packets) <= 10:
                continue

            # Check for all groups of packets coming from the same port if they match the tool fingerprint
            if self.is_valid_sequence(potential_match_packets):
                matched_sets_count += 1
                matched_packets += potential_match_packets

        return matched_packets
                
    
    def is_valid_sequence(self, packets: list[ModbusPacket]) -> bool:
        expected_transaction_id = 1
        expected_function_code = 3

        for packet in packets:
            # don't care about responses
            if packet.request_response == "response":
                continue

            # Function Code behavior: 3 -> 1, repeat
            # Transaction ID behavior: starts at 1, increases sequentially 
            # Unit ID: 1
            if packet.modbus_function == expected_function_code and packet.unit_id == 1 and packet.transaction_id == expected_transaction_id:
                if expected_function_code == 3:
                    if packet.get_function_specific_data("address") == 1 and packet.get_function_specific_data("quantity") == 125:
                        expected_function_code = 1
                    else:
                        return False
                elif expected_function_code == 1:
                    if packet.get_function_specific_data("address") == 1 and packet.get_function_specific_data("quantity") == 2000:
                        expected_function_code = 3
                    else:
                        return False

                expected_transaction_id += 1
            else:
                return False
        
        return True