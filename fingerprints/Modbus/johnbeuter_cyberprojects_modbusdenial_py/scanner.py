from typing import List
from fingerprints import Fingerprint
from protocol_structures import ModbusPacket, UnifiedPacket


class CyberProjectsModbusDenialPyFingerprint(Fingerprint):
    protocol_packet_types = [ModbusPacket]
    tool_name = "JohnBeuter - Cyberprojects - Modbus denial (python)"

    @classmethod
    def run(cls, packets: list[UnifiedPacket]) -> list[UnifiedPacket]:
        matched_packets = []
        # Port behaviour: all same port
        potential_packet_sequence_matches: dict[int, list[UnifiedPacket]] = {}
        for packet in packets:
            if packet.request_response == "request":
                potential_packet_sequence_matches.setdefault(packet.src_port, []).append(packet)
            else:
                potential_packet_sequence_matches.setdefault(packet.dst_port, []).append(packet)

        for _, potential_match_packets in potential_packet_sequence_matches.items():
            # TCP stream behavior: All from same stream.
            # If a set of potential packet matches contains more than one session ID, it is a mismatch
            if len(set(packet.sessionId for packet in potential_match_packets)) > 1:
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
        expected_functions = [5, 5, 5, 5, 1]
        expected_reference_numbers = [0, 1, 2, 3, 0]
        expected_index = 0

        for packet in packets:
            # This tool does not branch requests based on responses, thus filter the set of packets to only request packets
            if packet.request_response == "response":
                continue

            # Function Code behavior: see expected functions
            # Transaction ID behavior: random
            # Unit ID: 1
            if packet.modbus_function == expected_functions[expected_index] and packet.unit_id == 1 and packet.get_function_specific_data("address") == expected_reference_numbers[expected_index]:
                if expected_index == 4:
                    expected_index = 0
                else:
                    expected_index += 1
            else:
                return False
        
        return True

