from typing import List
from fingerprints import Fingerprint
from protocol_structures import ModbusPacket, UnifiedPacket


class MatrixCoilWriteFingerprint(Fingerprint):
    protocol_packet_types = [ModbusPacket]
    tool_name = "karlvbiron - MATRIX modbus coil write attack"

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

            # Fingerprint consists of two requests
            if len([packet for packet in potential_match_packets if packet.request_response == "request"]) != 2:
                continue

            # Check for all groups of packets coming from the same port if they match the tool fingerprint
            if cls.is_valid_sequence(potential_match_packets):  
                matched_packets += potential_match_packets

        return matched_packets
    
    @classmethod
    def is_valid_sequence(cls, packets: list[ModbusPacket]) -> bool:
        expected_functions = [15, 1]
        expected_transaction_ids = [1, 2]

        expected_index = 0

        for packet in packets:
            # This tool does not branch requests based on responses, thus filter the set of packets to only request packets
            if packet.request_response == "response":
                continue

            # Function Code behavior: 15 -> 1 (write, read)
            # Transaction ID behavior:  1 -> 2
            # Unit ID: 1
            if packet.transaction_id == expected_transaction_ids[expected_index] and packet.modbus_function == expected_functions[expected_index] and packet.unit_id == 1 and packet.get_function_specific_data("address") == 0 and packet.get_function_specific_data("quantity") == 8:
                if expected_index == 0:
                    if packet.get_function_specific_data("values") != "T,T,T,T,F,F,F,F": # Writes a single byte with the following values: 1,1,1,1,0,0,0,0
                        return False

                expected_index += 1
            else:
                return False

        # Means that the second request is also a match
        if expected_index != 2:
            return False
        
        return True

