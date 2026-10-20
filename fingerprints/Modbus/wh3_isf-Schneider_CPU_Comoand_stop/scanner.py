from typing import List
from fingerprints import Fingerprint
from protocol_structures import ModbusPacket, UnifiedPacket


class ISFSchneiderStopFingerprint(Fingerprint):
    protocol_packet_types = [ModbusPacket]
    tool_name = "w3h ISF - Schneider CPU command (stop)"

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
    
    @staticmethod
    def is_valid_sequence(packets: list[ModbusPacket]) -> bool:
        expected_transaction_ids = [312,344]
        expected_subfunctions = [0x10, 0x41]

        expected_index = 0

        for packet in packets:
            # This tool does not branch requests based on responses, thus filter the set of packets to only request packets
            if packet.request_response == "response":
                continue

            # Function Code behavior: 90
            # Transaction ID behavior:  312 -> 344
            # Unit ID behavior: 0
            if packet.transaction_id == expected_transaction_ids[expected_index] and packet.modbus_function == 90 and packet.unit_id == 0 and packet.get_function_specific_data("umas function code") == expected_subfunctions[expected_index]:
                expected_index += 1
            else:
                return False

        # Means that the second request is also a match
        if expected_index != 2:
            return False
        
        return True

