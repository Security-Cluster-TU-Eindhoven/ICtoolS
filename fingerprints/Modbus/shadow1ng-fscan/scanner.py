from typing import List
from fingerprints import Fingerprint
from protocol_structures import ModbusPacket, UnifiedPacket


class FscanFingerprint(Fingerprint):
    protocol_packet_types = [ModbusPacket]
    tool_name = "Shadow1ng - fscan"

    @classmethod
    def run(cls, packets: list[UnifiedPacket]) -> list[UnifiedPacket]:
        matched_packets = []
        # Port behaviour: single request => Group all packets that come from the same port
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

            # If this set of packets contains only 1 packet, and that packet is a response. The request is either not Modbus, or 
            # the request is missing from the interaction. Discard this set as potential match
            if potential_match_packets[0].request_response == "response":
                continue

            # Single request, so only one request should be present
            if len([packet for packet in potential_match_packets if packet.request_response == "request"]) != 1:
                continue

            # Check for all groups of packets coming from the same port if they match the tool fingerprint
            if cls.is_valid_sequence(potential_match_packets):  
                matched_packets += potential_match_packets

        return matched_packets
    
    @staticmethod
    def is_valid_sequence(packets: list[ModbusPacket]) -> bool:
            packet = packets[0]
    
            return packet.request_response == "request" and packet.transaction_id == 1 and packet.modbus_function == 1 and packet.unit_id == 1 and packet.get_function_specific_data("address") == 0
