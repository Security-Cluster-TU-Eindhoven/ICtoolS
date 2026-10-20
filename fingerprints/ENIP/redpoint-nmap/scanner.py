from protocol_structures import UnifiedPacket, ENIPPacket
from fingerprints import Fingerprint
import logging


class DigitalBondRedpointENIPFingerprint(Fingerprint):
    protocol_packet_types = [ENIPPacket]
    tool_name = "Digital Bond - Redpoint - ENIP"

    @classmethod
    def run(cls, packets: list[UnifiedPacket]) -> list[UnifiedPacket]:
        matched_packets = []
        # Port behaviour: same for every request => Group all packets that come from the same port
        potential_packet_matches: dict[tuple[str, str], list[UnifiedPacket]] = {}
        for packet in packets:
            if packet.request_response == "request":
                potential_packet_matches.setdefault(packet.src_port, []).append(packet)
            else:
                potential_packet_matches.setdefault(packet.dst_port, []).append(packet)

        for _, potential_match_packets in potential_packet_matches.items():
            # Single request
            if len(potential_match_packets) > 2:
                continue

            # the request is missing from the interaction. Discard this set as potential match
            if potential_match_packets[0].request_response == "response":
                continue

            # Fingerprint contains 1 request
            if len([packet for packet in potential_match_packets if packet.request_response == "request"]) != 1:
                continue
            
            # Check for all groups of packets coming from the same port if they match the tool fingerprint
            if cls.is_valid_sequence(potential_match_packets):  
                matched_packets += potential_match_packets

        return matched_packets
    
    @classmethod
    def is_valid_sequence(cls, packets: list[ENIPPacket]) -> bool:
        packet = packets[0]
        if not (packet.request_response == "request" and packet.transport_layer == "TCP" and packet.command == "0x63" and packet.sender_context == "0x00000000c1debed1"
                and packet.options == "0x00000000"):
            return False
        
        return True
