from protocol_structures import UnifiedPacket, ENIPPacket
from fingerprints import Fingerprint
import logging


class EIPScannerFingerprint(Fingerprint):
    protocol_packet_types = [ENIPPacket]
    tool_name = "EIPScanner"

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
                # the request is missing from the interaction. Discard this set as potential match
                if potential_match_packets[0].request_response == "response":
                    continue

                # Fingerprint contains at most 4 requests, at least 3
                num_requests = len([packet for packet in potential_match_packets if packet.request_response == "request"])
                if num_requests > 4 or num_requests < 3:
                    continue

                # Sender context always 0x0000000000000000
                if len([packet for packet in potential_match_packets if packet.sender_context != "0x0000000000000000"]) > 0:
                    continue
                
                # Check for all groups of packets coming from the same port if they match the tool fingerprint
                if cls.is_valid_sequence(potential_match_packets):  
                    matched_packets += potential_match_packets

            return matched_packets

    @classmethod
    def is_valid_sequence(cls, packets: list[ENIPPacket]) -> bool:
        if len(packets) < 5:
            return False

        session_handle = None
        packet = packets[0]
        # Check if the first packet is a session register
        if not (packet.request_response == "request" and packet.command == "0x65" and packet.session_handle == "0x00000000"):
            return False
        
        packet = packets[1]
        if not(packet.request_response == "response" and packet.command == "0x65"):
            return False
        
        session_handle = packet.session_handle # Session handle in first response

        packet = packets[2]
        if not (packet.request_response == "request" and packet.session_handle == session_handle and packet.contains_cip 
            and packet.cip_service == "0x0e" and packet.cip_class == "0x0001" and packet.cip_instance == "0x0001" and packet.cip_attribute == "1"):
            return False
        
        packet = packets[4]
        if not (packet.request_response == "request" and packet.session_handle == session_handle and packet.contains_cip 
            and packet.cip_service == "0x10" and packet.cip_class == "0x0004" and packet.cip_instance == "0x0097" and packet.cip_attribute == "3"):
            return False
        
        return True