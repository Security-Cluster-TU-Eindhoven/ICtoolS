from protocol_structures import UnifiedPacket, ENIPPacket
from fingerprints import Fingerprint
import logging


class MetasploitMultiCipCommandCrashEtherFingerprint(Fingerprint):
    protocol_packet_types = [ENIPPacket]
    tool_name = "Metasploit - MultiCip - CRASHETHER"

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

            # Fingerprint contains 2 requests
            if len([packet for packet in potential_match_packets if packet.request_response == "request"]) != 2:
                continue
            
            # Check for all groups of packets coming from the same port if they match the tool fingerprint
            if cls.is_valid_sequence(potential_match_packets):  
                matched_packets += potential_match_packets

        return matched_packets
    
    @classmethod
    def is_valid_sequence(cls, packets: list[ENIPPacket]) -> bool:
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
        if not (packet.request_response == "request" and packet.session_handle == session_handle and packet.sender_context == "0x2000020000000000" and
                packet.options == "0x000c00b2" and packet.timeout == "292" and packet.item_count == "17168" and packet.interface_handle == "0xf520030e"): 
            return False

        return True
