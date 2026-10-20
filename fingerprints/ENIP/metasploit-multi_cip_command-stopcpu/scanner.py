from protocol_structures import UnifiedPacket, ENIPPacket
from fingerprints import Fingerprint
import logging


class MetasploitMultiCipCommandStopCpuFingerprint(Fingerprint):
    protocol_packet_types = [ENIPPacket]
    tool_name = "Metasploit - MultiCip - STOPCPU"

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
        if (packet.request_response == "request" and packet.session_handle == session_handle and packet.sender_context == "0x0000000000000000" and
                packet.options == "0x00000000" and packet.timeout == "2" and packet.interface_handle == "0x00000000" and 
                packet.cip_class == "0x06" and packet.cip_service == "0x52" and packet.cip_instance == "0x01"): 
            
            # Get Connection Manager data
            cm_service = packet.function_specific_data.get("service", None)
            cm_class = packet.function_specific_data.get("class", None)
            cm_instance = packet.function_specific_data.get("instance", None)
            cm_data = packet.function_specific_data.get("data", None)

            if not (cm_service == "0x07" and cm_class == "0x64" and cm_instance == "0x01" and cm_data == "de:ad:be:ef:ca:fe"):
                return False
            
        else:
            return False

        return True
