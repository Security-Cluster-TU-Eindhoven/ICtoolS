from typing import List
from fingerprints import Fingerprint
from protocol_structures import ModbusPacket, UnifiedPacket


class MetasploitBannerGrabbingFingerprint(Fingerprint):
    protocol_packet_types = [ModbusPacket]
    tool_name = "Metasploit Banner Grabbing"

    def run(self) -> list[UnifiedPacket]:
        matched_packets = []
        # Port behaviour: single request => Group all packets that come from the same port
        potential_packet_sequence_matches: dict[int, list[UnifiedPacket]] = {}
        for packet in self.packets:
            if packet.request_response == "request":
                potential_packet_sequence_matches.setdefault(packet.src_port, []).append(packet)
            else:
                potential_packet_sequence_matches.setdefault(packet.dst_port, []).append(packet)

        for _, potential_match_packets in potential_packet_sequence_matches.items():
            # TCP stream behavior: All from same stream.
            # If a set of potential packet matches contains more than one session ID, it is a mismatch
            if len(set(packet.sessionId for packet in potential_match_packets)) > 1:
                continue

            # Tool behavior: Tool does a single request, thus potential sequences with more than 2 packets (request + response) are a mismatch
            if len(potential_match_packets) > 2:
                continue

            # If this set of packets contains only 1 packet, and that packet is a response. The request is either not Modbus, or 
            # the request is missing from the interaction. Discard this set as potential match
            if potential_match_packets[0].request_response == "response":
                continue

            # Ensure that at least one packet is processed, in case of incomplete interactions that only consist of responses
            if len([packet for packet in potential_match_packets if packet.request_response == "request"]) == 0:
                continue

            # Check for all groups of packets coming from the same port if they match the tool fingerprint
            if self.is_valid_sequence(potential_match_packets):  
                matched_packets += potential_match_packets

        return matched_packets
    
    def is_valid_sequence(self, packets: list[ModbusPacket]) -> bool:
        # Only the request packet is relevant
        packet = packets[0]
    
        # Packet must be a request (sanity check)
        # Function code behaviour: always 43
        # Unit ID behaviour: always 255
        # Transaction ID behaviour: always 17506
        # MEI type behaviour: always 14
        # Device ID code behaviour: always 3
        return (packet.request_response == "request" and packet.modbus_function == 43 and packet.unit_id == 255 and packet.transaction_id == 17506 
            and packet.get_function_specific_data("mei type") == 14 and packet.get_function_specific_data("Read Device ID") == 3)