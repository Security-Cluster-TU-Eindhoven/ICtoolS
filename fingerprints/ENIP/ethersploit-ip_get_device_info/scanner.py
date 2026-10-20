from protocol_structures import UnifiedPacket, ENIPPacket
from fingerprints import Fingerprint
import logging


class EtherSploitIpFingerprint(Fingerprint):
    protocol_packet_types = [ENIPPacket]
    tool_name = "EtherSploit/IP - get device info"

    def run(self) -> list[UnifiedPacket]:
            matched_packets = []
            # Port behaviour: same for every request => Group all packets that come from the same port
            potential_packet_matches: dict[tuple[str, str], list[UnifiedPacket]] = {}
            for packet in self.packets:
                if packet.request_response == "request":
                    potential_packet_matches.setdefault(packet.src_port, []).append(packet)
                else:
                    potential_packet_matches.setdefault(packet.dst_port, []).append(packet)

            for _, potential_match_packets in potential_packet_matches.items():
                # TCP stream behavior: All from same stream.
                # If a set of potential packet matches contains more than one session ID, it is a mismatch
                if len(set(packet.sessionId for packet in potential_match_packets)) > 1:
                    continue

                # the request is missing from the interaction. Discard this set as potential match
                if potential_match_packets[0].request_response == "response":
                    continue

                # Fingerprint contains 2 requests
                if len([packet for packet in potential_match_packets if packet.request_response == "request"]) != 2:
                    continue
                
                # 2 requests, 2 responses
                if len(potential_match_packets) != 4:
                    continue

                # To reduce false positives, check if the set of potential packets is larger than 2 (i.e., more than 1 request)
                if len(potential_match_packets) <= 2:
                    continue

                # Check for all groups of packets coming from the same port if they match the tool fingerprint
                if self.is_valid_sequence(potential_match_packets):  
                    matched_packets += potential_match_packets

            return matched_packets


    def is_valid_sequence(self, packets: list[ENIPPacket]) -> bool:
        if packets[0].sender_context != "0x0000000000000000" or packets[0].command != "0x65":
            return False

        if packets[2].contains_cip:
            if not (
                packets[2].command == "0x6f"
                and packets[2].cip_service == "0x01"
                and packets[2].cip_instance == "0x01"
                and packets[2].cip_class == "0x01"
                and packets[2].cip_path_segment == "0x20"
            ):
                return False
        else:
            return False

        return True