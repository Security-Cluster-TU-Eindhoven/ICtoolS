from typing import List, Dict
from typing import List
from collections import defaultdict
from fingerprints import Fingerprint
from protocol_structures import ModbusPacket, UnifiedPacket

class FernillScanFingerprint(Fingerprint):
    protocol_packet_types = [ModbusPacket]
    tool_name = "Fernill Scan"


    @classmethod
    def run(cls, packets: list[UnifiedPacket]) -> list[UnifiedPacket]:
        matched_packets = []
        # Port behaviour: same for every request => Group all packets that come from the same port
        potential_packet_matches: dict[int, list[UnifiedPacket]] = {}
        for packet in packets:
            if packet.request_response == "request":
                potential_packet_matches.setdefault(packet.src_port, []).append(packet)
            else:
                potential_packet_matches.setdefault(packet.dst_port, []).append(packet)

        for _, potential_match_packets in potential_packet_matches.items():
            # TCP stream behavior: All from same stream.
            # If a set of potential packet matches contains more than one session ID, it is a mismatch
            if len(set(packet.sessionId for packet in potential_match_packets)) > 1:
                continue

            # The request is either not Modbus, or 
            # the request is missing from the interaction. Discard this set as potential match
            if potential_match_packets[0].request_response == "response":
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
        expected_unit_id = 1
        expected_transaction_id = 1

        for packet in packets:
            # This tool does not branch requests based on responses, thus filter the set of packets to only request packets
            if packet.request_response == "response":
                continue

            # Function code behavior: This tool only uses function code 8
            # Unit id behavior: This tool only uses Unit IDs between 1 and 255
            # Transaction ID behavior: This tool only uses transaction IDs between 1 and 255
            if packet.modbus_function != 8 or packet.transaction_id > 255 or packet.unit_id > 255:
                return False
            
            # Transaction ID behavior: increases by one every request
            # Unit ID behavior: increases by one every request
            if packet.transaction_id == expected_transaction_id and packet.unit_id == expected_unit_id:
                expected_transaction_id += 1
                expected_unit_id += 1
            else:
                return False

        return True