from typing import List
from fingerprints import Fingerprint
from protocol_structures import ModbusPacket, UnifiedPacket


class BasecampModiconStopFingerprint(Fingerprint):
    """
    Fingerprint class for identifying Basecamp Modicon Stop by analyzing Modbus packets.
    """

    protocol_packet_types = [ModbusPacket]
    tool_name = "Basecamp Modicon Stop"


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
        expected_transaction_id = 0 # also used as counter for the subfunctions index
        subfunctions = [0x02, 0x01, 0x0A, 0x03, 0x03, 0x04, 0x01, 0x0A, 0x04, 0x04, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x10, 0x04, 0x50, 0x50, 0x12, 0x04, 0x12, 0x04, 0x02, 0x58, 0x58, 0x04, 0x58,  0x41, 0x04]

        for packet in packets:
            # This tool does not branch requests based on responses, thus filter the set of packets to only request packets
            if packet.request_response == "response":
                continue
            
            # If more than 37 packets in this sequence: no match
            if expected_transaction_id >= 37:
                return False

            # Function Code behavior: 90
            # UMAS function order: 
            # Transaction ID behavior:  0 -> 36
            # Unit ID behavior: 0
            if packet.transaction_id == expected_transaction_id and packet.modbus_function == 90 and packet.unit_id == 0 and packet.get_function_specific_data("umas function code") == subfunctions[expected_transaction_id]:
                expected_transaction_id += 1
            else:
                return False
            
        return True