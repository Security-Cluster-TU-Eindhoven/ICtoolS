from typing import List
from fingerprints import Fingerprint
from protocol_structures import ModbusPacket, UnifiedPacket


class ModbussploitDosWriteCoilsFingerprint(Fingerprint):
    """
    Fingerprint class for identifying C4l1b4n Modbussploit DoS Write Coils by analyzing Modbus packets.
    """

    protocol_packet_types = [ModbusPacket]
    tool_name = "C4l1b4n Modbussploit DoS Write Coils"


    @classmethod
    def run(cls, packets: list[UnifiedPacket]) -> list[UnifiedPacket]:
        matched_packets = []
        # Port behaviour: same for every request for each thread (default: 20) => Group all packets that come from the same port, confirm that no unexpected packets are in each port group
        potential_packet_matches: dict[tuple[str, str], list[UnifiedPacket]] = {}
        for packet in packets:
            if packet.request_response == "request":
                potential_packet_matches.setdefault(packet.src_port, []).append(packet)
            else:
                potential_packet_matches.setdefault(packet.dst_port, []).append(packet)


        matched_groups = 0
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

            # To reduce false positives, check if the set of potential packets is larger than 2 (i.e., more than 1 request)
            if len(potential_match_packets) <= 2:
                continue

            # Check for all groups of packets coming from the same port if they match the tool fingerprint
            if cls.is_valid_sequence(potential_match_packets):  
                matched_packets += potential_match_packets
                matched_groups += 1

        # only if 20 packet groups match, match this fingerprint. This method considers the possibility of multiple tools being present in these packets, while ensuring that false positives are reduced to a minimum
        if matched_groups == 20:
            return matched_packets
        else:
            return []

    @classmethod
    def is_valid_sequence(cls, packets: list[ModbusPacket]) -> bool:
        for packet in packets:
            # This tool does not branch requests based on responses, thus filter the set of packets to only request packets
            if packet.request_response == "response":
                continue

            # Function Code behavior: always 5
            # Transaction ID behavior:  always 6147
            # Unit ID behavior: always 1
            if packet.transaction_id == 6147 and packet.modbus_function == 5 and packet.unit_id == 1:
                continue
            else:
                return False

        return True