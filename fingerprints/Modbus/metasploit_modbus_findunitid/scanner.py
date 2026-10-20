from typing import List
from fingerprints import Fingerprint
from protocol_structures import ModbusPacket, UnifiedPacket


class MetasploitFindUnitIDFingerprint(Fingerprint):
    protocol_packet_types = [ModbusPacket]
    tool_name = "Metasploit Find Unit ID"


    @classmethod
    def run(cls, packets: list[UnifiedPacket]) -> list[UnifiedPacket]:
        matched_packets = []
        # Port behaviour: Increasing sequentially for every request, but consider ports being in use, so only check for strictly increasing port numbers
        # ASSUMPTION: In an interaction, all packets with a sequential port number come from the same tool. E.g., if tool X uses port y,z where z = y + x (x >= 1), a tool Y in the same interaction will not use z in this interaction
        packet_sequences: list[list[UnifiedPacket]] = []

        # Create sequences for all packets
        for packet in packets:
            sequence_found = False
            match_session_id = False

            # Decide which port is the increasing port
            if packet.request_response == "response":
                match_session_id = True

            # Check if packet can be appended to a sequence, or if a new sequence must be created
            for packet_set in packet_sequences:

                # This is a response packet, thus find the sequence with matching session ID. Can't have a response without a request.
                if match_session_id:
                    if packet_set[-1].sessionId == packet.sessionId:
                        packet_set.append(packet)
                        sequence_found = True
                        break
                else:
                    # This is a request packet
                    # Get the port of the last request packet in the packet sequence
                    expected_port = 0
                    if packet_set[-1].request_response == "request":
                        expected_port = packet_set[-1].src_port + 1
                    else:
                        expected_port = packet_set[-1].dst_port + 1
                    
                    # Account for sequential ports in use
                    if packet.src_port >= expected_port:
                        packet_set.append(packet)
                        sequence_found = True
                        break
            
            if not sequence_found:
                packet_sequences.append([])
                packet_sequences[-1].append(packet)

        # Check for all groups of packets coming from the same port if they match the tool fingerprint
        for packet_sequence in packet_sequences:
            # The request is either not Modbus, or 
            # the request is missing from the interaction. Discard this set as potential match
            if packet_sequence[0].request_response == "response":
                continue
            
            # Ensure that at least one packet is processed, in case of incomplete interactions that only consist of responses
            if len([packet for packet in packet_sequence if packet.request_response == "request"]) == 0:
                continue

            if cls.is_valid_sequence(packet_sequence):
                matched_packets += packet_sequence

        return matched_packets
    
    @classmethod
    def is_valid_sequence(cls, packets: list[ModbusPacket]) -> bool:
        expected_unit_id = packets[0].unit_id
        for packet in packets:
            # This tool does not branch requests based on responses, thus filter the set of packets to only request packets
            if packet.request_response == "response":
                continue

            # Function code behavior: Always 4
            # Unit ID behavoir: Between 1 and 254
            # Transaction ID behavoir: always 8448
            if packet.modbus_function != 4 or packet.unit_id > 254 or packet.transaction_id != 8448:
                return False
            
            if packet.unit_id == expected_unit_id:
                expected_unit_id += 1
            else:
                return False

        return True

