from typing import List
from fingerprints import Fingerprint
from protocol_structures import ModbusPacket, UnifiedPacket
import logging
from typing import Tuple


class NMAPFingerprint(Fingerprint):
    protocol_packet_types = [ModbusPacket]
    tool_name = "NMAP" # Checks unit ids regardless if a correct unit id has been found

    def run(self):
        matched_packets = []
        # Port behaviour: New session every request
        # First: Group all packets on the same port, discard all groups with more than 2 packets (multiple request on same port). 
        # Second: sort all remaining packets by timestamp
        # Third: Loop over all packets to confirm that every request has a response, and that a next request is only send after a response (otherwise 
        potential_packet_sequence_matches: dict[int, list[UnifiedPacket]] = {}
        for packet in self.packets:
            if packet.request_response == "request":
                potential_packet_sequence_matches.setdefault(packet.src_port, []).append(packet)
            else:
                potential_packet_sequence_matches.setdefault(packet.dst_port, []).append(packet)

        packets_to_consider = []
        for _, potential_match_packets in potential_packet_sequence_matches.items():
            # Only consider packet groups who only have 1 request and 1 response on the requester's port (i.e., one request per port and different ports for every request)
            if len(potential_match_packets) == 2:
                if potential_match_packets[0].request_response == "request" and potential_match_packets[1].request_response == "response":
                    packets_to_consider.append(potential_match_packets[0])
                    packets_to_consider.append(potential_match_packets[1])

        # Sort packets chronologically
        packets_to_consider.sort(key = lambda x: float(x.timestamp))  # Faster than implementing a cmp function https://stackoverflow.com/questions/403421/how-do-i-sort-a-list-of-objects-based-on-an-attribute-of-the-objects

        packets_to_exclude = []
        # Loop over all packets to see if they could be a starting packet for this tool, then check for that packet
        for i in range(0, len(packets_to_consider)):
            index = len(packets_to_consider) - 1 - i
            if self.is_tool_start_packet(packets_to_consider[index]):
                relevant_packets, is_match = self.find_matching_packets(packets_to_consider[index:], matched_packets)
                packets_to_exclude += relevant_packets
                if is_match:
                    matched_packets += relevant_packets
        
        # If less than 1 cycle (1x func 17, 1x func 43) has only been identified, return no matched packets
        if len(matched_packets) < 4:
            return []

        return matched_packets
                
    
    def is_tool_start_packet(self, packet: ModbusPacket) -> bool:
        # Function code: 17
        # Transaction ID: 0
        # Unit ID: 1
        if packet.modbus_function == 17 and packet.transaction_id == 0 and packet.unit_id == 1 and packet.request_response == "request":
            return True

    def find_matching_packets(self, packets: list[ModbusPacket], packets_to_exclude: list[ModbusPacket]) -> Tuple[list[ModbusPacket], bool]:
        """
            Return what packets match + if they are a match or if any disproving characteristics are found.
        """
        is_match = True
        matching_packets = []
        expected_unit_id = 1
        expected_function_code = 17

        packets_to_check = [packet for packet in packets if packet not in packets_to_exclude]

        # Sanity check
        if not self.is_tool_start_packet(packets_to_check[0]):
            return [], False
        
        looking_for = "request" # "request" or "response"

        for packet in packets_to_check:
            if packet.request_response != looking_for:
                continue
            
            if packet.modbus_function == expected_function_code and packet.unit_id == expected_unit_id and packet.transaction_id == 0:
                matching_packets.append(packet)
                
                if looking_for == "response":
                    looking_for = "request"
                    if expected_function_code == 17:
                        expected_function_code = 43
                    elif expected_function_code == 43: # Sanity check instead of "else"
                        expected_function_code = 17
                        expected_unit_id += 1
                elif looking_for == "request":
                    looking_for = "response"


        return matching_packets, is_match