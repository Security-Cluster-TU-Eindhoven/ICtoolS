from typing import List
from fingerprints import Fingerprint
from protocol_structures import ModbusPacket, UnifiedPacket
import logging
from typing import Tuple


class MeeasPlcScanFingerprint(Fingerprint):
    protocol_packet_types = [ModbusPacket]
    tool_name = "Meeas - PLC Scan" # Checks unit ids regardless if a correct unit id has been found

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
            # Only consider packet groups who have at most 2 packets (i.e., one request + response per port). Take into account possibility of no response due to unit ID 0 being targeted
            if len(potential_match_packets) == 1:
                if potential_match_packets[0].request_response == "request":
                    packets_to_consider.append(potential_match_packets[0])
            elif len(potential_match_packets) == 2:
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
        if len(matched_packets) < 3:
            return []

        return matched_packets
                
    
    def is_tool_start_packet(self, packet: ModbusPacket) -> bool:
        # Function code: 17
        # Transaction ID: 0
        # Unit ID: 1
        if packet.modbus_function == 43 and packet.transaction_id == 0 and packet.unit_id == 0 and packet.request_response == "request" and packet.get_function_specific_data("mei type") == 14 and packet.get_function_specific_data("Read Device ID") == 1:
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

        # Req #1, Resp #1, Req #2, Resp #2
        found = [False, False, False, False]

        for packet in packets_to_check:
            
            # Request #1 
            if packet.request_response == "request" and packet.modbus_function == 43 and packet.transaction_id == 0 and packet.unit_id == 0 and packet.get_function_specific_data("mei type") == 14 and packet.get_function_specific_data("Read Device ID") == 1 and not found[0]:
                found[0] = True
                matching_packets.append(packet)

            # Response #1 
            # Can only have found response #1 if request #1 has been found
            if packet.request_response == "response" and packet.modbus_function == 43 and packet.transaction_id == 0 and packet.unit_id == 0 and not found[1] and found[0]:
                found[1] = True
                matching_packets.append(packet)

            # Request #2
            # Can only have found request #2 if request #1 has been found (do not care about response 1 as it may be that there is no response to unit id 0)
            if packet.request_response == "request" and packet.modbus_function == 43 and packet.transaction_id == 0 and packet.unit_id == 255 and packet.get_function_specific_data("mei type") == 14 and packet.get_function_specific_data("Read Device ID") == 1 and not found[2] and found[0]:
                found[2] = True
                matching_packets.append(packet)

            # Response #2
            if packet.request_response == "response" and packet.modbus_function == 43 and packet.transaction_id == 0 and packet.unit_id == 255 and not found[3] and found[0] and found[2]:
                found[3] = True
                matching_packets.append(packet)

        is_match = found[0] and found[2] and found[3] # do not care about response #1

        return matching_packets, is_match