from typing import List
from fingerprints import Fingerprint
from protocol_structures import ModbusPacket, UnifiedPacket
import logging
from typing import Tuple


class SModDosGalilrioFingerprint(Fingerprint):
    protocol_packet_types = [ModbusPacket]
    tool_name = "Smod - galilRIO" # Checks unit ids regardless if a correct unit id has been found

    def run(self):
        # Port behaviour: New session every request, but account for port reuse due to the amount of packets being used.
        matched_packets = []

        packets_to_exclude = []
        # Loop over all packets to see if they could be a starting packet for this tool, then check for that packet
        for i in range(0, len(self.packets)):
            relevant_packets, is_match = self.find_matching_packets(self.packets[i:], matched_packets)
            packets_to_exclude += relevant_packets
            if is_match:
                matched_packets += relevant_packets

            # if all packets have been checked, stop looking for matching packets
            if len(packets_to_exclude) == len(self.packets):
                break 
        
        # Reduce potential false positives, this tool runs by default on 24 threads, so many requests before a possible human intervention to stop the tool
        if len(matched_packets) < 10:
            return []

        return matched_packets
                
    def find_matching_packets(self, packets: list[ModbusPacket], packets_to_exclude: list[ModbusPacket]) -> Tuple[list[ModbusPacket], bool]:
        """
            Return what packets match + if they are a match or if any disproving characteristics are found.
        """
        is_match = True
        matching_packets = []
        found_request_transaction_ids = []

        packets_to_check = [packet for packet in packets if packet not in packets_to_exclude]

        for packet in packets_to_check:
            if packet.modbus_function == 1 and packet.unit_id == 0:
                if packet.request_response == "request":
                    if packet.get_function_specific_data("address") == 0 and packet.get_function_specific_data("quantity") == 1: # always reference num 0 and 1 bit
                        matching_packets.append(packet)
                        found_request_transaction_ids.append(packet.transaction_id)
                elif packet.request_response == "response":
                    # transaction id must have been found already as request
                    if packet.transaction_id in found_request_transaction_ids:
                        matching_packets.append(packet)

        return matching_packets, is_match