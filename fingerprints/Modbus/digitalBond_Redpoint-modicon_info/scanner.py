from typing import List
from fingerprints import Fingerprint
from protocol_structures import ModbusPacket, UnifiedPacket


class DigitalBondRedPointModiconFingerprint(Fingerprint):
    protocol_packet_types = [ModbusPacket]
    tool_name = "Digital Bond - Redpoint - Modicon"

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
        expected_transaction_ids = [0,1,447,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]
        expected_subfunctions = [0x02, 0x06, 0x02, 0x01, 0xFE, 0x03, 0x03, 0x04, 0x01, 0x0A, 0x04, 0x04, 0x04, 0x20, 0x20, 0x20, 0x20, 0x20]

        expected_transaction_index = 0
        expected_subfunction_index = 0

        # If the first packet does not match the fingerprint, this set of patckets is not a match
        if not (packets[0].modbus_function == 43 and packets[0].transaction_id == expected_transaction_ids[0] and packets[0].get_function_specific_data("Read Device ID") == 2 and packets[0].get_function_specific_data("mei type") == 14 and packets[0].unit_id == 0):
            return False
        
        if len(packets) == 1:  # No response, could be due to invalid honeypot configuration. However, the first request matched this tool's fingerprint.
            return True 
        # If there is a response, check if the response indicates that this is not a Schneider device
        # Not all devices implement Read Device Identification, if a not implemented exception is returned, assume that the target device is not Schneider made. => If no more packets are present in this set, Fingerprint matches
        elif len(packets) == 2:
            if packets[1].request_response == "response":
                if packets[1].is_exception: 
                    return True
                elif packets[1].modbus_function == 43: # Check if the response will contain "VendorName"
                    if not self.is_schneider(packets[1]): # If the VendorName is not Schneider => Check if there are more packets in the 
                            return True
                else: # Packet is not an exception, nor a function 43 response => not this tool.
                    return False
            else: # No response to the Read Device Identification request, but another request in the potential packet matches => Not this tool.
                return False
        # This may be a complete execution of the tool, check this
        else: # len(packets) > 2
            if packets[1].request_response != "response" or packets[1].modbus_function != 43: # second packet is not a response, nor a function 43 response => not this tool.
                return False
            
            if packets[1].modbus_function == 43:
                if not self.is_schneider(packets[1]): # If the VendorName is not Schneider, but more packets in the list => not this tool.
                            return False
            
            # loop over remaining packets to check if they match the fingerprint
            expected_transaction_index = 1
            for packet in packets[2:-1]:
                if packet.request_response == "response": # responses are irrelevant, only check 
                      continue
                 
                # More UMAS requests than this tool sends => not this tool.
                if expected_subfunction_index >= len(expected_subfunctions):
                     return False

                if packet.modbus_function == 90 and packet.transaction_id == expected_transaction_ids[expected_transaction_index] and packet.get_function_specific_data("umas function code") == expected_subfunctions[expected_subfunction_index]:
                      expected_subfunction_index += 1
                      expected_transaction_index += 1
                else:
                     return False
                
            if expected_transaction_index != 19: # This tool is 19 requests long if it is a Schneider device.
                 return False
            
            return True


        return False # catch if anything goes wrong

    @staticmethod
    def is_schneider(packet: ModbusPacket) -> bool:
        # The tool only checks if the vendor name starts with "Schneider" (e.g., "Schneider Electric")
        vendor_name = packet.get_function_specific_data("VendorName")
        return vendor_name is not None and vendor_name.startswith("Schneider")
