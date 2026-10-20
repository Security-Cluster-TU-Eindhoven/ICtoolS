from patterns.pattern import Pattern
from interactions import Interaction
import copy
from patterns.enums import *
from patterns.non_functional_pdu_values import non_functional_pdu_values

class PatternHandler:

    @staticmethod
    def extract_pattern(interaction: Interaction) -> Pattern:
        ## CREATE PATTERN FROM INTERACTION
        pattern_packets = []
        actor_port = interaction.packets[0]["src_port"]
        port_behavior = ""
        for packet in interaction.packets:
            packet_dict = copy.deepcopy(packet)
            
            # Delete non-fingerprint related stuff
            del packet_dict["timestamp"]
            del packet_dict["src_ip"]
            del packet_dict["src_port"]
            del packet_dict["dst_ip"]
            del packet_dict["dst_port"]
            del packet_dict["sessionId"]
            del packet_dict["tainted"]
            del packet_dict["tool_matches"]
            del packet_dict["original_location"]
    
            if packet["request_response"] == "request":
                if packet["src_port"] == actor_port and port_behavior == "same":
                    port_behavior = "same"
                else:
                    port_behavior = "different"
    
            pattern_packets.append(packet_dict)

        # Create pattern
        pattern = Pattern()
        pattern.port_behavior = port_behavior
        pattern.packets = pattern_packets

        return pattern


    @staticmethod
    def compare_patterns(one: Pattern, two: Pattern) -> bool:
        if one.port_behavior != two.port_behavior:
            return False

        result = PatternHandler.compare_packets(one.packets, two.packets)
        if not result:
            return False


        return True


    @staticmethod 
    def compare_packets(packets_one: list[dict], packets_two: list[dict]) -> bool:
        if len(packets_one) != len(packets_two):
            return False

        for index in range(0, len(packets_one)):
            if not (packets_one[index] == packets_two[index]):
                return False

        return True


    @staticmethod
    def does_pattern_exist(pattern_to_check: Pattern, existing_patterns: list[Pattern]) -> bool:
        for existing_pattern in existing_patterns:
            if PatternHandler.compare_patterns(pattern_to_check, existing_pattern):
                return True

        return False

    @staticmethod
    def strip_pattern(pattern: Pattern) -> Pattern:
        stripped_pattern = copy.deepcopy(pattern)

        for packet in stripped_pattern.packets:
            for values in non_functional_pdu_values.values():
                for value in values:
                    if value in packet:
                        del packet[value]


        return stripped_pattern

    @staticmethod
    def strip_packets(packets: list[dict]) -> list[dict]:
        stripped_packets = []

        for packet in packets:
            stripped_packet = copy.deepcopy(packet)
            for values in non_functional_pdu_values.values():
                for value in values:
                    if value in stripped_packet:
                        del stripped_packet[value]

            stripped_packets.append(stripped_packet)


        return stripped_packets



    @staticmethod
    def check_pattern_similarity(pattern_one: Pattern, pattern_two: Pattern) -> REQUEST_SIMILARITY:
        '''
        Returns request similarity and ordering similarity
        '''
        request_similarity: REQUEST_SIMILARITY = REQUEST_SIMILARITY.NO_OVERLAP

        fp_one_requests = [packet for packet in pattern_one.packets if packet["request_response"] == "request"]
        fp_two_requests = [packet for packet in pattern_two.packets if packet["request_response"] == "request"]

        # Find shortest pattern length to loop over to check for similarity
        shortest_pattern_length = -1
        if len(fp_one_requests) >= len(fp_two_requests):
            shortest_pattern_length = len(fp_two_requests) 
        else:
            shortest_pattern_length = len(fp_one_requests)

        # Count number of matches
        match_count = 0
        for i in range(0, shortest_pattern_length):
            if fp_one_requests[i] == fp_two_requests[i]:
                match_count += 1
            else:
                break

        if match_count > 0:
            same_length = len(fp_one_requests) == len(fp_two_requests)
            if match_count == shortest_pattern_length and same_length:
                request_similarity = REQUEST_SIMILARITY.TOTAL_REQUEST_OVERLAP
            elif match_count == shortest_pattern_length and not same_length:
                request_similarity = REQUEST_SIMILARITY.TOTAL_INCLUSION
            else:
                request_similarity = REQUEST_SIMILARITY.PARTIAL_REQUEST_OVERLAP




        return request_similarity