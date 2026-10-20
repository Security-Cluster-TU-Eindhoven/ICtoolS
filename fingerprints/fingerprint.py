from dataclasses import dataclass, field
from typing import List, Sequence, ClassVar
from protocol_structures import UnifiedPacket
import logging


@dataclass
class Fingerprint:
    """Base class for implementing tool identification algorithms.
    
    Analyzes network traffic patterns to identify a specific tool based on its fingerprint.
    """
    tool_name: ClassVar[str]
    protocol_packet_types: ClassVar[list[type[UnifiedPacket]]]
    packets: List[UnifiedPacket] = field(default_factory=list)

    def __init__(self, interaction_packets: list[UnifiedPacket]):
        self.packets = []
        
        # Initialize the tool identifier by filtering packets that this fingerprinter cannot process.
        if len(self.protocol_packet_types) == 0:
            raise NotImplementedError("protocol_packet_types cannot be empty; fingerprint must implement at least one protocol to run on.")

        for packet in interaction_packets:
            if type(packet) in self.protocol_packet_types:
                self.packets.append(packet)


    @classmethod
    def delegate_run(cls, interaction_packets: list[UnifiedPacket]) -> list[UnifiedPacket]:
        packets = []

        for packet in interaction_packets:
            if type(packet) in cls.protocol_packet_types:
                packets.append(packet)

        return cls.run(packets)
    
    @classmethod
    def run(cls, packets: list[UnifiedPacket]) -> list[UnifiedPacket]:
        """Runs the fingerprinting algorithm on packets
        
        Must be implemented by subclasses to define specific fingerprinting logic.
        
        Raises:
            NotImplementedError: If the subclass doesn't implement this method.
        """
        raise NotImplementedError("Subclasses must implement the run() method.")

    @staticmethod
    def summarize_ids(unit_ids: Sequence[int]) -> str:
        """Convert a sequence of unit IDs into a concise range representation.
        
        Converts sequential numbers into ranges using hyphen notation.
        For example: [1, 2, 3, 5, 6] becomes '1-3, 5-6'
        
        Args:
            unit_ids: Sequence of integer unit IDs to summarize.
            
        Returns:
            A string representation of the unit ID ranges.
        """
        if not unit_ids:
            return ""
            
        ranges = []
        start = prev = unit_ids[0]
        
        for uid in unit_ids[1:]:
            if uid != prev + 1:
                ranges.append(f"{start}" if start == prev else f"{start}-{prev}")
                start = uid
            prev = uid
            
        ranges.append(f"{start}" if start == prev else f"{start}-{prev}")
        return ", ".join(ranges)