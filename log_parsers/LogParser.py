from abc import ABC, abstractmethod
from protocol_structures import UnifiedPacket
from pathlib import Path

class LogParser(ABC):

    @staticmethod
    @abstractmethod
    def parse_directory(directory: Path) -> list[UnifiedPacket]:
        """

        return the set of parsed packets
        """
        raise NotImplementedError("Subclasses must implement the parse_directory() method.")