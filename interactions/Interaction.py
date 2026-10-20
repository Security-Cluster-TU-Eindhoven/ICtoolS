from dataclasses import dataclass, field, asdict
from protocol_structures.UnifiedPacket import UnifiedPacket
from .coverage import COVERAGE

@dataclass
class Interaction:
    """
    A single interaction, consisting of one or more packets
    """
    actorIP: str
    targetIP: str
    startTime: float # Time since epoch in seconds
    endTime: float
    packets: list[UnifiedPacket]
    coverage: COVERAGE = COVERAGE.NOT_PROCESSED
    tool_matches: list[str] = field(default_factory=list) # Dictionary of tool name + matched packets
    
    def to_dict(self):
        return {
            "actorIP": self.actorIP,
            "targetIP": self.targetIP,
            "startTime": self.startTime,
            "endTime": self.endTime,
            "packets": [asdict(p) for p in self.packets],
            "coverage": self.coverage.value,
            "tool_matches": self.tool_matches
        }