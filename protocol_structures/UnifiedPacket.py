from dataclasses import dataclass, asdict, field
import uuid
from typing import Optional

@dataclass
class UnifiedPacket:
    """
    Fileformat agnostic representation of a packet
    """
    timestamp: str # To be rewritten to float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    request_response: str # "request" / "response"
    sessionId: str = None
    tainted: bool = False
    transport_layer: str = "TCP"
    function_specific_data: dict[str, any] = None
    tool_matches: list[str] = field(default_factory=list)

    def __post_init__(self):
        """Generate a unique identifier for each instance after initialization."""
        if not hasattr(self, 'id'):
            self.id = str(uuid.uuid4())
    
    def to_dict(self) -> dict:
        """Convert the packet to a dictionary."""
        return asdict(self)

    def __eq__(self, other):
        if not hasattr(other, "id"):
            return NotImplemented
        else:
            return self.id == other.id
        
    def get_function_specific_data(self, *args):
        """ 
        A wrapper to get any data out of 'function_specific_data'. 
        TODO: nesting. 
        Returns None if object is not found.
        
        """
        if len(args) == 0:
            return None

        if args[0] in self.function_specific_data:
            return self.function_specific_data[args[0]]
        else:
            return None

