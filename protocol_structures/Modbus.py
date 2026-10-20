from dataclasses import dataclass, asdict
from typing import Optional
from protocol_structures.UnifiedPacket import UnifiedPacket

@dataclass
class ModbusPacket(UnifiedPacket):
    """
    A dataclass representing Modbus network traffic log entries.
    
    Required fields:
    - modbus_function: Modbus function code (integer)
    
    Optional fields include unit ID, transaction ID, exception details,
    PDU information, and device-specific data.
    """
    modbus_function: int = -1
    unit_id: int = -1
    transaction_id: int = -1
    is_exception: bool = False

    def __eq__(self, other):
        """Compare ModbusPacket instances based on their id."""
        if isinstance(other, ModbusPacket):
            return self.id == other.id
        return False
    
    def __hash__(self) -> int:
        """Generate hash based on the instance's id."""
        return hash(self.id)

    def __repr__(self) -> str:
        """Provide a detailed string representation of the Modbus instance."""
        return (f"ModbusPacket(id={self.id}, sessionId={self.sessionId}, timestamp={self.timestamp}, "
                f"src_ip={self.src_ip}, src_port={self.src_port}, "
                f"dst_ip={self.dst_ip}, dst_port={self.dst_port}, "
                f"modbus_function={self.modbus_function})")