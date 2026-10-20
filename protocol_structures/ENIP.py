from dataclasses import dataclass
from typing import Optional
from protocol_structures.UnifiedPacket import UnifiedPacket


@dataclass
class ENIPPacket(UnifiedPacket):
    # Encapsulation Header can put -1 for debugging
    command: str = ""
    length: int = 0
    session_handle: str = ""
    status: str = ""
    sender_context: str = ""
    options: str = ""
    max_resp_delay: Optional[int] = None
    packet_correlation_id: str = None  # id that correlates enip packet with it's cip part if exists

    # In case of a malformed packet
    is_malformed: Optional[bool] = False
    item_count: Optional[str] = None
    timeout: Optional[str] = None
    interface_handle: Optional[str] = None


    # Common Industrial Protocol (CIP)
    contains_cip: bool = False
    cip_class: Optional[str] = None
    cip_instance: Optional[str] = None
    cip_attribute: Optional[str] = None
    cip_path_segment: Optional[str] = None
    cip_service: Optional[str] = None

    function_specific_data: Optional[dict] = None

    def __eq__(self, other):
        """Compare EipPacket instances based on their id."""
        if isinstance(other, ENIPPacket):
            return self.id == other.id

        return False

    def __hash__(self) -> int:
        """Generate hash based on the instance's id."""
        return hash(self.id)

    def __repr__(self) -> str:
        """Provides a detailed string representation of the EIP packet instance."""
        if not self.contains_cip:
            return (
                f"EipPacket(id={self.id}, timestamp={self.timestamp}, "
                f"src_ip={self.src_ip}, src_port={self.src_port}, dst_ip={self.dst_ip}, dst_port={self.dst_port},"
                f"command={self.command}, length={self.length}, session_handle={self.session_handle}, status={self.status}, sender_context={self.sender_context}, "
            )
        else:
            return (
                f"EipPacket(id={self.id}, timestamp={self.timestamp}, "
                f"src_ip={self.src_ip}, src_port={self.src_port}, dst_ip={self.dst_ip}, dst_port={self.dst_port},"
                f"command={self.command}, length={self.length}, session_handle={self.session_handle}, status={self.status}, sender_context={self.sender_context}, "
                f"contains_cip={self.contains_cip}, cip_class={self.cip_class}, cip_instance={self.cip_instance}, cip_path_segment={self.cip_path_segment}, cip_service={self.cip_service}, "
            )
