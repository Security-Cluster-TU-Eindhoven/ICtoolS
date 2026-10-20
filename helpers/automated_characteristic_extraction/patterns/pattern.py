from dataclasses import dataclass, field, asdict

@dataclass
class Pattern:
    port_behavior = ""
    packets = []
    id = -1
    compare_complete = False
    name = ""


    def to_dict(self):
        return {
            "port_behavior": self.port_behavior,
            "packets": self.packets,
            "id": self.id,
            "compare_complete": self.compare_complete
        }