from enum import IntEnum, auto

class REQUEST_SIMILARITY(IntEnum):
    TOTAL_REQUEST_OVERLAP = auto()
    PARTIAL_REQUEST_OVERLAP = auto()
    TOTAL_INCLUSION = auto()
    NO_OVERLAP = auto()

class FUNCTIONAL_SIMILARITY(IntEnum):
    EXACT_SAME_PDU_VALUES = auto()
    FUNCTIONAL_SAME_PDU_VALUES = auto()
    NO_SIMILARITY = auto()

class PORT_BEHAVIOR_SIMILARITY(IntEnum):
    SAME = auto()
    DIFFERENT = auto()

class VERDICT(IntEnum):
    DEEMED_SAME = auto()
    DEEMED_DIFFERENT = auto()
    INCONCLUSIVE = auto()
    NOT_CHECKED = auto()