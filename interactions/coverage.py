from enum import Enum

class COVERAGE(Enum):
    NOT_PROCESSED = "Not processed"

    SINGLE_TOOL_MATCH_COMPLETE_IDENTIFICATION = "Single Tool Match; Complete Identification"
    SINGLE_TOOL_MATCH_INCOMPLETE_IDENTIFICATION = "Single Tool Match; Incomplete Identification"

    MULTIPLE_TOOL_MATCH_NO_OVERLAP_COMPLETE_IDENTIFICATION = "Multiple Tool Match; No Overlap; Complete Identification"
    MULTIPLE_TOOL_MATCH_NO_OVERLAP_INCOMPLETE_IDENTIFICATION = "Multiple Tool Match; No Overlap; Incomplete Identification"

    MULTIPLE_TOOL_MATCH_WITH_OVERLAP_COMPLETE_IDENTIFICATION = "Multiple Tool Match; Overlap; Complete Identification"
    MULTIPLE_TOOL_MATCH_WITH_OVERLAP_INCOMPLETE_IDENTIFICATION = "Multiple Tool Match; Overlap; Incomplete Identification"

    NO_MATCHES = "No Match"