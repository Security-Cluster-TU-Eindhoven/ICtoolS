import argparse
from pathlib import Path
import os
import sys
import json
from dataclasses import asdict, dataclass, field
import copy


# Add the project root directory to sys.path
CURRENT_FILE = Path(__file__).resolve()
PROJECT_ROOT = CURRENT_FILE.parents[2]  # Go from helpers/automated_extraction → helpers → project root
sys.path.insert(0, str(PROJECT_ROOT))

from interactions import Interaction
from patterns.pattern_handler import PatternHandler
from patterns.pattern import Pattern
from patterns.non_functional_pdu_values import non_functional_pdu_values

from enum import StrEnum, auto

class BEHAVIOR(StrEnum):
    STATIC = auto()
    SEQUENTIAL = auto()
    PATTERN = auto()
    RANDOM = auto()

class STARTING_BEHAVIOR(StrEnum):
    FIXED = auto()
    RANDOM = auto()

class REQUEST_COUNT_BERHAVIOR(StrEnum):
    SINGLE = auto()
    MULTIPLE = auto()



@dataclass
class PDUData:
    starting_value: int
    behavior: BEHAVIOR
    starting_behavior: STARTING_BEHAVIOR
    pattern: list

    def to_dict(self):
        return {
            "starting_value": self.starting_value,
            "behavior": self.behavior.value if self.behavior else None,
            "starting_behavior": self.starting_behavior.value if self.starting_behavior else None,
            "pattern": self.pattern
        }

@dataclass
class ToolFeatures:
    port_behavior = None
    packets = []
    transport_protocols = None
    non_functional_fields: dict[PDUData] = field(default_factory=dict)
    request_count_behavior = None

    def to_dict(self):
        serialize_nffs = {}
        for name, value in self.non_functional_fields.items():
            serialize_nffs[name] = value.to_dict()

        return {
            "port_behavior": self.port_behavior,
            "packets": self.packets,
            "transport_protocols": self.transport_protocols,
            "non_functional_fields": {nff[0]: nff[1].to_dict() for nff in self.non_functional_fields.items()},
            "request_count_behavior": self.request_count_behavior.value
        }



def ExtractFieldBehavior(packets: list[dict], field: str) -> PDUData:
    behavior = None
    pattern = None

    values = []
    for packet in packets:
        if field in packet:
            value = packet[field]
            if isinstance(value, str):
                try:
                    values.append(int(value, 0))
                except:
                    print(f"[ERROR] Unparsable value found in field \"{field}\". Please report this bug, include the json files that you try to parse.")
                    print(f"[WARNING] field \"{field}\" was not parsed correctly, its output is incorrect.")
                    return PDUData(None, None, None, None)
            elif isinstance(value, int):
                values.append(packet[field])



    # Determine BEHAVIOR
    # Note that BEHAVIOR.RANDOM cannot be extracted from a single field behavior extraction, this can only be determined through comparison between executions.
    if all(value == values[0] for value in values):
        behavior = BEHAVIOR.STATIC
    else:
        # check if field value increases sequentially
        diffs = [values[i + 1] - values[i] for i in range(0, len(values) - 1)]

        if all(diff == 1 for diff in diffs):
            behavior = BEHAVIOR.SEQUENTIAL
        else:
            behavior = BEHAVIOR.PATTERN
            pattern = values

    # Starting behavior cannot be deducted from a single interaction. Currently hacked to STARTING_BEHAVIOR.FIXED as three identical interactions result in one toolfeatures being output.
    return PDUData(values[0], behavior, STARTING_BEHAVIOR.FIXED, pattern)


def CreateToolFeature(pattern: Pattern) -> ToolFeatures:
    toolfeature = ToolFeatures()

    requests = [packet for packet in pattern.packets if packet["request_response"] == "request"]
    
    # non_deterministic_fields
    # first identify all different fields in the packets
    fields_in_packets = list({key for packet in requests for key in packet.keys()})
    for values in non_functional_pdu_values.values():
        for value in values:
            if value in fields_in_packets:
                toolfeature.non_functional_fields[value] = ExtractFieldBehavior(requests, value)



    # port behavior
    toolfeature.port_behavior = pattern.port_behavior

    # functional fields
    toolfeature.packets = PatternHandler.strip_packets(requests)

    # transport_protocol 
    toolfeature.transport_protocols = list({packet["transport_layer"] for packet in toolfeature.packets})

    # request behavior
    toolfeature.request_count_behavior = REQUEST_COUNT_BERHAVIOR.SINGLE if len(toolfeature.packets) == 1 else REQUEST_COUNT_BERHAVIOR.MULTIPLE

    return toolfeature

def OutputToolFeature(toolfeature: ToolFeatures, save_path: Path):
    with open(save_path, 'w') as f:
        json.dump(toolfeature.to_dict(), f, indent=4)
    pass


if __name__ == "__main__":
    # Arguments
    parser = argparse.ArgumentParser(description="Extract fingerprint characteristics from ICtoolS logs.")
    parser.add_argument('--input_json_dir', type=str, required=True, help='Path to three ICtoolS generated json files each containing one tool execution.')
    parser.add_argument('--output', type=str, required=True, help='File to save the tool features to in json format.')

    #TODO branch between checking a single state execution and comparing branches

    args = parser.parse_args()    
    input_json_path = Path(args.input_json_dir)
    output_path = Path(args.output)

    # Make sure that dir contains three files and that they are json
    dir_list = os.scandir(input_json_path)
    files = []

    for entry in dir_list:
        if entry.is_file() and entry.name.split('.')[-1] == "json":
            files.append(entry.path)

    if len(files) != 3:
        print("Make sure that there are 3 json files in your input directory.")
        sys.exit()

    # parse files
    interactions = []

    for i in range(0, 3):
        try: 
            with open(input_json_path/files[i], "r", encoding="utf-8") as f:
                json_data = json.load(f)

                # Make sure that each file contains one interaction
                if len(json_data) != 1:
                    print(f"The following file contains more than one object/Interaction: {files[i]}.")
                    sys.exit()

                interactions.append(Interaction(**json_data[0]))
        except:
            print(f"The following file is either not a json file or does not contain an ICtoolS outputted json: {files[i]}")
            sys.exit()

    interaction_one = interactions[0]
    interaction_two = interactions[1]
    interaction_three = interactions[2]

    # Extract patterns from each interaction
    pattern_one = PatternHandler.extract_pattern(interaction_one)
    pattern_two = PatternHandler.extract_pattern(interaction_two)
    pattern_three = PatternHandler.extract_pattern(interaction_three)

    # First check if the patterns are completely deterministic
    complete_one_two = PatternHandler.compare_patterns(pattern_one, pattern_two)
    complete_one_three = PatternHandler.compare_patterns(pattern_one, pattern_three)
    complete_two_three = PatternHandler.compare_patterns(pattern_two, pattern_three)


    # if all three patterns are exactly the same, no further computation is needed, just create a single tool feature and output that.
    if complete_one_two and complete_one_three and complete_two_three:
        toolfeature = CreateToolFeature(pattern_one)
        OutputToolFeature(toolfeature, output_path)
        sys.exit()
    else:
        # Create toolfeature for each pattern
        toolfeatures_one = CreateToolFeature(pattern_one)
        toolfeatures_two = CreateToolFeature(pattern_two)
        toolfeatures_three = CreateToolFeature(pattern_three)

        #sanity checks first:
        if not PatternHandler.compare_packets(toolfeatures_one.packets, toolfeatures_two.packets):
            print(f"The functional fields and packet count between \"{input_json_path/files[0]}\" and \"{input_json_path/files[1]}\" are not the same. Are you sure your input consist of three executions of the same branching logic?")
            sys.exit()

        if not PatternHandler.compare_packets(toolfeatures_one.packets, toolfeatures_three.packets):
            print(f"The functional fields and packet count between \"{input_json_path/files[0]}\" and \"{input_json_path/files[2]}\" are not the same. Are you sure your input consist of three executions of the same branching logic?")
            sys.exit()

        if not PatternHandler.compare_packets(toolfeatures_two.packets, toolfeatures_three.packets):
            print(f"The functional fields and packet count between \"{input_json_path/files[1]}\" and \"{input_json_path/files[2]}\" are not the same. Are you sure your input consist of three executions of the same branching logic?")
            sys.exit()

        # compare toolfeatures
        toolfeature_nffs = {}
        for name in toolfeatures_one.non_functional_fields.keys():
            one = toolfeatures_one.non_functional_fields[name]
            two = toolfeatures_two.non_functional_fields[name]
            three = toolfeatures_three.non_functional_fields[name]

            nffs = [one, two, three]

            # Figure out starting behavior
            starting_behavior = None
            starting_value = None
            if all(x.starting_value == one.starting_value for x in nffs):
                starting_behavior = STARTING_BEHAVIOR.FIXED
                starting_value = one.starting_value
            else:
                starting_behavior = STARTING_BEHAVIOR.RANDOM

            # Figure out behavior
            behavior = None
            pattern = None
            if all(x.behavior == BEHAVIOR.STATIC for x in nffs):
                behavior = BEHAVIOR.STATIC
            elif all(x.behavior == BEHAVIOR.SEQUENTIAL for x in nffs):
                behavior = BEHAVIOR.SEQUENTIAL
            elif all(x.behavior == BEHAVIOR.PATTERN for x in nffs):
                # confirm that the patterns are the same
                if one.pattern == two.pattern and one.pattern == three.pattern:
                    behavior = BEHAVIOR.PATTERN
                    pattern = one.pattern
                else:
                    behavior = BEHAVIOR.RANDOM
            else:
                behavior = BEHAVIOR.RANDOM

            toolfeature_nffs[name] = PDUData(starting_value, behavior, starting_behavior, pattern)

        toolfeatures_output = copy.deepcopy(toolfeatures_one)
        toolfeatures_output.non_functional_fields = toolfeature_nffs
        OutputToolFeature(toolfeatures_output, output_path)