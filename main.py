import argparse
import json
import logging
from pathlib import Path
from typing import Type
from concurrent.futures import ProcessPoolExecutor, as_completed

from log_parsers import *
from fingerprints import *

from interactions import Interaction, InteractionHandler, COVERAGE
from protocol_structures import UnifiedPacket
from config import CONFIG

logging.basicConfig(level=CONFIG.LOGGING_LEVEL, format=CONFIG.LOGGING_FORMAT, datefmt='%Y-%m-%d %H:%M:%S')


def parse_logs(root_dir: Path, log_dir: Path, parsers: list[Type[LogParser]]) -> list[UnifiedPacket]:
    """Process a directory of logs.
    
    Args:
        root_dir: Root directory containing all log directories
        log_dir: Directory containing the specific logs to process (subdirectories are processed separately)
        parsers: Log parsers to run on the directory
    Returns:
        List of parsed packets
    """
    logger = logging.getLogger("Log parser")

    parsed_packets: list[UnifiedPacket] = []

    relative_path = log_dir.relative_to(root_dir)
    dir_name = str(relative_path)

    for parser in parsers:
        packets = parser.parse_directory(log_dir)
        logger.debug(f"Processed {dir_name}: loaded {len(packets)} {parser.__name__} packets")
        parsed_packets += packets
    
    return parsed_packets
            
    

def process_interaction(interaction: Interaction, matchers: dict[str, Type[Fingerprint]]) -> Interaction:
    interaction = run_matchers_on_interaction(interaction, matchers)
    interaction.coverage = determine_tool_match_outcome(interaction)

    return interaction

def run_matchers_on_interaction(interaction: Interaction, matchers: dict[str, Type[Fingerprint]]) -> Interaction:
    """
        Run the desired fingerprint matchers on a single interaction.
    """

    for matcher_name, matcher_class in matchers.items():
        matcher_instance = matcher_class(interaction.packets)
        matched_packets = matcher_instance.run()

        if len(matched_packets) > 0:
            interaction.tool_matches.append(matcher_class.tool_name)

        for matched_packet in matched_packets:
            matched_packet.tool_matches.append(matcher_class.tool_name)

    return interaction


def determine_tool_match_outcome(interaction: Interaction) -> COVERAGE:
    """
        Determine the interaction coverage
    """
    
    #Check for no matches
    if len(interaction.tool_matches) == 0:
        return COVERAGE.NO_MATCHES
        #Check for single tool match
    #Check for other cases
    else:
        num_matched_packets = 0
        num_packets_with_overlap = 0
        for packet in interaction.packets:
            if len(packet.tool_matches) == 1:
                num_matched_packets += 1
            elif len(packet.tool_matches) >= 2:
                num_matched_packets += 1
                num_packets_with_overlap += 1

        is_complete = len(interaction.packets) == num_matched_packets
        has_overlap = num_packets_with_overlap > 0
        single_tool = len(interaction.tool_matches) == 1

        if  single_tool and is_complete:           
            return COVERAGE.SINGLE_TOOL_MATCH_COMPLETE_IDENTIFICATION
        elif single_tool and not is_complete:
            return COVERAGE.SINGLE_TOOL_MATCH_INCOMPLETE_IDENTIFICATION
        elif not single_tool and has_overlap and is_complete:
            return COVERAGE.MULTIPLE_TOOL_MATCH_WITH_OVERLAP_COMPLETE_IDENTIFICATION
        elif not single_tool and has_overlap and not is_complete:
            return COVERAGE.MULTIPLE_TOOL_MATCH_WITH_OVERLAP_INCOMPLETE_IDENTIFICATION
        elif not single_tool and not has_overlap and is_complete:
            return COVERAGE.MULTIPLE_TOOL_MATCH_NO_OVERLAP_COMPLETE_IDENTIFICATION
        elif not single_tool and not has_overlap and not is_complete:
            return COVERAGE.MULTIPLE_TOOL_MATCH_NO_OVERLAP_INCOMPLETE_IDENTIFICATION
        
    raise ValueError("Interaction without a valid coverage calculation outcome")




def main():
    """Entry point for the script."""
    parser = argparse.ArgumentParser(description="Identify ICS tools in honeypot logs.")
    parser.add_argument('--input_dir', type=str, required=True, 
                       help='Directory containing log files')
    parser.add_argument('--output', type=str, required=True, 
                       help='File to save analysis results in json')
    args = parser.parse_args()    

    input_directory = Path(args.input_dir)

    logger = logging.getLogger("ICtoolS")

    scanners = { name: globals()[name] for name in globals() if isinstance(globals()[name], type) and issubclass(globals()[name], Fingerprint) and globals()[name] is not Fingerprint}
    
    parsers = [ globals()[name] for name in globals() if isinstance(globals()[name], type) and issubclass(globals()[name], LogParser) and globals()[name] is not LogParser]



    # Process directories
    # TODO: refactor to the parsers themselves finding the right files
    log_dirs = [
        log_dir 
        for log_dir in sorted([input_directory] + list(input_directory.rglob('*')))
        if log_dir.is_dir() and (any(log_dir.glob('*.log')) or any(log_dir.glob('*.pcap')) or any(log_dir.glob('*.pcapng')))
    ]

    # Process logs in parallel, i.e. create a list of unified packets from all fed logs
    unified_packets = []
    executor = ProcessPoolExecutor()
    futures = [executor.submit(parse_logs, input_directory, log_dir, parsers) for log_dir in log_dirs] 
    for future in as_completed(futures):
            parsed_packets = future.result()
            if parsed_packets:
                unified_packets += parsed_packets

    executor.shutdown()

    logger.info(f"Logs parsed, total packets: {len(unified_packets)}")

    # Sort packets chronologically
    unified_packets.sort(key = lambda x: float(x.timestamp))  # Faster than implementing a cmp function https://stackoverflow.com/questions/403421/how-do-i-sort-a-list-of-objects-based-on-an-attribute-of-the-objects

    logger.info("Unified packets sorted")

    # Sort the unified packets into interactions
    unprocessed_interactions = InteractionHandler.create_interactions(unified_packets)

    logger.info(f"Interactions created, total: {len(unprocessed_interactions)}")

    number_of_processed_interactions = 0
    processed_interactions = []
    executor = ProcessPoolExecutor()
    futures = [executor.submit(process_interaction, interaction, scanners) for interaction in unprocessed_interactions] 
    for future in as_completed(futures):
        processed_interaction = future.result()
        if processed_interaction:
            processed_interactions.append(processed_interaction)
            number_of_processed_interactions +=1
            logger.info(f"interaction progress: {number_of_processed_interactions} / {len(unprocessed_interactions)}")

    executor.shutdown()
    
    with open(args.output, 'w') as f:
        to_dump = [interaction.to_dict() for interaction in processed_interactions]
        json.dump(to_dump, f, indent=4)

    pass


if __name__ == "__main__":
    main()
