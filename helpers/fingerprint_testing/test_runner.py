import argparse
import json
import logging
import sys
from pathlib import Path
import importlib.util
import inspect
from concurrent.futures import ProcessPoolExecutor, as_completed

# Add the project root directory to sys.path
CURRENT_FILE = Path(__file__).resolve()
PROJECT_ROOT = CURRENT_FILE.parents[2]  # Go from tests/fingerprint_testing → tests → project root
sys.path.insert(0, str(PROJECT_ROOT))

from pcap_to_zeek import generate_zeek_output
from config.config import CONFIG
from log_parsers import *
from fingerprints import *
from interactions import InteractionHandler
from main import parse_logs, process_interaction

logging.basicConfig(level=CONFIG.LOGGING_LEVEL,
                    format=CONFIG.LOGGING_FORMAT,
                    datefmt='%Y-%m-%d %H:%M:%S')

# Dynamically discover all implemented fingerprint classes
def discover_fingerprints():
    fingerprints = {}
    for name, cls in globals().items():
        if (
            isinstance(cls, type)
            and issubclass(cls, Fingerprint)
            and cls is not Fingerprint
        ):
            fingerprints[name] = cls
    return fingerprints

# Dynamically discover all implemented log parsers
def discover_parsers():
    parsers = []
    for cls in globals().values():
        if isinstance(cls, type) and issubclass(cls, LogParser) and cls is not LogParser:
            parsers.append(cls)
    return parsers

# Run a single test case:
# - Parse logs
# - Run interactions through fingerprints
# - Compare actual vs expected tool matches
# - Return a summary of the test case result
def run_test_case(pcap_logs_dir: Path, expected_tools: list[str], all_fingerprints: dict):
    logger = logging.getLogger("Log parser and tester")
    logger.info(f"\n ########## Running tests for: {pcap_logs_dir.name} ##########")

    # Discover and initialize all available log parsers
    parsers = discover_parsers()

    # Parse logs into packet objects from the given input folder
    packets = parse_logs(pcap_logs_dir.parent, pcap_logs_dir, parsers)

    if not packets:
        logger.info(f"[ERROR] No packets parsed from {pcap_logs_dir}")
        return {
            "expected_matches": expected_tools,
            "matched_tools": [],
            "unexpected_matches": [],
            "missing_matches": [],
            "is_tool_expected_match": False
        }

    # Ensure packets are processed in chronological order
    packets.sort(key=lambda p: float(p.timestamp))

    # Group packets into higher-level interactions
    interactions = InteractionHandler.create_interactions(packets)

    # Enable all fingerprints, even if not explicitly expected, for broader test coverage
    enabled_fingerprints = {k: v for k, v in all_fingerprints.items()}

    # Run fingerprint detection in parallel across interactions
    processed = []
    with ProcessPoolExecutor() as executor:
        futures = [executor.submit(process_interaction, i, enabled_fingerprints) for i in interactions]
        for f in as_completed(futures):
            try:
                processed.append(f.result())
            except:
                logger.error(f"[ERROR] when running test cases for [{pcap_logs_dir.name}]")


    # Aggregate detected tools from processed interactions
    matched_tools = set()
    for interaction in processed:
        matched_tools.update(interaction.tool_matches)

    # Sort for clean comparison
    matched_tools = sorted(list(matched_tools))
    expected_tools = sorted(expected_tools)
    unexpected, missing = set(), set()

    # Evaluate results and print outcome
    if matched_tools == expected_tools:
        if expected_tools == [] and any(packets):  # No match expected, but input exists
            logger.info(f"[WARNING] No matches expected for {pcap_logs_dir.name} and none found — but logs were present. Is the fingerprint implemented?")
        else:
            logger.info(f"[SUCCESS] {pcap_logs_dir.name} matches as expected: {matched_tools}")
    else:
        if expected_tools != []:
            logger.info(f"[FAIL] {pcap_logs_dir.name} expected: {expected_tools} | Got: {matched_tools}")
        else:
            if any(packets):
                logger.info(f"[WARNING] Logs were present for {pcap_logs_dir.name}. Is the fingerprint implemented?")
        unexpected = set(matched_tools) - set(expected_tools)
        if unexpected:
            logger.info(f"  - {pcap_logs_dir.name} unexpected matches: {unexpected}")
        missing = set(expected_tools) - set(matched_tools)
        if missing:
            logger.info(f"  - {pcap_logs_dir.name} missing matches: {missing}")

    if matched_tools == expected_tools and matched_tools == []:
        outcome = False
    else:
        outcome = matched_tools == expected_tools

    return {
        "expected_matches": expected_tools,
        "matched_tools": matched_tools,
        "unexpected_matches": list(unexpected),
        "missing_matches": list(missing),
        "is_tool_expected_match": outcome
    }

# Generate the expectations data structure
def generate_expectations(input_zeek_path, fingerprints_path):
    logger = logging.getLogger("Expectations builder")
    expectations = {}

    # For each folder in input_zeek
    for root, folders, files in input_zeek_path.walk():
        for folder in folders:
            fingerprint_folder = fingerprints_path / root.name / folder
            scanner_path = fingerprint_folder / "scanner.py"

            if fingerprint_folder.exists():
                if scanner_path.exists():
                    # Dynamically load scanner.py and read tool_name
                    spec = importlib.util.spec_from_file_location("scanner", scanner_path)
                    module = importlib.util.module_from_spec(spec)
                    try:
                        spec.loader.exec_module(module)
                        # Search for Fingerprint subclasses and extract tool_name
                        for name, obj in inspect.getmembers(module, inspect.isclass):
                            if issubclass(obj, Fingerprint) and obj is not Fingerprint:
                                tool_name = getattr(obj, "tool_name", None)
                                if tool_name:
                                    expectations[input_zeek_path / root / folder] = [tool_name]
                                    break  # Only one fingerprint per folder assumed
                    except Exception as e:
                        logger.info(f"[ERROR] Failed to load {scanner_path}: {e}")
                else:
                    logger.info(f"[INFO] No scanner.py in {fingerprint_folder}")
                    expectations[input_zeek_path / root / folder] = []

    logger.info(f"[INFO] Generated expectations: {expectations}")

    return expectations

# Test case wrapper used for parallel execution
def run_case_wrapper(args):
    pcap_logs_dir, expected, all_fingerprints = args
    return pcap_logs_dir.name, run_test_case(pcap_logs_dir, expected, all_fingerprints)

# Run all test cases based on the input_zeek folder and expectations.json
def main():
    parser = argparse.ArgumentParser(description="Run tests for Modbus logs using fingerprint scanners.")
    parser.add_argument('-i', '--input_dir', type=str, required=True, 
                       help='Directory containing log files')
    parser.add_argument('-o', '--output_dir', type=str, required=True, 
                       help='Directory to save analysis results')
    parser.add_argument('-ml', '--make_logs', type=str, default="false", choices=["true", "false"],
                       help='Whether to generate Zeek logs from PCAPs for the tests')
    args = parser.parse_args()

    base_dir = Path(args.input_dir)
    base_dir.mkdir(parents=True, exist_ok=True)
    make_logs = args.make_logs
    # Generate zeek logs first if option is enabled
    if make_logs == "true":
        generate_zeek_output(Path("../../fingerprints"), base_dir)
    expectations = generate_expectations(base_dir, Path("../../fingerprints"))
    output_base_dir = Path(args.output_dir)
    output_base_dir.mkdir(parents=True, exist_ok=True)
    all_fingerprints = discover_fingerprints()

    # Iterate through each test case folder
    results = {}
    args_list = []
    for log_dir in expectations.keys():
        expected = expectations.get(log_dir, [])
        args_list.append((log_dir, expected, all_fingerprints))

    # Run all test cases in parallel 
    executor = ProcessPoolExecutor()
    futures = [executor.submit(run_case_wrapper, arg) for arg in args_list] 
    for future in as_completed(futures):
        name, result = future.result()
        results[name] = result

    executor.shutdown()

   # with ProcessPoolExecutor() as executor:
    #    for name, result in executor.map(run_case_wrapper, args_list):
     #       results[name] = result
    
    # Summarize the results
    no_fingerprint_yet = 0
    correct = 0
    false_positives = 0
    incorrect_implementation = 0
    total = 0
    for tool, result in results.items():
        total += 1

        if result["is_tool_expected_match"]:
            correct += 1
            continue

        if result["expected_matches"] == []:
            no_fingerprint_yet += 1

        if result["expected_matches"] == result["missing_matches"] and result["expected_matches"] != []:
            incorrect_implementation += 1
            print(f"INCORRECT IMPLEMENTATION [{tool}]")

        if result["unexpected_matches"] != []:
            false_positives += 1
            print(f"FALSE POSTIVE(S) FOR [{tool}]: [{result["unexpected_matches"]}]")

    print(f"TOTAL: {total} - CORRECT {correct} - FALSE POSITIVES {false_positives} - INCORRECT IMPLEMENTATION {incorrect_implementation} - NO FINGERPRINT YET {no_fingerprint_yet}")

    # Write out the final results to a summary file
    output_file = output_base_dir / "test_results.json"
    with output_file.open("w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
