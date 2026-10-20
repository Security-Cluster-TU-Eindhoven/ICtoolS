# Fingerprint Tester

This directory contains the script necessary for testing all the implemented fingerprints; it tests if a tool fingerprint is correctly identified in its accompanying pcap, and tests if a fingerprint matches to other tool pcaps.

## Test Runner (`test_runner.py`)

A script which dynamically tests the matches between Modbus tools' Zeek logs and implemented fingerprints. 

### Features
- Converts PCAP files to structured Modbus Logs format (Optional)
- Preserves directory structure
- Dynamically generates expectations for test cases (`name of the folder containing a tool's Zeek logs: [title of the expected fingerprint]`)
- For each set of Zeek logs, all available fingerprints are tested
- For each tool: outputs a list of expected matches, a list of matched tools, a list of unexpected matches, a list of missing matches, and a boolean variable stating whether the tool is matched to the expected fingerprint or not.

### Usage

```bash
python test_runner.py --input_dir ../../input_zeek --output_dir ../../output --make_logs true
```

Arguments:
- `-i, --input_dir`: Path to input directory containing Zeek log files (This directory also serves as an output location for the Zeek logs obtained from PCAPs)
- `-o, --output_dir`: Output directory for test results
- `-ml, --make_logs`: Option to first convert all PCAP files in the `../../fingerprints` folder to Zeek logs (default: 'false')

### Example

```bash
# Convert all PCAP files to Zeek logs first, then run the tests
python test_runner.py -i ../../input_zeek -o ../../output -ml true

# Assuming the PCAP files are already converted, run the tests
python test_runner.py -i ../../input_zeek -o ../../output
```

The output for the "CAS Modbus Scanner" tool can look as follows:

```
"cas_modbus_scanner": {
    "expected_matches": [
      "CAS Modbus Scanner"
    ],
    "matched_tools": [
      "CAS Modbus Scanner"
    ],
    "unexpected_matches": [],
    "missing_matches": [],
    "is_tool_expected_match": true
  }
```

## Notes

- It is assumed that the PCAP files and fingerprints are located under the `../../fingerprints` directory
- The Modbus Log converter feature requires Zeek to be installed