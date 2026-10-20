# ICtoolS

ICtoolS (pronounced "I See Tools") identifies the use of ICS-capable tools in honeypot network traffic logs. It groups log entries into *interactions*, matches each interaction against a set of tool fingerprints, and reports which tools were used and which packets each tool accounts for.

ICtoolS currently supports:

| Protocol   | Log format                                   | Parser                                              |
|------------|----------------------------------------------|-----------------------------------------------------|
| Modbus/TCP | Zeek logs (with the ICSNPP Modbus and UMAS plug-ins) | [`log_parsers/Modbus/Zeek.py`](log_parsers/Modbus/Zeek.py) |
| ENIP / CIP | PCAP / PCAPNG                                | [`log_parsers/ENIP/pcap.py`](log_parsers/ENIP/pcap.py)     |

ICtoolS is presented in the paper *"ICtoolS: Fingerprinting ICS Tools to Characterize Honeypot Interactions"* (see [Citation](#citation)).

## How it works

ICtoolS processes logs in four steps:

1. **Log parsing.** Each parser handles one protocol/log-format combination and converts the log entries into a common *unified packet* structure ([`protocol_structures`](protocol_structures)).
2. **Interaction building.** Packets are sorted chronologically and grouped by actor/target IP pair. Port numbers are not used, because many tools open a new connection per request. Each group is split into separate interactions whenever two consecutive packets are more than `INTERACTION_TIMEOUT` seconds apart (default: 11 s).
3. **Fingerprint matching.** Every fingerprint matcher ([`fingerprints`](fingerprints)) runs independently on every interaction and tags the packets that match its tool.
4. **Coverage calculation.** Each interaction gets a coverage outcome that says whether one or more tools matched, whether matchers overlap on the same packets, and whether every packet is explained by a tool (see [Coverage outcomes](#coverage-outcomes)).

## Requirements

- **Python 3.9 or later**. Tested with Python 3.13.
- The Python packages in [`requirements.txt`](requirements.txt).
- **tshark** (part of Wireshark) on the `PATH`. pyshark needs it to parse ENIP pcaps. Tested with Wireshark 4.6.
- To produce Modbus logs from raw captures: **Zeek** (tested with Zeek 9.0) with these packages:
  - [CISA ICSNPP Modbus](https://github.com/cisagov/icsnpp-modbus) **v1.x** (tested with v1.0.0). Version 2.0.0 changed the format of `modbus_detailed.log` and is not supported yet.
  - [znpa-umas](https://github.com/Security-Cluster-TU-Eindhoven/znpa-umas), which adds support for Schneider Electric's UMAS (Modbus function code 90)

## Installation

```bash
git clone https://github.com/Security-Cluster-TU-Eindhoven/ICtoolS.git ictools
cd ictools
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Preparing the input

ICtoolS takes a directory as input and searches it recursively. A directory is processed if it directly contains `*.log`, `*.pcap` or `*.pcapng` files, and each such directory is parsed separately.

### Modbus (Zeek logs)

Install the two Zeek packages with `zkg`:

```bash
zkg install icsnpp-modbus --version v1.0.0
zkg install https://github.com/Security-Cluster-TU-Eindhoven/znpa-umas
```

Run Zeek with both packages loaded on each capture, using the names `zkg` installs them under. Write the logs for each capture into their own directory:

```bash
mkdir -p logs/capture1 && cd logs/capture1
zeek -C -r /path/to/capture1.pcap icsnpp-modbus znpa-umas
```

The Modbus parser uses these Zeek logs (in Zeek's default tab-separated format, not JSON):

| Log file                                   | Required | Used for                                                    |
|--------------------------------------------|----------|-------------------------------------------------------------|
| `modbus.log`                               | yes      | Base packet information (function code, unit ID, transaction ID) |
| `modbus_detailed.log`                      | recommended | Addresses, quantities and written values                  |
| `modbus_read_device_identification.log`    | recommended | MEI type, device ID code and returned objects (e.g., `VendorName`) |
| `modbus_umas.log`                          | recommended | UMAS sub-function codes                                    |
| `conn.log`                                 | recommended | Packet-loss detection (`missed_bytes`)                    |

If an optional log is missing, ICtoolS prints a warning and continues. Fingerprints that need those fields will then not match.

### ENIP (pcaps)

Put the `*.pcap` / `*.pcapng` files in the input directory. The ENIP parser reads every capture it finds and keeps only packets that tshark decodes as ENIP (port 44818). Request/response direction is derived from the port, as Wireshark does.

> **Note:** Large captures are slow to parse with pyshark, and the ENIP parser also reads pcaps that contain no ENIP traffic. If your input directory holds both Zeek logs and the pcaps they were generated from, keep the pcaps somewhere else unless you also want ENIP analysis.

## Running ICtoolS

```bash
python3 main.py --input_dir <log_dir> --output <results.json>
```

| Option                | Description                                                |
|-----------------------|------------------------------------------------------------|
| `--input_dir PATH`    | Directory containing the logs to analyse (required)        |
| `--output FILE_PATH`  | JSON file the results are written to (required)            |

Example:

```bash
python3 main.py --input_dir logs --output results.json
```

### Configuration

Settings are in [`config/config.py`](config/config.py):

| Setting                         | Default | Description |
|---------------------------------|---------|-------------|
| `INTERACTION_TIMEOUT`           | `11`    | Maximum gap (seconds) between consecutive packets of the same IP pair for them to belong to the same interaction. The paper derives this value from the inter-arrival times in its Modbus dataset. |
| `DISCARD_TAINTED_INTERACTIONS`  | `True`  | Drop interactions that contain packets from a TCP connection with packet loss (Zeek `conn.log` `missed_bytes > 0`). Fingerprints need complete logs, so such interactions cannot be matched reliably. |
| `LOGGING_LEVEL`                 | `INFO`  | Python logging level. |

## Output

The output is a JSON list with one object per interaction:

```json
{
    "actorIP": "10.0.0.1",
    "targetIP": "10.0.0.2",
    "startTime": 1.0,
    "endTime": 2.0,
    "packets": [
        {
            "timestamp": "1.000000",
            "src_ip": "10.0.0.1",
            "src_port": 40000,
            "dst_ip": "10.0.0.2",
            "dst_port": 502,
            "request_response": "request",
            "sessionId": "C1",
            "tainted": false,
            "transport_layer": "TCP",
            "function_specific_data": {
                "mei type": 14,
                "Read Device ID": 1
            },
            "tool_matches": ["zgrab2"],
            "modbus_function": 43,
            "unit_id": 0,
            "transaction_id": 23111,
            "is_exception": false
        }
    ],
    "coverage": "Single Tool Match; Incomplete Identification",
    "tool_matches": ["zgrab2"]
}
```

- `tool_matches` on the interaction lists every tool whose fingerprint matched.
- `tool_matches` on each packet lists the tools that account for that packet. These per-packet results make each outcome explainable.
- `sessionId` is the Zeek connection UID for Modbus, or `<pcap file>:<tcp|udp>:<stream index>` for ENIP.

### Coverage outcomes

| Output value                                              | Paper | Tools matched | Packets matched by more than one tool | All packets matched |
|-----------------------------------------------------------|-------|---------------|----------------------------------------|---------------------|
| `Single Tool Match; Complete Identification`              | SC    | One           | N/A                                    | Yes                 |
| `Single Tool Match; Incomplete Identification`            | SI    | One           | N/A                                    | No                  |
| `Multiple Tool Match; No Overlap; Complete Identification`   | MNC | Multiple   | No                                     | Yes                 |
| `Multiple Tool Match; No Overlap; Incomplete Identification` | MNI | Multiple   | No                                     | No                  |
| `Multiple Tool Match; Overlap; Complete Identification`      | MOC | Multiple   | Yes                                    | Yes                 |
| `Multiple Tool Match; Overlap; Incomplete Identification`    | MOI | Multiple   | Yes                                    | No                  |
| `No Match`                                                | ∅     | None          | N/A                                    | N/A                 |

Treat any outcome other than *Single Tool Match; Complete Identification* with care. An incomplete outcome means some packets come from an unknown tool, or from a tool run in the same time window. An overlap often means one fingerprint is a subset of another. Known subset relations: Modscan and Fuzzowski are subsets of NMAP, Scannerl is a subset of Meeas PLC Scan, and Metasploit Modbus Detect is a subset of Metasploit Find Unit ID.

## Tool fingerprints

Each fingerprint lives in its own folder under [`fingerprints/<protocol>/`](fingerprints). A folder contains a `scanner.py` with the matcher and, where available, the reference capture recorded while running the tool against our testbed. The full lists of collected tools, including the ones without a fingerprint yet, are in [`fingerprints/Modbus/modbus_tools.xlsx`](fingerprints/Modbus/modbus_tools.xlsx) and [`fingerprints/ENIP/enip_tools.xlsx`](fingerprints/ENIP/enip_tools.xlsx).

Fingerprints are built from each tool's **default** configuration. A tool run with non-default parameters (e.g., a custom transaction ID) will usually not be matched.

Implemented fingerprints:

<details>
<summary><b>Modbus/TCP (32)</b></summary>

| Folder | Reported tool name |
|---|---|
| `c4l1b4n_modbussploit_doswritecoils` | C4l1b4n Modbussploit DoS Write Coils |
| `c4l1b4n_modbussploit_doswriteregisters` | C4l1b4n Modbussploit DoS Write Registers |
| `cas_modbus_scanner` | CAS Modbus Scanner |
| `digitalbond_Basecamp-modicon_command_start` | Basecamp Modicon Start |
| `digitalbond_Basecamp-modicon_command_stop` | Basecamp Modicon Stop |
| `digitalBond_Redpoint-modicon_info` | Digital Bond - Redpoint - Modicon |
| `fernill` | Fernill Scan |
| `fuzzowski-modbusmonitor_get_modbus_device_id_nse` | Fuzzowski - Modbus monitor device id nse |
| `johnbeuter_cyberprojects_modbusdenial_py` | JohnBeuter - Cyberprojects - Modbus denial (python) |
| `karlvbiron_MATRIX-modbus_coil_write_attack` | karlvbiron - MATRIX modbus coil write attack |
| `karlvbiron_MATRIX-modbus_dos_attack` | karlvbiron - MATRIX - Modbus DoS attack |
| `karlvbiron_MATRIX-modbus_registers_write_attack` | karlvbiron - MATRIX modbus register write attack |
| `marcom_modbus_scan` | Marcom Modbus Scanner |
| `meeas_plcscan` | Meeas - PLC Scan |
| `metasploit_bannergrabbing` | Metasploit Banner Grabbing |
| `metasploit_modbus_findunitid` | Metasploit Find Unit ID |
| `metasploit_modbusdetect` | Metasploit Modbus Detect |
| `modscan` | Modscan |
| `msak` | MSAK |
| `nmap` | NMAP |
| `scannerl_modbus` | Scannerl - Modbus |
| `shadow1ng-fscan` | Shadow1ng - fscan |
| `smod_modbus_dos_galilrio` | Smod - galilRIO |
| `w3h_icsmaster_modbus_enum_aggressive` | w3h - ICSMaster - enum (aggressive) |
| `w3h_icsmaster-MODBUS_REMOTE_COMMAND_TOOL_enter_user_mode` | w3h - ICS Master (enter user mode) |
| `w3h_icsmaster-MODBUS_REMOTE_COMMAND_TOOL_restart_controller` | w3h - ICS Master (restart controller) |
| `w3h_icsmaster-MODBUS_REMOTE_COMMAND_TOOL_start` | w3h - ICS Master (start) |
| `w3h_icsmaster-MODBUS_REMOTE_COMMAND_TOOL_stop` | w3h - ICS Master (stop) |
| `wh3_isf-Schneider_CPU_Comoand_start` | w3h ISF - Schneider CPU command (start) |
| `wh3_isf-Schneider_CPU_Comoand_stop` | w3h ISF - Schneider CPU command (stop) |
| `zgrab` | zgrab |
| `zgrab2` | zgrab2 |

Folders that contain only a capture (no `scanner.py`) are tools we recorded but have not fingerprinted yet.

</details>

<details>
<summary><b>ENIP (10)</b></summary>

| Folder | Reported tool name |
|---|---|
| `censys` | Censys (derived from honeypot logs) |
| `eipscanner` | EIPScanner |
| `ethersploit-ip_get_device_info` | EtherSploit/IP - get device info |
| `metasploit-multi_cip_command-crashcpu` | Metasploit - MultiCip - CRASHCPU |
| `metasploit-multi_cip_command-crashether` | Metasploit - MultiCip - CRASHETHER |
| `metasploit-multi_cip_command-resetether` | Metasploit - MultiCip - RESETETHER |
| `metasploit-multi_cip_command-stopcpu` | Metasploit - MultiCip - STOPCPU |
| `redpoint-nmap` | Digital Bond - Redpoint - ENIP |
| `scada-cip-discovery` | SCADA-CIP-Discovery |
| `shodan` | Shodan (derived from honeypot logs) |

The Shodan and Censys fingerprints come from patterns observed in honeypot logs, not from running the tools, so they have no reference capture.

</details>

### Adding a fingerprint or a parser

See the [Fingerprints README](fingerprints/README.md) for how to write a new fingerprint matcher. To support another protocol or log format, add a `UnifiedPacket` subclass in [`protocol_structures`](protocol_structures) (if needed) and a `LogParser` subclass in [`log_parsers`](log_parsers), then export it from `log_parsers/__init__.py`. `main.py` picks up every exported parser and fingerprint automatically.

## Tests

The [`tests`](tests) directory holds unit tests and regression tests that run ICtoolS on all reference captures. See the [Tests README](tests/README.md) for how to run them:

```bash
pip install -r requirements.txt pytest
python -m pytest tests/unit
```

## Contributing

ICtoolS is developed in a GitLab repository at Eindhoven University of Technology. The [GitHub repository](https://github.com/Security-Cluster-TU-Eindhoven/ICtoolS) is a read-only mirror that is updated automatically from it, so pull requests cannot be merged on GitHub.

To report a bug or suggest a change, please [open an issue](https://github.com/Security-Cluster-TU-Eindhoven/ICtoolS/issues). Pull requests are welcome as proposals: if a change is accepted, the maintainers apply it in the development repository, and it appears on GitHub with the next update. Please report security issues privately through [GitHub's private vulnerability reporting](https://github.com/Security-Cluster-TU-Eindhoven/ICtoolS/security/advisories/new) rather than in a public issue.

## License

ICtoolS is released under the [BSD 3-Clause License](LICENSE).

## Citation

If you use ICtoolS in your research, please cite:

```bibtex
@inproceedings{ictools,
  title     = {{ICtoolS}: Fingerprinting {ICS} Tools to Characterize Honeypot Interactions},
  author    = {Kempinski, Stash and Asanache, Victor and Lahaije, Lucas and Schlett, Kristopher and Sciancalepore, Savio and Zambon, Emmanuele and Zannone, Nicola},
  booktitle = {Industrial Control System Security Workshop (ICSS), co-located with the Annual Computer Security Applications Conference (ACSAC)},
  year      = {2026}
}
```

## Acknowledgments

This work has been supported by the INTERSECT project, Grant No. NWA.1162.18.301, funded by the Netherlands Organization for Scientific Research (NWO). We thank Bureau Veritas Benelux for access to Ethernet/IP honeypot data.
