# How to Add a New Fingerprint

A fingerprint matcher is a Python class that receives the packets of one interaction and returns the packets that match a specific tool. `main.py` discovers matchers automatically, so you don't need to register them anywhere.

## Step 1: Create the fingerprint folder

1. **Add a folder** under the protocol directory, i.e. [`fingerprints/Modbus`](Modbus) or [`fingerprints/ENIP`](ENIP). Name the folder after the tool, plus the specific function if the tool has several (e.g., `nmap`, `metasploit_bannergrabbing`, `metasploit-multi_cip_command-stopcpu`).
2. **Add a `scanner.py` file** to that folder. On import, [`fingerprints/__init__.py`](__init__.py) walks the `fingerprints` tree and loads every `scanner.py`.
3. **Add a reference capture** (`.pcap`/`.pcapng`) of the tool run with its default settings against a test target. It documents the behaviour and lets others check the matcher.

## Step 2: Define the fingerprint class

Create a class in `scanner.py` that:

- inherits from [`Fingerprint`](fingerprint.py);
- has a name **ending in `Fingerprint`** and unique across all fingerprints (the loader only picks up such classes);
- sets `protocol_packet_types` to the packet classes it handles (e.g., `[ModbusPacket]` or `[ENIPPacket]`). The base class drops every other packet, so `self.packets` only holds packets of these types;
- sets `tool_name`, the name reported in the output;
- implements `run()`, which returns the list of matched packets (an empty list if the tool is not found).

Most existing matchers follow the same pattern. They group the interaction's packets by the client-side port, which usually means one TCP connection per group. They discard groups that cannot belong to the tool, then check each remaining group request by request:

```python
# fingerprints/Modbus/custom_tool/scanner.py
from fingerprints import Fingerprint
from protocol_structures import ModbusPacket, UnifiedPacket


class CustomToolFingerprint(Fingerprint):
    protocol_packet_types = [ModbusPacket]
    tool_name = "Custom Tool"

    def run(self) -> list[UnifiedPacket]:
        matched_packets = []

        # Group all packets by the port of the requester
        potential_packet_matches: dict[int, list[UnifiedPacket]] = {}
        for packet in self.packets:
            if packet.request_response == "request":
                potential_packet_matches.setdefault(packet.src_port, []).append(packet)
            else:
                potential_packet_matches.setdefault(packet.dst_port, []).append(packet)

        for _, potential_match_packets in potential_packet_matches.items():
            # The request is missing from the interaction. Discard this set as potential match
            if potential_match_packets[0].request_response == "response":
                continue

            if self.is_valid_sequence(potential_match_packets):
                matched_packets += potential_match_packets

        return matched_packets

    def is_valid_sequence(self, packets: list[ModbusPacket]) -> bool:
        for packet in packets:
            if packet.request_response == "response":
                continue

            # Function code behaviour: always 43
            # Unit ID behaviour: always 0
            # Transaction ID behaviour: always 1234
            if not (packet.modbus_function == 43 and packet.unit_id == 0 and packet.transaction_id == 1234):
                return False

        return True
```

### Available packet fields

All packets ([`UnifiedPacket`](../protocol_structures/UnifiedPacket.py)) provide `timestamp`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `request_response` (`"request"`/`"response"`), `sessionId` (Zeek connection UID, or the TCP/UDP stream for pcaps) and `transport_layer`.

- [`ModbusPacket`](../protocol_structures/Modbus.py) adds `modbus_function`, `unit_id`, `transaction_id` and `is_exception`. Use `packet.get_function_specific_data(key)` to read optional fields. It returns `None` when a field is missing. Keys:
  - `"address"`, `"quantity"`, `"values"` (from `modbus_detailed.log`);
  - `"mei type"`, `"Read Device ID"` and returned objects such as `"VendorName"` (from `modbus_read_device_identification.log`);
  - `"umas function code"`, `"umas session key"` (from `modbus_umas.log`).
- [`ENIPPacket`](../protocol_structures/ENIP.py) adds the encapsulation header (`command`, `session_handle`, `status`, `sender_context`, `options`, ...), the CIP fields (`contains_cip`, `cip_service`, `cip_class`, `cip_instance`, `cip_attribute`, `cip_path_segment`) and, for Connection Manager requests, `function_specific_data` with `service`, `class`, `instance` and `data`.

### Guidelines

- Build the fingerprint from the tool's **default** settings, and check every deterministic value (function codes, IDs, addresses, sequence order). Non-deterministic values work as wildcards.
- Check the **number of requests**. Single-request tools are easily confused with longer tools that start with the same request.
- If the tool branches on responses (e.g., it stops when the target is not from a specific vendor), accept every branch.
- `run()` must not raise on unexpected input. An exception aborts the whole analysis.

## Step 3: Test the fingerprint

Run ICtoolS on the folder that holds your reference capture. For Modbus, first generate Zeek logs from the capture (see the [main README](../README.md#modbus-zeek-logs)):

```bash
python3 main.py --input_dir fingerprints/ENIP/<your_tool> --output /tmp/result.json
```

Check that:

- the interactions from the reference capture show *Single Tool Match; Complete Identification* with your `tool_name`;
- your fingerprint does not match the reference captures of other tools. Run ICtoolS on the whole `fingerprints/<protocol>` directory and look for unexpected matches or overlaps.

Finally, add the new reference capture to the regression tests and check that no other capture's results change (see the [Tests README](../tests/README.md#updating-the-expected-results)):

```bash
UPDATE_EXPECTED=1 REGRESSION_PROTOCOL=<protocol> python -m pytest tests/regression
git diff tests/expected
```

The diff should only add your capture, with your `tool_name`.
