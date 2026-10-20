# Tests

The tests use [pytest](https://pytest.org). Run them from the repository root:

```bash
pip install -r requirements.txt pytest
```

## Unit tests

[`unit`](unit) tests the Zeek log parser on small hand-written logs, packets, interactions and coverage
outcomes, and checks that every `scanner.py` loads a well-formed fingerprint:

```bash
python -m pytest tests/unit
```

## Regression tests

[`regression`](regression) runs ICtoolS on the reference captures in `fingerprints/<protocol>/` and compares
the results with [`expected/<protocol>.json`](expected). Every fingerprint runs on every capture, so the
expected results also record the known overlaps between fingerprints and catch fingerprints that match other
tools' captures.

```bash
# ENIP: needs tshark
REGRESSION_PROTOCOL=ENIP python -m pytest tests/regression

# Modbus: needs Zeek with ICSNPP Modbus v1.x and znpa-umas, see the main README
REGRESSION_PROTOCOL=Modbus python -m pytest tests/regression
```

The Modbus tests convert each capture with `zeek -C -r <capture> icsnpp-modbus znpa-umas`. To use packages
that are not installed with `zkg`, point `ZEEK_SCRIPTS` at their `scripts` directories, e.g.
`ZEEK_SCRIPTS="../icsnpp-modbus/scripts ../znpa-umas/scripts"`.

The expected results were produced with Wireshark 4.6 and Zeek 9.0. Personal Wireshark plugins can change
how tshark decodes ENIP traffic; if the ENIP results differ, run the tests with an empty home directory
(`HOME=$(mktemp -d)`) to use stock Wireshark.

### Updating the expected results

After adding a fingerprint or a reference capture, or after a deliberate change in matching, regenerate the
expected results and review the changes before committing them:

```bash
UPDATE_EXPECTED=1 REGRESSION_PROTOCOL=Modbus python -m pytest tests/regression
git diff tests/expected
```
