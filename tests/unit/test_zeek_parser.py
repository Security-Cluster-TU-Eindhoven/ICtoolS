"""Tests for the Modbus Zeek log parser, using small hand-written Zeek logs."""
from pathlib import Path

from log_parsers import ModbusZeekParser

ID = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"]
FIELDS = {
    "modbus.log": ID + ["tid", "unit", "func", "pdu_type", "exception"],
    "modbus_detailed.log": ID + ["request_response", "address", "quantity", "values"],
    "modbus_read_device_identification.log": ID + ["request_response", "mei_type", "device_id_code", "object_id", "object_value"],
    "modbus_umas.log": ID + ["request_response", "umas_func", "session_key"],
    "conn.log": ["uid", "missed_bytes"],
}


def conn_id(ts, uid="C1"):
    return [ts, uid, "10.0.0.1", "40000", "10.0.0.2", "502"]


def write_log(directory: Path, name: str, rows: list[list[str]]):
    lines = ["#separator \\x09", "#fields\t" + "\t".join(FIELDS[name])]
    lines += ["\t".join(row) for row in rows]
    (directory / name).write_text("\n".join(lines) + "\n")


def write_request_response(directory: Path, func="READ_COILS", conn_rows=None):
    write_log(directory, "modbus.log", [
        conn_id("1.0") + ["1", "1", func, "REQ", "-"],
        conn_id("1.1") + ["1", "1", func, "RESP", "-"],
    ])
    write_log(directory, "conn.log", conn_rows if conn_rows is not None else [["C1", "0"]])


def test_parses_request_and_response(tmp_path):
    write_request_response(tmp_path)
    packets = ModbusZeekParser.parse_directory(tmp_path)

    assert [p.request_response for p in packets] == ["request", "response"]
    request, response = packets
    assert (request.src_ip, request.src_port, request.dst_port) == ("10.0.0.1", 40000, 502)
    # Responses are flipped so that src always is the sender of the packet
    assert (response.src_ip, response.src_port, response.dst_port) == ("10.0.0.2", 502, 40000)
    assert request.modbus_function == 1 and request.unit_id == 1 and request.transaction_id == 1
    assert request.sessionId == "C1"
    assert not request.tainted


def test_missing_conn_log_does_not_crash(tmp_path):
    write_request_response(tmp_path)
    (tmp_path / "conn.log").unlink()

    packets = ModbusZeekParser.parse_directory(tmp_path)

    assert len(packets) == 2
    assert not any(p.tainted for p in packets)


def test_connection_missing_from_conn_log(tmp_path):
    write_request_response(tmp_path, conn_rows=[["OTHER", "0"]])

    packets = ModbusZeekParser.parse_directory(tmp_path)

    assert len(packets) == 2
    assert not any(p.tainted for p in packets)


def test_missed_bytes_dash_is_no_packet_loss(tmp_path):
    write_request_response(tmp_path, conn_rows=[["C1", "-"]])

    packets = ModbusZeekParser.parse_directory(tmp_path)

    assert not any(p.tainted for p in packets)


def test_missed_bytes_marks_packets_tainted(tmp_path):
    write_request_response(tmp_path, conn_rows=[["C1", "12"]])

    packets = ModbusZeekParser.parse_directory(tmp_path)

    assert all(p.tainted for p in packets)


def test_exception_function_code(tmp_path):
    write_log(tmp_path, "modbus.log", [conn_id("1.0") + ["1", "1", "WRITE_SINGLE_COIL_EXCEPTION", "RESP", "-"]])
    write_log(tmp_path, "conn.log", [["C1", "0"]])

    [packet] = ModbusZeekParser.parse_directory(tmp_path)

    assert packet.modbus_function == 5
    assert packet.is_exception


def test_unknown_function_codes(tmp_path):
    write_log(tmp_path, "modbus.log", [
        conn_id("1.0") + ["1", "1", "READ_COILS", "REQ", "-"],
        conn_id("1.1") + ["2", "1", "unknown-77", "REQ", "-"],
        # A name missing from the lookup table must not reuse the previous row's code
        conn_id("1.2") + ["3", "1", "NOT_A_FUNCTION", "REQ", "-"],
    ])
    write_log(tmp_path, "conn.log", [["C1", "0"]])

    packets = ModbusZeekParser.parse_directory(tmp_path)

    assert [p.modbus_function for p in packets] == [1, 77, -1]


def test_umas_function_codes(tmp_path):
    write_log(tmp_path, "modbus.log", [
        conn_id("1.0") + ["1", "0", "PROGRAM_UNITY", "REQ", "-"],
        conn_id("1.1") + ["2", "0", "PROGRAM_UNITY", "REQ", "-"],
        conn_id("1.2") + ["3", "0", "PROGRAM_UNITY", "REQ", "-"],
    ])
    write_log(tmp_path, "modbus_umas.log", [
        conn_id("1.0") + ["REQUEST", "unknown-77", "0x00"],
        conn_id("1.1") + ["REQUEST", "-", "-"],
        conn_id("1.2") + ["REQUEST", "unknown-5", "0x00"],
    ])
    write_log(tmp_path, "conn.log", [["C1", "0"]])

    packets = ModbusZeekParser.parse_directory(tmp_path)

    assert [p.get_function_specific_data("umas function code") for p in packets] == [77, None, 5]


def test_identification_rows_without_object_id(tmp_path):
    write_log(tmp_path, "modbus.log", [
        conn_id("1.0") + ["1", "1", "ENCAP_INTERFACE_TRANSPORT", "REQ", "-"],
        conn_id("1.1") + ["1", "1", "ENCAP_INTERFACE_TRANSPORT", "RESP", "-"],
    ])
    write_log(tmp_path, "modbus_read_device_identification.log", [
        conn_id("1.0") + ["REQUEST", "READ-DEVICE-IDENTIFICATION", "1", "-", "-"],
        conn_id("1.1") + ["RESPONSE", "READ-DEVICE-IDENTIFICATION", "1", "VendorName", "Schneider Electric"],
    ])
    write_log(tmp_path, "conn.log", [["C1", "0"]])

    request, response = ModbusZeekParser.parse_directory(tmp_path)

    assert None not in request.function_specific_data
    assert request.get_function_specific_data("mei type") == 14
    assert request.get_function_specific_data("Read Device ID") == 1
    assert response.get_function_specific_data("VendorName") == "Schneider Electric"


def test_detailed_log_fields(tmp_path):
    write_log(tmp_path, "modbus.log", [conn_id("1.0") + ["1", "1", "WRITE_SINGLE_REGISTER", "REQ", "-"]])
    write_log(tmp_path, "modbus_detailed.log", [conn_id("1.0") + ["REQUEST", "10", "-", "42"]])
    write_log(tmp_path, "conn.log", [["C1", "0"]])

    [packet] = ModbusZeekParser.parse_directory(tmp_path)

    assert packet.get_function_specific_data("address") == 10
    assert packet.get_function_specific_data("quantity") is None
    assert packet.get_function_specific_data("values") == "42"


def test_nested_directories_are_not_parsed_twice(tmp_path):
    write_request_response(tmp_path)
    child = tmp_path / "child"
    child.mkdir()
    write_request_response(child)

    # main.py passes every log directory to the parser separately
    assert len(ModbusZeekParser.parse_directory(tmp_path)) == 2
    assert len(ModbusZeekParser.parse_directory(child)) == 2
