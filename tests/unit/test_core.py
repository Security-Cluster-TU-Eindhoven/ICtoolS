"""Tests for packets, interactions and coverage outcomes."""
import pytest

import main
from config import CONFIG
from interactions import COVERAGE, Interaction, InteractionHandler
from protocol_structures import ModbusPacket, UnifiedPacket


def packet(ts, request_response="request", tainted=False, cls=ModbusPacket):
    src, dst = ("10.0.0.1", "10.0.0.2") if request_response == "request" else ("10.0.0.2", "10.0.0.1")
    return cls(timestamp=str(ts), src_ip=src, src_port=40000, dst_ip=dst, dst_port=502,
               request_response=request_response, tainted=tainted, function_specific_data={})


def test_unified_packet_compares_with_other_types():
    p = packet(1.0, cls=UnifiedPacket)

    assert p != None  # noqa: E711
    assert p != "a string"
    assert p in [None, p]
    assert p == p


def test_interactions_split_on_timeout():
    packets = [packet(0), packet(5), packet(5 + CONFIG.INTERACTION_TIMEOUT + 1), packet(5 + CONFIG.INTERACTION_TIMEOUT + 2)]

    interactions = InteractionHandler.extract_interactions_from_packets(packets, CONFIG.INTERACTION_TIMEOUT)

    assert [len(i.packets) for i in interactions] == [2, 2]
    assert interactions[0].actorIP == "10.0.0.1" and interactions[0].targetIP == "10.0.0.2"


@pytest.mark.parametrize("discard", [True, False])
def test_tainted_interactions(monkeypatch, discard):
    monkeypatch.setattr(CONFIG, "DISCARD_TAINTED_INTERACTIONS", discard)
    clean = Interaction("a", "b", 0, 1, [packet(0), packet(1, "response")])
    tainted = Interaction("a", "b", 0, 1, [packet(0), packet(1, "response", tainted=True)])

    assert InteractionHandler.keep_interaction(clean)
    assert InteractionHandler.keep_interaction(tainted) is not discard


def interaction_with_matches(*packet_matches):
    packets = []
    for tools in packet_matches:
        p = packet(len(packets))
        p.tool_matches = list(tools)
        packets.append(p)
    interaction = Interaction("a", "b", 0, 1, packets)
    interaction.tool_matches = sorted({t for tools in packet_matches for t in tools})
    return interaction


@pytest.mark.parametrize("packet_matches, expected", [
    ([[], []], COVERAGE.NO_MATCHES),
    ([["A"], ["A"]], COVERAGE.SINGLE_TOOL_MATCH_COMPLETE_IDENTIFICATION),
    ([["A"], []], COVERAGE.SINGLE_TOOL_MATCH_INCOMPLETE_IDENTIFICATION),
    ([["A", "B"], ["A"]], COVERAGE.MULTIPLE_TOOL_MATCH_WITH_OVERLAP_COMPLETE_IDENTIFICATION),
    ([["A", "B"], []], COVERAGE.MULTIPLE_TOOL_MATCH_WITH_OVERLAP_INCOMPLETE_IDENTIFICATION),
    ([["A"], ["B"]], COVERAGE.MULTIPLE_TOOL_MATCH_NO_OVERLAP_COMPLETE_IDENTIFICATION),
    ([["A"], ["B"], []], COVERAGE.MULTIPLE_TOOL_MATCH_NO_OVERLAP_INCOMPLETE_IDENTIFICATION),
])
def test_coverage_outcome(packet_matches, expected):
    assert main.determine_tool_match_outcome(interaction_with_matches(*packet_matches)) == expected
