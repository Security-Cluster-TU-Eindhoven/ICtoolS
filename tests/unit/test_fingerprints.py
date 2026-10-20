"""Checks that every fingerprint is loaded and well formed."""
import importlib
import inspect

import pytest

from conftest import ICTOOLS_DIR
import fingerprints
from fingerprints import Fingerprint
from protocol_structures import UnifiedPacket

SCANNER_MODULES = sorted(
    "fingerprints." + ".".join(path.relative_to(ICTOOLS_DIR / "fingerprints").parent.parts) + ".scanner"
    for path in (ICTOOLS_DIR / "fingerprints").rglob("scanner.py")
)


def fingerprint_classes(module):
    return [cls for name, cls in inspect.getmembers(module, inspect.isclass)
            if issubclass(cls, Fingerprint) and cls is not Fingerprint and cls.__module__ == module.__name__]


@pytest.mark.parametrize("module_name", SCANNER_MODULES)
def test_scanner_module(module_name):
    # fingerprints/__init__.py only prints import errors, which silently drops the fingerprint
    module = importlib.import_module(module_name)
    classes = fingerprint_classes(module)

    assert classes, f"{module_name} defines no Fingerprint subclass"
    for cls in classes:
        assert cls.__name__.endswith("Fingerprint"), f"{cls.__name__}: the loader only picks up classes ending in 'Fingerprint'"
        assert getattr(fingerprints, cls.__name__, None) is cls, f"{cls.__name__} is not exported by the fingerprints package"
        assert isinstance(getattr(cls, "tool_name", None), str) and cls.tool_name
        assert cls.protocol_packet_types and all(issubclass(t, UnifiedPacket) for t in cls.protocol_packet_types)


def test_names_are_unique():
    classes = [cls for name in SCANNER_MODULES for cls in fingerprint_classes(importlib.import_module(name))]
    class_names = [cls.__name__ for cls in classes]
    tool_names = [cls.tool_name for cls in classes]

    assert len(class_names) == len(set(class_names)), "duplicate fingerprint class names"
    assert len(tool_names) == len(set(tool_names)), "duplicate tool names"


def run_fingerprint(cls, packets):
    # main runs fingerprints as class methods; release branches (1.0) instantiate them
    if hasattr(cls, "delegate_run"):
        return cls.delegate_run(packets)
    return cls(packets).run()


@pytest.mark.parametrize("module_name", SCANNER_MODULES)
def test_runs_on_empty_interaction(module_name):
    for cls in fingerprint_classes(importlib.import_module(module_name)):
        assert run_fingerprint(cls, []) == []
