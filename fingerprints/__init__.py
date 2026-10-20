import os
import importlib

from .fingerprint import Fingerprint

__all__ = ["Fingerprint"]

base_dir = os.path.dirname(__file__)

# Walk through all subdirectories of the fingerprints folder to find scanner.py files
for root, _, files in os.walk(base_dir):
    if "scanner.py" in files:
        relative_path = os.path.relpath(root, base_dir).replace(os.sep, ".")
        module_name = f"{relative_path}.scanner"

        try:
            module = importlib.import_module(f".{module_name}", package="fingerprints")
            
            # Add all classes that end with "Fingerprint" to the current module's namespace
            for attr_name in dir(module):
                if attr_name.endswith("Fingerprint"):
                    attr_value = getattr(module, attr_name)
                    if isinstance(attr_value, type) and issubclass(attr_value, Fingerprint):
                        globals()[attr_name] = attr_value
                        __all__.append(attr_name)
        except ImportError as e:
            print(f"Error importing module {module_name}: {e}")
