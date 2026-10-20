import sys
from pathlib import Path

# Root of the ICtoolS repository, which holds main.py and the packages under test
ICTOOLS_DIR = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(ICTOOLS_DIR))
