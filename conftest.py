import sys
from pathlib import Path

# Make the top-level `target` package importable in tests without installing it.
sys.path.insert(0, str(Path(__file__).parent))
