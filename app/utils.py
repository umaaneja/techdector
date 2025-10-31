# app/utils.py
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

def load_fingerprints(path: str = None):
    p = Path(path) if path else BASE / "fingerprints.json"
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)
