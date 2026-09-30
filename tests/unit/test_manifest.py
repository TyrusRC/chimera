import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_skill_json_valid_and_has_launch_command():
    m = json.loads((ROOT / "skill.json").read_text())
    assert m["name"] == "chimera"
    assert m["mcp_server"]["command"]  # non-empty launch command
    assert m["capabilities"]["transport"] == "stdio"
