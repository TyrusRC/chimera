from chimera.integrations.command import build_launch_command


def test_local_command_uses_repo_launch_wrapper(tmp_path):
    (tmp_path / "scripts").mkdir()
    wrapper = tmp_path / "scripts" / "mcp-launch.sh"
    wrapper.write_text("#!/usr/bin/env bash\n")
    (tmp_path / ".venv").mkdir()
    cmd = build_launch_command(repo_root=tmp_path)
    assert cmd["command"] == str(wrapper)
    assert cmd["args"] == ["mcp"]


def test_portable_command_uses_uvx():
    cmd = build_launch_command(portable=True)
    assert cmd["command"] == "uvx"
    assert "git+https://github.com/TyrusRC/chimera" in cmd["args"]
    assert cmd["args"][-2:] == ["chimera", "mcp"]
