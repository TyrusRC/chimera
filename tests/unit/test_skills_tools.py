import asyncio

from chimera.mcp_handlers import skills


def _call(name, args):
    return asyncio.run(skills.dispatch(name, args))


def test_list_skills_returns_catalog(tmp_path, monkeypatch):
    d = tmp_path / "re-workflow"
    d.mkdir()
    (d / "SKILL.md").write_text(
        "---\nname: re-workflow\ndescription: do RE\n---\nbody here\n"
    )
    monkeypatch.setenv("CHIMERA_SKILLS_DIR", str(tmp_path))
    out = _call("list_skills", {})
    assert "re-workflow" in out[0].text
    assert "do RE" in out[0].text


def test_get_skill_returns_body(tmp_path, monkeypatch):
    d = tmp_path / "re-workflow"
    d.mkdir()
    (d / "SKILL.md").write_text("---\nname: re-workflow\ndescription: x\n---\nBODY\n")
    monkeypatch.setenv("CHIMERA_SKILLS_DIR", str(tmp_path))
    out = _call("get_skill", {"name": "re-workflow"})
    assert "BODY" in out[0].text


def test_get_skill_rejects_traversal(tmp_path, monkeypatch):
    monkeypatch.setenv("CHIMERA_SKILLS_DIR", str(tmp_path))
    for bad in ["../../etc/passwd", "/etc/passwd", "foo/bar"]:
        out = _call("get_skill", {"name": bad})
        assert "error" in out[0].text.lower()


def test_returns_none_for_foreign_tool():
    assert _call("not_a_skill_tool", {}) is None
