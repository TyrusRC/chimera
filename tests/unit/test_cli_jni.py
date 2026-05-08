from click.testing import CliRunner

from chimera.cli import main


def test_jni_subcommand_registered():
    runner = CliRunner()
    result = runner.invoke(main, ["jni", "--help"])
    assert result.exit_code == 0
    assert "JNI bindings" in result.output or "Native methods" in result.output
