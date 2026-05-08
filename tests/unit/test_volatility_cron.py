"""Unit tests for Volatility cron/systemd content parsers."""
from chimera.parsers.volatility_cron import (
    CronEntry, SystemdUnit,
    parse_cron_text, parse_systemd_unit,
)


# ---------------------------------------------------------------------------
# parse_cron_text
# ---------------------------------------------------------------------------

def test_parse_cron_text_empty_returns_empty():
    assert parse_cron_text("") == []
    assert parse_cron_text(None) == []


def test_parse_cron_text_system_crontab():
    text = (
        "# system crontab\n"
        "SHELL=/bin/sh\n"
        "17 * * * *  root  cd / && run-parts /etc/cron.hourly\n"
        "25 6 * * *  root  test -x /usr/sbin/anacron || run-parts /etc/cron.daily\n"
    )
    entries = parse_cron_text(text, source_path="/etc/crontab", system=True)
    assert len(entries) == 2
    assert entries[0].user == "root"
    assert "run-parts" in entries[0].command
    assert entries[0].source_path == "/etc/crontab"


def test_parse_cron_text_reboot_schedule():
    text = "@reboot root /opt/evil/persist.sh\n"
    entries = parse_cron_text(text, system=True)
    assert len(entries) == 1
    assert entries[0].schedule == "@reboot"
    assert entries[0].user == "root"
    assert entries[0].command == "/opt/evil/persist.sh"


def test_parse_cron_text_user_crontab_no_user_field():
    text = "*/5 * * * * /home/attacker/beacon.sh\n"
    entries = parse_cron_text(text, source_path="/var/spool/cron/attacker", system=False)
    assert len(entries) == 1
    assert "/home/attacker/beacon.sh" in entries[0].command
    # User field not present in user crontab format
    assert entries[0].user is None


def test_parse_cron_text_skips_comments_and_blank_lines():
    text = (
        "\n"
        "# This is a comment\n"
        "0 0 * * * root /usr/bin/true\n"
    )
    entries = parse_cron_text(text, system=True)
    assert len(entries) == 1


def test_cron_entry_to_dict():
    e = CronEntry(schedule="@daily", user="root", command="/usr/bin/find", source_path="/etc/crontab")
    d = e.to_dict()
    assert d["schedule"] == "@daily"
    assert d["user"] == "root"
    assert d["command"] == "/usr/bin/find"
    assert d["source_path"] == "/etc/crontab"


# ---------------------------------------------------------------------------
# parse_systemd_unit
# ---------------------------------------------------------------------------

def test_parse_systemd_unit_empty_returns_none():
    assert parse_systemd_unit("") is None
    assert parse_systemd_unit(None) is None


def test_parse_systemd_unit_basic_service():
    text = (
        "[Unit]\n"
        "Description=Evil Backdoor\n"
        "\n"
        "[Service]\n"
        "ExecStart=/opt/evil/backdoor --daemon\n"
        "User=root\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    unit = parse_systemd_unit(text, source_path="/etc/systemd/system/evil.service")
    assert unit is not None
    assert unit.name == "evil.service"
    assert unit.exec_start == "/opt/evil/backdoor --daemon"
    assert unit.user == "root"
    assert unit.wanted_by == "multi-user.target"
    assert unit.source_path == "/etc/systemd/system/evil.service"


def test_parse_systemd_unit_returns_none_for_non_service_ini():
    # A file with no [Service] or [Install] sections should be ignored
    text = "[Unit]\nDescription=Something\n"
    assert parse_systemd_unit(text, source_path="/tmp/fake.conf") is None


def test_parse_systemd_unit_handles_comments_and_blank_lines():
    text = (
        "# leading comment\n"
        "[Service]\n"
        "; inline comment\n"
        "\n"
        "ExecStart=/usr/bin/malware\n"
    )
    unit = parse_systemd_unit(text, source_path="/etc/systemd/system/malware.service")
    assert unit is not None
    assert unit.exec_start == "/usr/bin/malware"


def test_parse_systemd_unit_name_from_path():
    text = "[Service]\nExecStart=/bin/true\n"
    unit = parse_systemd_unit(text, source_path="/lib/systemd/system/noop.service")
    assert unit.name == "noop.service"


def test_systemd_unit_to_dict():
    u = SystemdUnit(
        name="evil.service",
        exec_start="/opt/evil/run",
        user="nobody",
        wanted_by="multi-user.target",
        source_path="/etc/systemd/system/evil.service",
    )
    d = u.to_dict()
    assert d["name"] == "evil.service"
    assert d["exec_start"] == "/opt/evil/run"
    assert d["user"] == "nobody"
    assert d["wanted_by"] == "multi-user.target"
    assert d["source_path"] == "/etc/systemd/system/evil.service"
