"""Tests for pcap_extract (tshark-backed capture payload extraction)."""
from __future__ import annotations

import os

import pytest

from chimera.dynamic import pcap_extract as px

_CH5 = "/home/kali/ctf/FlareOn26/5-catthief/catthief/capture.pcapng"


def test_unhex_formats():
    assert px._unhex("deadbeef") == b"\xde\xad\xbe\xef"
    assert px._unhex("de:ad:be:ef") == b"\xde\xad\xbe\xef"
    assert px._unhex("not hex at all") == b""


@pytest.mark.skipif(not px.tshark_available(), reason="tshark required")
@pytest.mark.skipif(not os.path.exists(_CH5), reason="ch5 capture not present")
def test_extract_http_bodies_real():
    reqs = [r for r in px.list_http(_CH5) if r["method"] == "POST"]
    assert len(reqs) == 6 and all(r["uri"] == "/exfil" for r in reqs)
    bodies = px.extract_http_bodies(_CH5)
    sizes = sorted(b["size"] for b in bodies)
    assert 264 in sizes          # the handshake body
    assert any(s > 2_000_000 for s in sizes)   # the exfiltrated files
