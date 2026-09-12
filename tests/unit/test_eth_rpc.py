"""eth-fetch: minimal ABI codec, the network gate, and mocked RPC decode.

No test touches the network — the gate is off by default and the RPC transport
is monkeypatched.
"""
from __future__ import annotations

import pytest

from chimera.dynamic import eth_rpc as E


# ── ABI codec ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("t,v", [
    ("string", "KEY_CHECK_VALUE"),
    ("string", ""),
    ("address", "0x76d76ee8823de52a1a431884c2ca930c5e72bff3"),
    ("uint256", 43152014),
])
def test_abi_roundtrip(t, v):
    enc = E.encode_params([t], [v])
    dec = E.decode_param(t, enc)
    if t == "address":
        assert dec.lower() == v.lower()
    else:
        assert dec == v


def test_encode_two_params_head_tail():
    # address (static) + string (dynamic): head = 2 words, tail = the string.
    enc = E.encode_params(["address", "string"],
                          ["0x" + "11" * 20, "hi"])
    assert len(enc) == 32 * 2 + 32 + 32           # 2 heads + len word + data word
    # the dynamic offset points past both heads
    assert int.from_bytes(enc[32:64], "big") == 64


def test_decode_unsupported_type_raises():
    with pytest.raises(E.AbiError):
        E.decode_param("uint8[]", b"\x00" * 32)


# ── network gate (off by default) ────────────────────────────────────────────

def test_eth_call_refuses_without_optin():
    r = E.eth_call("http://x", "0x0", "0x1234")
    assert r["ok"] is False and "network disabled" in r["error"]


def test_get_transaction_refuses_without_optin():
    r = E.get_transaction("http://x", "0xabc")
    assert r["ok"] is False and "network disabled" in r["error"]


# ── mocked RPC ───────────────────────────────────────────────────────────────

def test_eth_call_decodes_string_result(monkeypatch):
    payload = E.encode_params(["string"], ["on-chain-payload"])
    monkeypatch.setattr(E, "_rpc", lambda *a, **k: {"result": "0x" + payload.hex()})
    r = E.eth_call("http://x", "0xC0", "0x5684cff5", ["string"], ["k"],
                   return_type="string", allow_network=True)
    assert r["ok"] and r["decoded"] == "on-chain-payload"
    assert r["data_sent"].startswith("0x5684cff5")


def test_get_transaction_returns_calldata(monkeypatch):
    monkeypatch.setattr(E, "_rpc", lambda *a, **k: {
        "result": {"from": "0xaa", "to": "0xbb", "blockNumber": "0x2a4d3fc",
                   "input": "0x916ed24bdeadbeef", "value": "0x0"}})
    r = E.get_transaction("http://x", "0xhash", allow_network=True)
    assert r["ok"] and r["input"] == "0x916ed24bdeadbeef" and r["to"] == "0xbb"


def test_eth_call_surfaces_node_error(monkeypatch):
    monkeypatch.setattr(E, "_rpc", lambda *a, **k: {"error": {"code": -32000, "message": "missing trie node"}})
    r = E.eth_call("http://x", "0xC0", "0x1234", allow_network=True)
    assert r["ok"] is False and "missing trie node" in r["error"]
