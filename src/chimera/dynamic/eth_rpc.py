"""Read-only EVM JSON-RPC fetch — reach LIVE on-chain state for malware triage.

`evm_tour` disassembles/interprets EVM bytecode OFFLINE; it cannot read what a
deployed contract returns or what a transaction carried. The **EtherHiding**
technique (ClearFake and kin) hides the real payload on-chain and pulls it at
runtime via `eth_call` / by reading a storage-write transaction's calldata — so
triaging such a dropper means doing those reads. This does exactly two, read
only: `eth_call` (ABI-encode a method call, decode the result) and
`get_transaction` (recover a tx's calldata).

Network egress is OFF by default: every call refuses unless `allow_network=True`
is passed explicitly, so importing/uinit-testing this never touches the network.
A minimal ABI codec covers the types EtherHiding uses (string, address, bytes,
uintN); anything else raises rather than guessing.
"""
from __future__ import annotations

import json
import urllib.request

_WORD = 32


class AbiError(Exception):
    pass


def _is_dynamic(t: str) -> bool:
    return t in ("string", "bytes")


def _enc_one(t: str, v) -> tuple[bytes, bool]:
    """Return (encoding, is_dynamic) for a single value."""
    if "[" in t or "(" in t:            # arrays/tuples are out of scope
        raise AbiError(f"unsupported composite ABI type: {t!r}")
    if t == "string":
        b = v.encode() if isinstance(v, str) else bytes(v)
        return _enc_bytes(b), True
    if t == "bytes":
        b = bytes.fromhex(v[2:] if isinstance(v, str) and v.startswith("0x") else v) \
            if isinstance(v, str) else bytes(v)
        return _enc_bytes(b), True
    if t == "address":
        n = int(v, 16) if isinstance(v, str) else int(v)
        return n.to_bytes(_WORD, "big"), False
    if t.startswith("uint") or t.startswith("int"):
        n = int(v, 0) if isinstance(v, str) else int(v)
        return (n & ((1 << 256) - 1)).to_bytes(_WORD, "big"), False
    raise AbiError(f"unsupported ABI type for encode: {t!r}")


def _enc_bytes(b: bytes) -> bytes:
    pad = (-len(b)) % _WORD
    return len(b).to_bytes(_WORD, "big") + b + b"\x00" * pad


def encode_params(types: list[str], values: list) -> bytes:
    """ABI-encode a flat parameter list (head/tail; no nested tuples/arrays)."""
    if len(types) != len(values):
        raise AbiError("types/values length mismatch")
    heads: list[bytes] = []
    tails: list[bytes] = []
    head_len = _WORD * len(types)
    for t, v in zip(types, values):
        enc, dyn = _enc_one(t, v)
        if dyn:
            off = head_len + sum(len(x) for x in tails)
            heads.append(off.to_bytes(_WORD, "big"))
            tails.append(enc)
        else:
            heads.append(enc)
    return b"".join(heads) + b"".join(tails)


def decode_param(t: str, data: bytes):
    """Decode a single ABI return value from `data` (the whole return blob)."""
    if "[" in t or "(" in t:            # arrays/tuples are out of scope
        raise AbiError(f"unsupported composite ABI type: {t!r}")
    if len(data) < _WORD:
        raise AbiError("return data too short")
    if t in ("string", "bytes"):
        off = int.from_bytes(data[:_WORD], "big")
        length = int.from_bytes(data[off:off + _WORD], "big")
        raw = data[off + _WORD:off + _WORD + length]
        return raw.decode(errors="replace") if t == "string" else raw
    if t == "address":
        return "0x" + data[_WORD - 20:_WORD].hex()
    if t.startswith("uint") or t.startswith("int"):
        return int.from_bytes(data[:_WORD], "big")
    raise AbiError(f"unsupported ABI type for decode: {t!r}")


def _rpc(rpc_url: str, method: str, params: list, timeout: int) -> dict:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                          "params": params}).encode()
    req = urllib.request.Request(rpc_url, data=payload,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - user-supplied RPC
        return json.load(resp)


def eth_call(rpc_url: str, to: str, method_id: str,
             param_types: list[str] | None = None, args: list | None = None,
             *, block: str | int = "latest", return_type: str | None = None,
             allow_network: bool = False, timeout: int = 30) -> dict:
    """ABI-encode a method call, eth_call it, and (optionally) decode the result.

    `method_id` is the 4-byte selector (e.g. 0x5684cff5). `return_type` decodes
    the raw return (e.g. "string" for an EtherHiding payload). Read-only; refuses
    unless allow_network=True.
    """
    if not allow_network:
        return {"ok": False, "error": "network disabled — pass allow_network=true "
                "(this makes a live read-only eth_call to the given RPC)."}
    mid = method_id if method_id.startswith("0x") else "0x" + method_id
    data = mid + (encode_params(param_types or [], args or []).hex())
    blk = hex(block) if isinstance(block, int) else block
    try:
        r = _rpc(rpc_url, "eth_call", [{"to": to, "data": data}, blk], timeout)
    except Exception as exc:
        return {"ok": False, "error": f"RPC error: {exc}"}
    if "error" in r:
        return {"ok": False, "error": f"node error: {r['error']}", "data_sent": data}
    result_hex = r.get("result", "0x")
    out = {"ok": True, "result_hex": result_hex, "data_sent": data, "block": blk}
    if return_type and result_hex not in ("0x", "", None):
        try:
            out["decoded"] = decode_param(return_type, bytes.fromhex(result_hex[2:]))
        except AbiError as exc:
            out["decode_error"] = str(exc)
    return out


def get_transaction(rpc_url: str, tx_hash: str, *, allow_network: bool = False,
                    timeout: int = 30) -> dict:
    """Fetch a transaction; the `input` field is its calldata (the payload store)."""
    if not allow_network:
        return {"ok": False, "error": "network disabled — pass allow_network=true."}
    try:
        r = _rpc(rpc_url, "eth_getTransactionByHash", [tx_hash], timeout)
    except Exception as exc:
        return {"ok": False, "error": f"RPC error: {exc}"}
    tx = r.get("result")
    if not tx:
        return {"ok": False, "error": "transaction not found"}
    return {"ok": True, "from": tx.get("from"), "to": tx.get("to"),
            "block_number": tx.get("blockNumber"), "input": tx.get("input"),
            "value": tx.get("value")}
