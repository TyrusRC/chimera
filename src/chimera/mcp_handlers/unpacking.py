"""Static unpacking tools: peel layered/marshalled Python without running it.

Returns None when the tool is not one of this module's, so the server can
try the next handler group.
"""
from __future__ import annotations

import logging
from pathlib import Path

from mcp.types import TextContent

from chimera import mcp_session as mcpstate

logger = logging.getLogger(__name__)


async def dispatch(name: str, arguments: dict) -> list[TextContent] | None:
    if name == "flutter_extract":
        from chimera.adapters.blutter_adapter import BlutterAdapter, detect_libapp

        path = arguments["path"]
        if not Path(path).exists():
            return mcpstate.error(f"file not found: {path}")
        adapter = BlutterAdapter(binary_path=arguments.get("blutter_bin"))
        if not adapter.is_available():
            return mcpstate.error(
                "blutter not found — install from https://github.com/worawit/blutter, "
                "put it on PATH, or set CHIMERA_BLUTTER_BIN."
            )
        libapp = arguments.get("libapp")
        target = Path(libapp) if libapp else (
            detect_libapp(Path(path)) if Path(path).is_dir()
            else (Path(path) if Path(path).is_file() else None)
        )
        if target is None or not target.exists():
            return mcpstate.error(
                f"could not locate libapp.so / App binary under {path!r}; "
                "unpack the APK first (apktool d) or pass 'libapp' explicitly."
            )
        out_dir = arguments.get("out_dir") or f"{Path(path).with_suffix('')}_blutter"
        res = adapter.extract(target, out_dir)
        return mcpstate.json_reply({
            "ok": res.success,
            "out_dir": out_dir,
            "classes_dumped": res.classes_dumped,
            "methods_dumped": res.methods_dumped,
            "error": None if res.success else (res.stderr or "")[:1000],
        })

    if name == "hermes_decompile":
        from chimera.adapters.hermes_decomp import HermesDecompAdapter, detect_hbc

        path = arguments["path"]
        if not Path(path).exists():
            return mcpstate.error(f"file not found: {path}")
        adapter = HermesDecompAdapter(binary=arguments.get("hermes_bin"))
        if not adapter.is_available():
            return mcpstate.error(
                "hermes-decomp not found — install from "
                "https://github.com/SymbioticSec/hermes-decomp, put it on PATH, "
                "or set CHIMERA_HERMES_DECOMP_BIN."
            )
        target = Path(path)
        if target.is_dir():
            detected = detect_hbc(target)
            if detected is None:
                return mcpstate.error(
                    f"no Hermes bundle found under {path!r} "
                    "(expected index.android.bundle / main.jsbundle / *.hbc)"
                )
            target = detected
        res = await adapter.analyze(str(target), {
            "output_dir": arguments.get("out_dir"),
            "timeout": arguments.get("timeout", 300),
        })
        if not res.get("decompiled"):
            return mcpstate.error(f"hermes-decomp failed: {res.get('error') or 'unknown'}")
        return mcpstate.json_reply({
            "ok": True, "bundle": str(target),
            "output_file": res.get("output_file"), "size": res.get("size"),
        })

    if name == "sourcemap":
        from chimera.unpacking.sourcemap import recover_sources, write_sources

        path = arguments["path"]
        if not Path(path).exists():
            return mcpstate.error(f"file not found: {path}")
        r = recover_sources(path)
        if not r.get("ok"):
            return mcpstate.error(r.get("error", "source map recovery failed"))
        dest = arguments.get("out_dir") or (str(Path(path).with_suffix("")) + "_src")
        written = write_sources(r, dest)
        return mcpstate.json_reply({
            "ok": True, "count": r.get("count"), "out_dir": dest,
            "written": written[:200],
            "missing_content": len(r.get("missing_content") or []),
        })

    if name == "polyglot_scan":
        from chimera.unpacking.polyglot import scan

        path = arguments["path"]
        if not Path(path).exists():
            return mcpstate.error(f"file not found: {path}")
        hits = scan(path)
        return mcpstate.json_reply({"count": len(hits), "formats": hits})

    if name == "zip_legacy":
        from chimera.unpacking.zip_legacy import extract_file

        path = arguments["path"]
        if not Path(path).exists():
            return mcpstate.error(f"file not found: {path}")
        pw = arguments.get("password")
        pw_b = pw.encode() if isinstance(pw, str) else pw
        entries = []
        for e in extract_file(path, pw_b):
            d = e.pop("data", None)
            if d is not None:
                e["hex"] = d[:4096].hex()
                try:
                    e["text"] = d.decode("utf-8")
                except UnicodeDecodeError:
                    pass
            entries.append(e)
        return mcpstate.json_reply({"count": len(entries), "entries": entries})

    if name == "macho_codesign":
        from chimera.parsers.macho_codesign import (
            MachoCodeSignError, extract_slice, read_code_signatures,
        )
        path = arguments["path"]
        if not Path(path).exists():
            return mcpstate.error(f"file not found: {path}")
        try:
            sigs = [s.to_dict() for s in read_code_signatures(path)]
            result = {"signatures": sigs}
            idx = arguments.get("extract_slice")
            if idx is not None:
                out = arguments.get("out_path") or f"{path}.slice{idx}"
                result["extracted"] = {"index": int(idx), "out_path": out,
                                       "bytes": extract_slice(path, int(idx), out)}
            return mcpstate.json_reply(result)
        except MachoCodeSignError as exc:
            return mcpstate.error(str(exc))

    if name == "py_unwrap":
        from chimera.unpacking.pybytecode import disassemble, unwrap

        path = arguments["path"]
        if not Path(path).exists():
            return mcpstate.error(f"file not found: {path}")

        result = unwrap(path)
        if result.error and result.root is None:
            return mcpstate.error(result.error)

        payload = result.to_dict()
        if arguments.get("disasm"):
            payload["disassembly"] = [
                {"name": cn.name, "text": disassemble(cn.code_obj)}
                for cn in result.code_nodes()
            ]
        return mcpstate.json_reply(payload)

    if name == "fw_extract":
        from chimera.unpacking.uefi import carve_firmware, uefi_available
        path = arguments["path"]
        if not Path(path).exists():
            return mcpstate.error(f"file not found: {path}")
        if not uefi_available():
            return mcpstate.error('uefi_firmware not installed — pip install "chimera[firmware]"')
        result = carve_firmware(path, extract_dir=arguments.get("extract_dir"))
        return mcpstate.json_reply(result)

    if name == "node_extract":
        from chimera.unpacking.nodejs import extract_node_js

        path = arguments["path"]
        if not Path(path).exists():
            return mcpstate.error(f"file not found: {path}")
        result = extract_node_js(path, arguments.get("out_dir"))
        return mcpstate.json_reply(result.to_dict())

    if name == "tauri_extract":
        from chimera.unpacking.tauri import extract_tauri

        path = arguments["path"]
        if not Path(path).exists():
            return mcpstate.error(f"file not found: {path}")
        result = extract_tauri(path, arguments.get("out_dir"))
        return mcpstate.json_reply(result.to_dict())

    if name == "dotnet_extract":
        from chimera.unpacking.dotnet_bundle import extract_bundle

        path = arguments["path"]
        if not Path(path).exists():
            return mcpstate.error(f"file not found: {path}")
        result = extract_bundle(path, arguments.get("out_dir"))
        if not result.ok:
            return mcpstate.error(result.error or "extraction failed")
        return mcpstate.json_reply(result.to_dict())

    if name == "js_deobf":
        from chimera.unpacking.js_deobf import deobfuscate

        path = arguments["path"]
        if not Path(path).exists():
            return mcpstate.error(f"file not found: {path}")
        result = deobfuscate(path, out_dir=arguments.get("out_dir"),
                             prettier=bool(arguments.get("prettier", True)),
                             resolve=arguments.get("resolve"))
        if not result.get("available"):
            return mcpstate.error(result.get("error", "webcrack unavailable"))
        return mcpstate.json_reply(result)

    if name == "pdf_tour":
        from chimera.unpacking.pdf import pdf_tour

        path = arguments["path"]
        if not Path(path).exists():
            return mcpstate.error(f"file not found: {path}")

        tour = pdf_tour(
            path,
            password=str(arguments.get("password", "")).encode(),
            extract_images_dir=arguments.get("extract_images_dir"),
        )
        return mcpstate.json_reply(tour.to_dict())

    if name == "evm_tour":
        from chimera.parsers.evm import (
            EvmRevert, EvmUnsupported, evm_tour, run_pure, split_deploy_runtime,
        )

        source = arguments["source"]
        p = Path(source)
        try:
            is_file = p.exists()
        except OSError:                    # bytecode hex is longer than a filename
            is_file = False
        if is_file:
            raw = p.read_bytes()
            text = raw.decode("ascii", "ignore").strip()
            code = (bytes.fromhex(text[2:] if text.startswith("0x") else text)
                    if text and all(c in "0123456789abcdefABCDEF" for c in text)
                    else raw)
        else:
            try:
                code = bytes.fromhex(source[2:] if source.startswith("0x") else source)
            except ValueError:
                return mcpstate.error(f"not a file and not valid hex: {source[:40]}")

        calldata = arguments.get("calldata")
        if calldata is not None:
            runtime, _ = split_deploy_runtime(code)
            cd = bytes.fromhex(calldata[2:] if calldata.startswith("0x") else calldata)
            try:
                out = run_pure(runtime, cd)
            except (EvmUnsupported, EvmRevert, ValueError) as exc:
                return mcpstate.error(f"pure-run failed: {exc}")
            return mcpstate.json_reply({"return": "0x" + (out or b"").hex()})

        return mcpstate.json_reply(evm_tour(code).to_dict())

    if name == "wasm_decompile":
        from chimera.adapters import wabt
        from chimera.adapters.wabt import WasmToolError

        path = arguments["path"]
        if not Path(path).exists():
            return mcpstate.error(f"file not found: {path}")
        out_dir = arguments.get("out_dir") or f"{Path(path).with_suffix('')}_wasm"
        try:
            result = wabt.decompile(Path(path), Path(out_dir))
            if arguments.get("wat"):
                wat = Path(out_dir) / "module.wat"
                wabt.wat_disassemble(Path(path), wat)
                result["wat"] = str(wat)
        except WasmToolError as exc:
            return mcpstate.error(str(exc))
        return mcpstate.json_reply(result)

    if name == "wasm_oracle":
        from chimera.dynamic import wasm_oracle as wo

        path = arguments["path"]
        if not Path(path).exists():
            return mcpstate.error(f"file not found: {path}")
        inputs = arguments.get("inputs") or []
        export = arguments.get("export", "check")
        wasm_exec = arguments.get("wasm_exec")
        wasm_exec_p = Path(wasm_exec) if wasm_exec else None
        go = arguments.get("go")
        try:
            if arguments.get("trace"):
                result = wo.trace(Path(path), inputs, export=export, go=go,
                                  wasm_exec=wasm_exec_p)
            else:
                result = wo.run_oracle(Path(path), inputs, export=export, go=go,
                                       wasm_exec=wasm_exec_p)
        except wo.WasmOracleError as exc:
            return mcpstate.error(str(exc))
        return mcpstate.json_reply(result)

    return None
