"""ELF native-runtime fingerprinting (Tauri / Rust / Go)."""

from __future__ import annotations

from chimera.frameworks.native_elf import detect_elf_runtime
from chimera.frameworks.native_pe import _detect_tauri


def test_detect_tauri_via_internals_marker():
    data = b"....__TAURI_INTERNALS__....cargo/registry/src/x/tauri-2.11.5/lib.rs...."
    rt = detect_elf_runtime(data)
    assert rt is not None and rt[0] == "tauri"
    assert "2.11.5" in rt[1]


def test_detect_tauri_embedded_v8_detail():
    data = b"__TAURI__ tauri-2.11.5 rusty_v8-0.32.1 version 9.5.172.19 blah"
    rt = _detect_tauri(data)
    assert rt is not None and rt[0] == "tauri"
    assert "rusty_v8-0.32.1" in rt[1]
    assert "9.5.172.19" in rt[1]


def test_detect_tauri_via_wry_and_tao():
    data = b"xx wry-0.52.0 yy tao-0.34.0 zz"  # no __TAURI__ / tauri-ver, but wry+tao
    rt = detect_elf_runtime(data)
    assert rt is not None and rt[0] == "tauri"


def test_tauri_beats_plain_rust():
    # A Tauri binary also carries Rust markers; the more specific tag must win.
    data = b"/rustc/0123456789abcdef/library cargo/registry __TAURI_INTERNALS__ tauri-2.0.0"
    rt = detect_elf_runtime(data)
    assert rt is not None and rt[0] == "tauri"


def test_plain_rust_still_rust():
    data = b"xx cargo/registry xx library/std/src/ panic yy"
    rt = detect_elf_runtime(data)
    assert rt is not None and rt[0] == "rust"


def test_go_detected_on_elf():
    data = b"\xff Go buildinf:\x08\x00 go1.22.2 runtime.goexit"
    rt = detect_elf_runtime(data)
    assert rt is not None and rt[0] == "go"
    assert "go1.22.2" in rt[1]


def test_no_false_positive():
    assert detect_elf_runtime(b"\x7fELF" + b"\x00" * 256) is None
    assert _detect_tauri(b"just some plain C program strings") is None
