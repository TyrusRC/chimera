---
name: python-bytecode
description: Use when a target is Python — a frozen EXE (PyInstaller/py2exe), a .pyc, or a .py that exec()s a marshalled/compressed/encoded blob. Covers static layer-peeling, the version-independent co_names/co_consts trick, cross-version disassembly, and when NOT to run the target.
---

# Reversing Python Targets (static, never run it)

Frozen/obfuscated Python is a recurring target class. It is almost always
solvable **statically** — running the target is often a trap (it may be
keyed, sandbox-hostile, or the flag path never triggers). Default to never
executing it.

## Decide the shape first
- **Source provided** (`.py` sitting next to the binary): read the source; the
  17MB frozen `.exe` is usually a tar pit. This is the fastest win — check for
  co-located `.py` before anything.
- **Frozen EXE** (PyInstaller): `chimera pyextract <exe> -o out/` — recovers the
  entry scripts + app modules + PYZ as loadable `.pyc`. `analyze` auto-detects
  PyInstaller and points here instead of dumping bootloader disassembly.
- **Raw/layered blob** (a `.py` that `exec(marshal.loads(zlib.decompress(...)))`,
  or base85/bz2/lzma nesting): `chimera pyunwrap <file>` (MCP `py_unwrap`) —
  recursively peels marshal/zlib/base64/base85/bz2/lzma and dumps the layer
  tree. Extract the bytes literal with `ast.literal_eval`, NEVER by importing
  the module.

## The key trick: co_names / co_consts are version-independent
When a marshalled code object was compiled for a **different** Python than the
host, `dis` shows garbage (opcode tables differ) — but `co_names`, `co_consts`
(recurse into nested code objects), `co_varnames`, and `co_filename` marshal
cleanly and reveal the whole logic: imports, string/byte constants, embedded
keys, the call sequence. **Read the consts tree before reaching for a
disassembler.** `pyunwrap` dumps this tree for you.

## Cross-version disassembly (only if you need the opcodes)
1. Detect the compile version: pyc magic, or a syntax feature (a nested
   f-string `f"{f''}"` ⇒ ≥3.12), or opcode-sanity across candidate tables.
2. Disassemble under that version: `chimera pyunwrap --disasm` (uses `xdis`
   when installed, which handles host≠target). Only fetch the matching
   interpreter (`uv python install 3.12`) if you must actually RUN a recovered
   function — prefer static reading.

## Decompilers are optional and brittle
`pycdc`/`decompyle3` often fail on modern constructs (async `RETURN_GENERATOR`,
3.12+ opcodes), forcing a fall back to a disassembler + manual reconstruction.
Don't depend on a decompiler: the consts tree + targeted disasm usually gets
you there faster.

## Then solve the logic
Recover keys/transforms from the consts and invert them (XOR is self-inverse;
an RC4/AES key derived from a username → invert the derivation, don't brute
force — see the `gpu-acceleration` skill's guardrail). Pull embedded ciphertext
straight from `co_consts` and decrypt offline.
