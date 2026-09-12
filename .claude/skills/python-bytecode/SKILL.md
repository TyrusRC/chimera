---
name: python-bytecode
description: Use when a target is Python — a frozen EXE (PyInstaller/py2exe), a .pyc, a .py that exec()s a marshalled/compressed/encoded blob, or a Nuitka-compiled binary. Covers static layer-peeling, the version-independent co_names/co_consts trick, cross-version disassembly, detecting Nuitka (native C, not bytecode), and when NOT to run the target.
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
- **Nuitka** (NOT bytecode — a trap for this skill): Nuitka compiles Python to
  native C, so there is no pyc to recover — it is genuine native RE (treat it
  like any C++ PE; `analyze`/disasm, not `pyextract`). Detect it by strings
  `nuitka` / `__compiled__` / a `cpNNN-…` tag, a `.pyd` beside `.exe`, or a
  `MANIFEST.txt`. If it ships `.encrypted` source with the key in Nuitka
  constants (`.rdata`/`.rsrc`), it is usually XOR+base64 with a repeating key —
  recover the key by known-plaintext from a predictable file (a JSON config
  starts `{` ⇒ `key[i] = enc[i] ^ plaintext[i]`), verify it parses, then bulk
  decrypt. (chimera has no dedicated Nuitka helper yet — this is native RE.)

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
