## Non-mobile binary fixtures

These directories supply minimal PE/ELF/.NET binaries for the integration
tests under `tests/integration/test_pipelines_*_e2e.py`.

### Directory layout

- `src/` — shared C source (`hello.c`).
- `pe/hello.exe` — Windows PE32+ binary. Built via mingw; otherwise a
  Python-synthesized stub (`build_pe_fixture.py`) is used.
- `elf/hello` — Linux ELF, built statically via gcc.
- `dotnet/src/` — C# project; .NET assembly built via `dotnet publish`.
- `dotnet/bin/hello.dll` — managed assembly. If `dotnet` is unavailable,
  a Python-synthesized stub (`build_dotnet_fixture.py`) is used.

### Rebuild

```sh
./build_fixtures.sh
```

This script falls back to the Python synthesizers when the real
toolchains are absent. The synthesizers produce parseable but
non-runnable binaries; integration tests only verify pipeline plumbing,
not behavioral correctness.

Keep each fixture under 200 KB.

## Memory image fixtures

`memory/sample.lime` — synthetic LiME-format memory image (~4 KB).

Built by `build_lime_fixture.py`. The file starts with a well-formed LiME
header (magic `EMiL` / `0x4C694D45` little-endian, version 1, 4 KB address
range) followed by 4096 zero bytes. It is parseable by Chimera's
`_detect_format` / `detect_binary_format` functions and will be classified as
`MEMORY_LIME` / `linux_memory`.

Volatility plugins will not extract meaningful kernel data from it — the
integration tests gate on classification and triage-cache writes, not on
Volatility plugin output.

### Rebuild

```sh
python tests/fixtures/build_lime_fixture.py
```
