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
