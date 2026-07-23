# Chimera — Review Findings & Remediation Checklist

Prioritized findings from a full-codebase review (architecture, AI/diff subsystems,
platform performance & security) plus a competitive gap analysis vs Binary Ninja /
Sidekick and the broader RE-tool landscape.

Legend: `[ ]` open · `[x]` fixed in-tree · `[~]` partially addressed / documented.
File refs are `path:line` at review time.

## Fixed (this branch)

Wave 1 (security/correctness): C1 (auth + localhost default), C2 (covered by C1
auth), C3 (ghidra_home removed + path confinement), H1 (extract caps), H3
(ResourceManager singleton), H4 (yara + blutter off-loop), H5 (upload cap + TTL),
H6 (flutter path confinement), H7 (API verify gate + identifier sanitization), M1
(CORS credentials), M2 (compose no longer publishes 5432), M3 (ghidra outer
timeout), A1/A2 (ghidra decompile + ingest), A3 (ilspy source surfaced), A6
(`--heuristic multi` wired).

Wave 2: A4 (r2 `aaa` escalation for stripped binaries), M4 (bounded reads in the
string scanners), H2-partial (bounded in-memory store), A7-corrected (x86_64 FLIRT
DB *is* shipped with 176 sigs).

Wave 3: A8 (`sources` column + serialize + save/load), H2-full (opt-in write-through
persistence + rehydrate-on-miss via `api/persistence.py`, gated by `CHIMERA_PERSIST`,
default off), A7 (informative "no pack for this arch" log).

New tests: `test_security_fixes.py`, `test_ghidra_ingest.py`, `test_r2_deepen.py`,
`test_sources_persistence.py`, `test_persistence_manager.py` (all green in-sandbox);
the asyncpg execution paths are covered by the Postgres integration suite (docker).
Only genuine remaining gap: an **arm64 FLIRT signature pack** (needs an aarch64
libc/toolchain to generate — no code fix possible here).

---

## Framing

Chimera is an **orchestration layer** over external tools (Ghidra, radare2, jadx,
ILSpy, capa, YARA, Frida, Volatility…). It owns **no IL, no SSA, no CFG, and no
decompiler of its own** — `model/function.py` stores `decompiled: str` and
`disassembly: list[dict]` as opaque tool output. Most findings below are the cost
of the wrapper model; the highest-value fixes make the tool honestly deliver what
it already computes.

---

## SECURITY — Critical (do before any network exposure)

- [x] **C1 — API is unauthenticated and binds `0.0.0.0` by default.**
  `cli/serve_cmd.py:19` (`--host 0.0.0.0`); `api/server.py` has zero auth
  dependency. Compose publishes `8080:8080`.
  → Default to localhost bind; add a fail-closed bearer-token `Depends` on all
  routers. Fixing C1 de-fangs C2/C3/H5/H6.

- [x] **C2 — Unauthenticated device RCE via Frida.**
  `POST /api/frida/sessions/{id}/exec` runs attacker JS in the target process
  (`api/frida_session_manager.py:134`, `api/routes/frida.py:70`); `.../load` loads
  arbitrary scripts.
  → Gate behind auth + explicit per-session capability; treat as the most
  privileged surface.

- [x] **C3 — Arbitrary file read + code-exec via analyze.**
  `POST /api/projects` analyzes any server path (`api/routes/projects.py:88`); the
  request body carries `ghidra_home`, executed as
  `<ghidra_home>/support/analyzeHeadless` (`adapters/ghidra.py:56`).
  → Confine `path` under the staging/project root; drop `ghidra_home` from the
  request model (server-config only).

## SECURITY — High

- [x] **H1 — `safe_extract` has no decompression-bomb caps** (zip-slip only;
  `pipelines/safe_extract.py:32` `extractall()` unconditional; zip symlink members
  not inspected).
  → Sum member sizes; cap total + per-file + count before extract; stream with a
  running budget.

- [x] **H2 — All project state was an in-memory dict** with no persistence.
  **Fixed (two parts):** (1) `_ProjectStore` evicts oldest non-in-flight projects
  past `CHIMERA_MAX_PROJECTS` (default 32) — a RAM ceiling; (2) opt-in write-through
  persistence (`api/persistence.py`, `ChimeraDatabase.save_model`/`load_model`/
  `load_model_by_id`) wired into `_run_analysis` (save) and `_ProjectStore.get`
  (rehydrate-on-miss), gated by `CHIMERA_PERSIST` and fully best-effort so the
  default (no DB) path is unchanged. `save_model` persists binary + functions +
  **strings + call graph**; `load_model` rehydrates all four. Manager logic
  unit-tested (`test_persistence_manager.py`); the asyncpg execution path is
  covered by the Postgres integration suite
  (`test_database_pg.py::test_save_and_load_full_model`).

- [x] **H3 — ResourceManager is per-request** (`core/engine.py:61` builds a new one
  per analysis), so its heavy/light semaphores can't cap RAM across concurrent
  analyses → N×Ghidra JVMs blow the 14 GB compose limit.
  → Make it a process singleton + add a global analysis-concurrency gate.

- [x] **H4 — Event-loop blocking:** synchronous `subprocess.run(timeout=600)` in an
  async handler (`adapters/blutter_adapter.py:91` via `api/routes/flutter.py:74`);
  synchronous `rules.match(timeout=30)` (`adapters/yara_adapter.py:94`).
  → Wrap in `asyncio.to_thread` (pattern already used at `api/routes/ai.py:113`).

- [x] **H5 — Unbounded unauthenticated uploads** (`api/routes/uploads.py:30`): no
  size cap, no extension allowlist, no cleanup of `~/.chimera/uploads`.
  → Cap size, allowlist extensions, TTL cleanup.

- [x] **H6 — Flutter extract writes to an arbitrary absolute path**
  (`api/routes/flutter.py:74`, `libapp_override`/`out_dir` unsanitized).
  → Confine under the project dir; validate override is inside the project tree.

- [x] **H7 — API rename endpoint bypasses the adversarial verifier.**
  `api/routes/ai.py:276` applies renames on confidence alone; the CLI correctly
  gates on `confidence >= min AND verify_accepted` (`cli/ai_cmd.py:312`). Combined
  with prompt-injection (decompiled bytes interpolated verbatim into prompts,
  `ai/prompts.py:36`) and no identifier sanitization (`core/overlay.py:149`), a
  crafted binary can plant arbitrary overlay content through the API.
  → Enforce the verify gate on the API path; sanitize/charset-clamp model-derived
  names before overlay writes.

## SECURITY — Medium

- [x] **M1 — CORS** `allow_credentials=True` with permissive localhost regex
  (`api/server.py:34`) — DNS-rebinding risk against the 0.0.0.0 bind.
- [x] **M2 — Hardcoded default DB creds** `chimera:chimera` with 5432 published
  (`core/config.py:60`, `docker-compose.yml`).
- [x] **M3 — Ghidra subprocess lacks an outer `wait_for`** (`adapters/ghidra.py:111`)
  — a wedged JVM holds the heavy semaphore until the 1800 s engine timeout.
- [x] **M4 — Whole-file reads on large bundles.** The Hermes/Dart/IL2CPP string
  scanners `read_bytes()` the entire file then looped byte-by-byte.
  **Fixed:** capped reads (`CHIMERA_MAX_SCAN_MB`, default 128 MB) in
  `react_native.py`/`flutter.py`; unity's entropy check now reads only its 64 KB
  sample. Bounds the RAM spike; behavior unchanged for files under the cap.

### Notably OK (verified, not issues)
No `shell=True`/`eval`/`pickle`/`os.system`; all tools spawned via
`create_subprocess_exec(*args)`; parameterized asyncpg SQL; zip-slip handled; AI
key from env, never logged; base_url from env (no SSRF).

---

## CORRECTNESS — the tool doesn't do what it advertises

- [x] **A1 — Ghidra script never decompiled.** `ghidra_scripts/ExportFunctions.java`
  wrote only functions/strings/symbols; no `DecompInterface`.
  **Fixed:** added `writeDecompilations()` (DecompInterface → `decompilations.json`,
  bounded by `-Dchimera.decompile.max` / `.timeout`).

- [x] **A2 — Ghidra output never ingested into the model.** Pipelines cached the
  result and discarded it (`pipelines/pe.py`, `elf.py`, `ios.py`, `android.py`), so
  `FunctionInfo.decompiled` was always None for native code.
  **Fixed:** new `pipelines/common.py:ingest_ghidra_functions()` merges functions +
  decompiled C into the model (address-normalized, backfilled onto r2-seeded
  functions via the enhanced `UnifiedProgramModel.add_function` merge); wired into
  all four native pipelines and into warm-cache rehydration. Covered by
  `tests/unit/test_ghidra_ingest.py`.

- [x] **A3 — ILSpy decompiled C# is dropped.** `adapters/ilspy.py:108` `_walk_output`
  returned metadata only; `pipelines/pe.py` reads a never-set `decompiled` key.
  **Fixed:** `_walk_output` now reads each emitted `.cs` (capped at 256 KB/type) into
  a `decompiled` field, so `FunctionInfo.decompiled` is populated for .NET types.

- [x] **A4 — Functions came from r2's *symbol table*, not analysis.** Native
  pipelines ran r2 `triage` → `isj`; the `aaa` path existed but was never called,
  so stripped binaries yielded ~0 functions.
  **Fixed:** `should_deepen_r2()` + `deepen_r2_functions()` in `pipelines/common.py`;
  PE/ELF now escalate to r2's analysis pass when triage under-recovers (or when
  `config.r2_deep` forces it), merging the recovered functions. Tested in
  `tests/unit/test_r2_deepen.py`.

- [x] **A6 — README documented non-existent diff flags.** `--backend/--rerank/
  --heuristic` didn't exist in `cli/diff_cmd.py`.
  **Fixed:** wired `--heuristic [jaccard|multi]` into `diff-functions` (real in-repo
  algorithm) and corrected the README; KEENHash/REVDECODE remain library-API-only
  and are now honestly documented as such (they need a real model / backend
  registration, deferred).

- [~] **A7 — FLIRT coverage is x86_64-only (not "no signatures").**
  `data/sigs/libfn-x86_64.json` ships **176** signatures (libc-musl/openssl/zlib/
  curl) — matching the README. The real gap: no arm64/other-arch packs, and it's an
  O(functions × signatures) linear scan. Generating arm64 sigs needs arm64 libc
  objects (out of sandbox); left as a data/perf follow-up. `match_functions` now
  logs which packs *are* available when the target arch has none, so a stripped
  arm64 user learns why FLIRT matched nothing. `parsers/function_signatures.py`
  `load_signature_db` no-ops on an empty `data/sigs/`; O(functions × signatures)
  linear. Verify the "176 prefixes" JSONs are actually shipped/generated.

- [x] **A8 — Lossy persistence (`sources` dropped).**
  **Fixed:** added a `sources TEXT` column (`schema.py`), a dependency-free
  `model/serialize.py` (encode/decode), and wired it through
  `save_function`/`load_functions`; removed the drop-warning. Round-trip proven via
  stdlib-sqlite (`test_sources_persistence.py`) and asserted in the pg integration
  test. Superseded finding text follows.
  ~~`FunctionInfo.sources` dropped on every DB
  round-trip (`model/database.py:104`, TODO); ObjC metadata, import buckets, and
  disassembly aren't in the schema at all.

### Research add-ons — status (all opt-in; none ship weights/binaries in-repo)
- Real via Claude API: LLM4Decompile-style refine, SymGen batch-rename,
  Sidekick-style verify, DecLLM recompile gate, PseudoFix rewrites.
- Real algorithm, unreachable from CLI: REVDECODE rerank, multi-heuristic diff.
- Surrogate/stub: KEENHash (`_stub_embedding`, `diff/keenhash_backend.py:207`),
  EMBER fallback (259-dim vs required 2381-dim), msynth (imported then ignored,
  `ai/postprocess.py:41`).
- Honest no-op shims (need absent external tools/models): Idioms, VarBERT, Mergen,
  Blutter, hermes-decomp, oatdump, Oxidizer (yields plain angr), BinQuery, FirmAgent
  loop (`pipelines/firmware_agent_loop.py` default hooks return `[]`).
- Latent bug: `AIClient.complete(system, user)` vs `firmware_agent_loop`'s
  `client.complete(prompt)` — signatures don't match.

---

## PERFORMANCE

- [ ] Cold subprocess spawn per phase; no warm r2 session reused across triage →
  decomp (the decomp route re-opens r2 per function, `api/routes/decomp.py:119`);
  Ghidra spins a full JVM per binary.
- [ ] Whole-artifact SHA256 cache only (`core/cache.py`) — any change re-runs the
  whole pipeline; no function/phase-level incremental analysis.
- [ ] Greedy O(functions²) diff with no blocking/indexing
  (`diff/function_similarity.py`).

---

## COMPETITIVE GAPS (roadmap, landscape-informed)

Table-stakes it fails: **a real decompiler backed by its own IL/SSA** (delegated).
Differentiators where Chimera wins: agentic MCP orchestration, verified LLM
decompiler refinement, mobile-framework reversing, whole-binary+rerank similarity.
Differentiators absent: native IL/SSA/symbolic, learned function embeddings,
concolic+fuzz hybrid, live collaboration, autonomous binary vuln discovery.

Highest-leverage bets:
1. Promote the existing angr dependency from a Rust-only path into a first-class
   symbolic/IL core (VEX + P-code via pypcode) — unlocks native deobfuscation,
   taint, type inference, and the LLM+symbolic hybrid; cheapest route to
   Sidekick-style "every finding links to IL".
2. Add a learned function-embedding recall model (jTrans/CLAP-class) to feed
   REVDECODE better candidates than opcode Jaccard.
3. BinExport protobuf ingest for IDA/Ghidra/BN similarity interop.
4. Grow the firmware shim into a FACT/EMBA/Karonte-class pipeline, then layer the
   existing agentic AI on top.
5. Live collaboration server to retire file-based `overlay.json` sharing.
