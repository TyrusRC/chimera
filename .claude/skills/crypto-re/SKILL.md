---
name: crypto-re
description: Use when a target's secret is gated by CRYPTO — an RSA/AES/stream-cipher blob to decrypt, a key to recover, a weak-parameter RSA to break, a hash/keygen check to invert, or an encrypted config/flag. Sets chimera's crypto-solving flow (rsa_recover / decrypt_blob / find_aes_keys / symcrypt / yara_solve / symexec) over hand-rolling the math. Load after re-workflow recon when the blocker is cryptographic, not control-flow.
---

# Crypto RE: recover the key, don't re-roll the math

The failure mode is hand-writing a decryptor or a factoring loop when chimera
already ships the primitive. **Identify the scheme, then reach for the tool.**
Every one degrades cleanly (missing optional dep → a clear message, not a crash)
and is deterministic/offline unless noted.

## Decide the scheme first (cheap)
- `detect_capabilities` / `get_strings` for crypto constants (S-boxes, `BCryptOpenAlgorithm`,
  `EVP_`, curve names), and `detect_protocols`/`detect_sdks` for a crypto SDK
  (OpenSSL/BouncyCastle/libsodium). A named library ⇒ standard scheme ⇒ a tool below.
- High-entropy section/blob in the summary = the ciphertext; a low-entropy 176/240/
  256-byte run near it may be an **AES key schedule** (see `find_aes_keys`).

## Pick the primitive

- **RSA with weak/leaked parameters** → `rsa_recover` (MCP) / `chimera rsa-solve`.
  Recovers `d`/plaintext from what's exposed — small `e` + no padding, shared or
  close primes, partial-key, given `p`/`q`/`dp`. Feed it the modulus + whatever
  leaked; it inverts rather than brute-forcing. Don't shell out to a factoring
  script until this can't.

- **AES key recovered at RUNTIME** (derived/decrypted/unpacked — never a literal)
  → `find_aes_keys` (MCP) / `chimera aeskeys`. It locates an expanded AES-128/192/256
  key schedule in a **memory dump / ELF core / live process / hex blob** by the
  KeyExpansion recurrence (self-checking), and reports the key + a candidate IV
  (tiny-AES layout). Pair with a process dump or a frozen target (see
  `dynamic-analysis`) when the key only exists while running.

- **A blob to decrypt with a KNOWN scheme+key** → `decrypt_blob` (MCP) /
  `chimera decrypt`. AES-CBC/ECB, XOR, RC4 etc. from a file/hex + key — so you test
  a recovered key without writing a one-off script.

- **A stream cipher / keystream** (ChaCha20, Salsa20, RC4) → `symcrypt` — the
  involutive keystream-XOR primitive (needs the `[pdf]`/crypto extra). Recover the
  flag once you have key+nonce (e.g. from `find_aes_keys`/`bp-dump`).

- **A YARA-keygen challenge** (craft an input that matches a `.yara` rule) →
  `yara_solve` (MCP) / `chimera yara-solve` — compiles the condition to Z3 and
  synthesises a matching file (the flag), then verifies with yara-python.

- **A per-byte compare / keygen check** (the "password" lives only as `cmp`
  immediates, or as a hardcoded byte array) → `recover_cmp_string` /
  `recover_data_bytes` (its `--gadget-target` inverts an additive gadget to the
  required input). For a check whose accepting input is non-obvious, declare the
  input symbolic and let **`symexec`** (angr) invert the constraints.

## The runtime-key move (when the key is computed, not stored)
Modern crypto challenges DERIVE the key at runtime (PBKDF2/KDF, decrypt-then-use).
Don't reverse the KDF by hand:
1. Run the target as an oracle (see `dynamic-analysis` / `sandbox`) or
   `emulate_function` the leaf that produces the key.
2. `run_with_breakpoints` / `x64dbg` to read the derived key at the call site, or
   `find_aes_keys` over a dump once it's resident.
3. Then `decrypt_blob` / `symcrypt` with the recovered key. Ground-truth key beats
   a re-derived KDF every time.

## Anti-patterns
- Hand-writing a factoring loop or an AES decryptor when `rsa_recover` /
  `decrypt_blob` / `find_aes_keys` already cover it — that's the gap this skill
  closes; log any case they miss (see re-workflow's gap protocol).
- Trusting a "the key is X" claim carried across a context boundary — re-verify by
  actually decrypting with it (`decrypt_blob`) before building on it.
- Reaching for symexec on a plain `cmp` cascade — `recover_cmp_string` is cheaper.
