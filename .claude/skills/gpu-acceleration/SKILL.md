---
name: gpu-acceleration
description: Use when a task involves cracking a hash, brute-forcing a password or small key/keyspace, or opening a password-protected archive (ZIP/7z/PDF/Office/KeePass) — detects the host GPU + hashcat/john and decides whether (and how) to offload to the GPU, or whether to recover the secret analytically instead.
---

# GPU-Accelerated Cracking

This box may have a GPU that turns hours of CPU work into seconds — but a GPU
helps only for the right shape of problem. This skill's job is twofold: **route
crackable work to the GPU**, and **stop uncrackable work from ever starting**.

## Step 0 — Detect (always first)

Query the host before proposing any crack:

- MCP: `detect_gpu` → `{gpus, hashcat, john, usable, note, hint}`
- CLI: `chimera gpu` (add `--json` to parse)

If `usable` is false, read `note` (no GPU? no cracker? — `apt install hashcat`)
and fall back to CPU or an analytic path. Do not claim GPU speed you don't have.

## Step 1 — Is this even brute-forceable? (the guardrail)

**Brute force is a last resort, not a first move.** Before reaching for hashcat,
decide honestly whether the keyspace is searchable:

| Situation | Do this |
|---|---|
| Known hash of an unknown *password* (human-chosen, ≤~10 chars, or wordlist-shaped) | ✅ GPU crack |
| Password-protected archive/document | ✅ extract hash → GPU crack |
| Small key with a **verifiable oracle** (known plaintext / magic bytes / checksum) and keyspace ≲ 2^40 | ✅ GPU or a short custom search |
| **Large unknown key** (e.g. a 16–32 byte RC4/AES key) with no crib | ❌ **NOT brute-forceable — recover it analytically** |
| The key is *derived* from something recoverable (a username, a transform, a seed) | ❌ don't crack — invert the derivation |

> Example: a key that looks large (16–32 bytes) but is *derived* from a
> recoverable value (a username, a seed, a timestamp) via a reversible transform
> (XOR, add, a small PRNG) is NOT brute-forceable — recover the input and replay
> the derivation. XOR and add are self-inverse. **When a key comes from a
> transform, invert the transform; never brute-force a derived key.** Announce
> this and skip the GPU.

If Step 1 says "not brute-forceable," stop here and solve it analytically.

## Step 2 — Route by workload (when the GPU does help)

### A. Hash / password cracking
1. Identify the hash type. `hashcat --identify <hashfile>`, or match the format
   (32 hex = MD5/NTLM, 40 = SHA1, `$2b$` = bcrypt, `$6$` = sha512crypt, …).
2. Pick the `-m` mode (e.g. 0 MD5, 100 SHA1, 1000 NTLM, 1400 SHA256, 3200 bcrypt,
   1800 sha512crypt). `hashcat --help | grep -i <name>` if unsure.
3. Attack, cheapest first:
   - Wordlist: `hashcat -m <mode> hash.txt rockyou.txt`
   - Wordlist + rules: `... rockyou.txt -r /usr/share/hashcat/rules/best64.rule`
   - Mask (known structure): `hashcat -m <mode> -a 3 hash.txt '?u?l?l?l?d?d?d?d'`
4. Read results from the potfile or `hashcat -m <mode> hash.txt --show`.

### B. Crypto keyspace search (only after Step 1 says ✅)
- If it maps to a hashcat mode, use it. Otherwise write a **tight** custom search
  that (a) enumerates only the justified keyspace and (b) validates each candidate
  against the oracle (known plaintext prefix, magic bytes, or `decode()` succeeding).
- Keep it CPU unless the keyspace genuinely needs the GPU; a 2^32 XOR search with a
  crib is often faster to just run in C/numpy than to marshal onto hashcat.

### C. Password-protected archives / documents
Extract the crackable hash with the matching `*2john`/`*2hashcat` tool, then crack:
- ZIP → `zip2john file.zip > h` (hashcat `-m 13600` for WinZip AES)
- 7z → `7z2hashcat file.7z > h` (`-m 11600`)
- PDF → `pdf2john file.pdf > h` (`-m 10500`/`10700` by version)
- Office → `office2john file.docx > h` (`-m 9400`+ by version)
- KeePass → `keepass2john file.kdbx > h` (`-m 13400`)
Then `hashcat -m <mode> h wordlist -r rules/best64.rule`.

## Step 3 — Run hygiene
- Long runs: launch in the background and poll, don't block. `--status --status-timer 10`.
- Start narrow (wordlist+rules), widen to masks only if it fails — don't open with a
  full `?a?a?a?a?a?a?a?a` sweep.
- Report the recovered secret and the exact command that found it (evidence).

## Ceiling
Detection targets NVIDIA + hashcat first. AMD/Intel/OpenCL-only rigs and hashcat
output-format drift are known gaps (`detect_gpu.note` will say when a GPU or
cracker is missing). The mode numbers above are a starting map, not exhaustive —
confirm with `hashcat --help`.
