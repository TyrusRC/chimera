---
name: mobile-re
description: Use when the target is a mobile app — an Android APK/AAB/XAPK/dex or an iOS IPA/Mach-O — and the goal is to understand it, find its API/secrets, or bypass its client-side defenses (SSL pinning, root/jailbreak detection). Sets the fingerprint→decompile→manifest→bypass→API flow over chimera's mobile tools (analyze/manifest/frida/proxy/Flutter/Hermes), Android and iOS.
---

# Mobile reverse engineering (Android + iOS)

Mobile apps are mostly client + API, so the payoff is usually the network layer:
endpoints, auth/signing, embedded secrets — reached by defeating client-side
defenses, not by reading every class. Fingerprint first; the framework decides
everything downstream.

## 1. Fingerprint before decompiling (cheap, decisive)
`analyze(path)` then `detect_framework` / `detect_sdks` / `detect_protections`.
The framework picks the toolchain — do NOT read Dart AOT or Hermes bytecode as
Java/native:
- **Native Android (Java/Kotlin)** → dex/jadx decompile (via `analyze`),
  `get_manifest` + `get_manifest_findings`, `list_source_files`/`read_source`.
- **Flutter** → `chimera flutter-extract` (static B(l)utter: Dart classes/methods)
  and, for traffic, `chimera flutter-patch` (reFlutter — Flutter ignores the
  system proxy + bundles its own CA, so this repackage is how you MITM it).
- **React Native** → `analyze` runs `hermes-decompile` (Hermes bytecode) or
  webcrack (plain-JSC bundle) + source-map recovery automatically.
- **Xamarin/Unity/Cordova** → `detect_framework` flags it; pull the managed
  DLLs / IL2CPP / web assets accordingly.
- **iOS** → IPA/Mach-O `analyze`; `get_class_headers` (ObjC/Swift class-dump)
  and `objc_xref` for the method graph; `detect_protocols` for the network stack.

## 2. Manifest / entitlements triage
`get_manifest_findings` surfaces exported components, debuggable/backup flags,
`usesCleartextTraffic`, weak `network_security_config`, custom URL schemes,
deep links — the client-side attack surface. On iOS, read entitlements + Info.plist
(ATS exceptions, URL schemes, keychain groups).

## 3. Deobfuscation that matters
- **R8/ProGuard**: `a.b.c` names aren't a dead end — Kotlin `@Metadata`/
  `@DebugMetadata` survive R8 and carry the ORIGINAL fully-qualified names
  (near-100% recovery on `*Repository`/`*ViewModel`/`*UseCase`); rebuild the
  obfuscated→real map, then read.
- Fingerprint the HTTP stack (Retrofit/OkHttp/Ktor/Apollo) + DI (Hilt/Koin) and
  trace **UI → ViewModel → repository → network** rather than grepping endpoints.
- String/asset obfuscation → the `python-bytecode`/`re-workflow` static-decrypt
  guidance; native `.so` logic → `get_disassembly`/`decompile`/`emulate_function`.

## 4. Defeat client defenses (dynamic, on a device/emulator)
`connect_device` (adb over TCP to a networked/rooted device or emulator) →
`list_packages` → `pull_app`. Then:
- **SSL pinning / root / jailbreak / debugger checks**: `get_bypass_scripts` +
  `get_dynamic_hooks` give ready Frida hooks; `start_frida_server` +
  `frida_spawn`/`frida_attach` + `frida_load_script` to inject, `frida_messages`
  to read results. Flutter pinning is the exception — use `flutter-patch`, not a
  Java/native hook.
- **Traffic**: `setup_proxy` (device → Burp/mitmproxy), `clear_proxy` after.
  `get_logcat` for runtime behaviour/crashes.
Run untrusted apps confined — see the `sandbox` skill; device work needs a real
device/emulator you control.

## 5. The deliverable
Endpoints + auth/signing scheme + embedded secrets + which client defenses were
bypassed and how. Persist with `add_note` / `set_classification` so it survives
compaction. For a malware APK, hand off to the `malware-triage` skill.

## Anti-patterns
- Decompiling before fingerprinting (reading Dart/Hermes as Java wastes hours).
- Grepping for endpoints instead of tracing the call graph from the UI.
- Assuming Burp+user-CA MITM works on Flutter (it doesn't) or on an app with
  pinning (hook/patch first).
- Pulling the whole dex/source into context — offload breadth to `mobile-recon`.
