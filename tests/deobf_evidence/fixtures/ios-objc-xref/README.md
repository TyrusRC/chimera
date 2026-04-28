# ios-objc-xref evidence fixture

The synthetic `sample.dylib` is a 2-class, 4-method ObjC dynamic library used to
verify the Mach-O ObjC parser end-to-end. Building requires macOS with Xcode CLI
tools (the iOS SDK is what ships ObjC's Foundation framework).

## Building

```bash
bash build_dylib.sh sample.dylib
```

The result is ~16KB and will be committed once built on a macOS host. Until
then, `test_objc_xref_parser_finds_known_classes` SKIPs cleanly. Regenerate
when the parser's expectations change (e.g., adding new struct fields).

## SHA pinning

`expected.json` currently uses `SKIP_SHA_CHECK` because the dylib will vary by
toolchain version. Once the fixture stabilizes, replace with the actual SHA:

```bash
sha256sum sample.dylib
```

and update `expected.json` `sample_sha256` accordingly.

## Why this is committed (deviation from SP5 pattern)

SP5 fixtures regenerate from `build.sh` on each test run. This fixture cannot —
no Linux toolchain produces ObjC binaries against Apple's Foundation. The
committed binary is the most reliable cross-platform answer; SHA-pinning detects
tampering, and the build script documents how to refresh.
