# e2e/material — real-binary slots for integration tests

`material/` (gitignored) holds bring-your-own-sample binaries for the
real-file integration tests under `tests/integration/`. Each slot has a
documented filename a researcher can drop in to activate the corresponding
test; without the file, the test SKIPs cleanly.

## Active slots

| Slot | Filename | Tests it activates |
|---|---|---|
| `material/swift-ios/` | `sample.ipa` | `test_swift_real_sample.py`, `test_objc_xref_real_sample.py` |
| `material/rn-android/` | `sample.apk` | `test_rn_android_real_sample.py` |
| `material/rn-ios/` | `sample.ipa` | `test_rn_ios_real_sample.py` |

Each slot may carry an optional `expected.json` next to its sample to
upgrade smoke assertions to tight ones (e.g., `min_names_demangled`,
`must_find_objc_selector`). See each slot's `README.md` for keys.

## Convention

- The `material/` directory is gitignored. The slot READMEs and
  `.gitkeep` files are force-added so the directory layout is checked in.
- Tests resolve the slot path from the repo root: `REPO_ROOT / "e2e" /
  "material" / "<slot>"`.
- Tests skip with a message that includes the expected sample path so
  it's obvious where to drop the file.
