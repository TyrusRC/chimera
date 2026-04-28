# iOS Swift sample slot

Drop a real Swift-built iOS IPA here as `sample.ipa` to enable
`tests/integration/test_swift_real_sample.py::test_swift_ios_real_pipeline`.

Optional `expected.json` next to `sample.ipa` adds tight assertions:

```json
{
  "min_names_demangled": 50,
  "must_find_demangled_substring": "AppDelegate.application"
}
```

Without `expected.json`, only smoke assertions run.

This directory and its contents are gitignored (`e2e/material/`).
