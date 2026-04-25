# RN iOS sample slot

Drop a real React Native IPA here as `sample.ipa` to enable
`tests/integration/test_rn_real_samples.py::test_rn_ios_real_pipeline`.

Optional `expected.json` next to `sample.ipa` adds tight assertions:

```json
{
  "variant": "hermes",
  "must_find_module": "src/App",
  "min_module_ids": 30,
  "min_strings": 50
}
```

Without `expected.json`, only smoke assertions run.

This directory and its contents are gitignored (`e2e/material/`).
