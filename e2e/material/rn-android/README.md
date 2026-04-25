# RN Android sample slot

Drop a real React Native APK here as `sample.apk` to enable
`tests/integration/test_rn_real_samples.py::test_rn_android_real_pipeline`.

Optional `expected.json` next to `sample.apk` adds tight assertions:

```json
{
  "variant": "hermes",
  "must_find_module": "src/screens/Login",
  "min_module_ids": 50,
  "min_strings": 100
}
```

Without `expected.json`, only smoke assertions run.

This directory and its contents are gitignored (`e2e/material/`).
