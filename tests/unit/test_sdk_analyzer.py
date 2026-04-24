from chimera.sdk.analyzer import SDKAnalyzer
from chimera.sdk.signatures import SDK_SIGNATURES


class TestSDKSignatures:
    def test_has_common_sdks(self):
        names = [s["name"] for s in SDK_SIGNATURES]
        assert "Firebase" in names
        assert "OkHttp" in names
        assert "Retrofit" in names

    def test_signatures_have_required_fields(self):
        for sig in SDK_SIGNATURES:
            assert "name" in sig
            assert "package" in sig
            assert "category" in sig


class TestSDKAnalyzer:
    def test_detect_from_packages(self):
        analyzer = SDKAnalyzer()
        packages = [
            "com.google.firebase.analytics",
            "com.squareup.okhttp3",
            "com.squareup.retrofit2",
            "com.facebook.react",
            "io.sentry",
            "com.example.myapp",
        ]
        detected = analyzer.detect_from_packages(packages)
        names = [d["name"] for d in detected]
        assert "Firebase" in names
        assert "OkHttp" in names
        assert "Retrofit" in names

    def test_categorize(self):
        analyzer = SDKAnalyzer()
        packages = ["com.google.firebase.analytics", "com.adjust.sdk"]
        detected = analyzer.detect_from_packages(packages)
        categories = [d["category"] for d in detected]
        assert "analytics" in categories

    def test_no_false_positives_on_app_code(self):
        analyzer = SDKAnalyzer()
        packages = ["com.example.myapp", "com.mycompany.internal"]
        detected = analyzer.detect_from_packages(packages)
        assert len(detected) == 0


def test_sdk_analyzer_handles_large_package_list_fast():
    """Stress test — 10k packages, expect sub-second detection."""
    from chimera.sdk.analyzer import SDKAnalyzer
    analyzer = SDKAnalyzer()
    packages = [f"com.example.pkg{i}.module{j}" for i in range(200) for j in range(50)]
    packages.append("com.google.firebase.messaging.FirebaseMessagingService")
    packages.append("com.facebook.react.bridge.ReactContext")
    import time
    t0 = time.perf_counter()
    hits = analyzer.detect_from_packages(packages)
    elapsed = time.perf_counter() - t0
    assert elapsed < 0.5, f"detection too slow: {elapsed:.3f}s"
    names = {h["name"] for h in hits}
    # Firebase is matched via com.google.firebase prefix
    assert "Firebase" in names
    # com.facebook.react.* must match BOTH React Native AND Facebook SDK
    # (overlapping-prefix behavior that the indexed version must preserve)
    assert "React Native" in names
    assert "Facebook SDK" in names


def test_sdk_analyzer_overlapping_prefixes_all_match():
    """Regression guard for the overlapping-prefix behavior the index must preserve."""
    from chimera.sdk.analyzer import SDKAnalyzer
    hits = SDKAnalyzer().detect_from_packages([
        "com.google.firebase.crashlytics.CrashlyticsCore",
    ])
    names = {h["name"] for h in hits}
    # This single package should match BOTH Firebase (com.google.firebase prefix)
    # AND Crashlytics (com.google.firebase.crashlytics prefix).
    assert "Firebase" in names
    assert "Crashlytics" in names
