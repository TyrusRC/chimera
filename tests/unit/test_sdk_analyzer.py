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
