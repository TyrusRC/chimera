import pytest
from pathlib import Path
from chimera.protocol.analyzer import ProtocolAnalyzer
from chimera.protocol.firebase import FirebaseAnalyzer


class TestProtocolAnalyzer:
    def test_detect_grpc_from_strings(self):
        analyzer = ProtocolAnalyzer()
        strings = [
            "grpc.service.Method",
            "application/grpc",
            "content-type: application/grpc+proto",
        ]
        result = analyzer.detect_protocols(strings)
        assert result["has_grpc"] is True

    def test_detect_graphql_from_strings(self):
        analyzer = ProtocolAnalyzer()
        strings = ["query { user { id name } }", "/graphql"]
        result = analyzer.detect_protocols(strings)
        assert result["has_graphql"] is True

    def test_detect_websocket(self):
        analyzer = ProtocolAnalyzer()
        strings = ["wss://api.example.com/ws", "Sec-WebSocket-Key"]
        result = analyzer.detect_protocols(strings)
        assert result["has_websocket"] is True

    def test_extract_endpoints(self):
        analyzer = ProtocolAnalyzer()
        strings = [
            "https://api.example.com/v2/auth",
            "https://api.example.com/v2/users",
            "wss://ws.example.com/stream",
            "not a url",
        ]
        endpoints = analyzer.extract_endpoints(strings)
        assert len(endpoints) >= 2
        assert any("/auth" in e["url"] for e in endpoints)


class TestFirebaseAnalyzer:
    def test_extract_config_android(self, tmp_path):
        config = {
            "project_info": {"project_id": "test-project-123", "firebase_url": "https://test-project-123.firebaseio.com"},
            "client": [{"client_info": {"mobilesdk_app_id": "1:123:android:abc"}, "api_key": [{"current_key": "AIzaSyB-test-key"}]}]
        }
        import json
        (tmp_path / "google-services.json").write_text(json.dumps(config))
        analyzer = FirebaseAnalyzer()
        result = analyzer.extract_config(tmp_path, platform="android")
        assert result["project_id"] == "test-project-123"
        assert result["api_key"] is not None

    def test_no_config(self, tmp_path):
        analyzer = FirebaseAnalyzer()
        result = analyzer.extract_config(tmp_path, platform="android")
        assert result["project_id"] is None


def test_endpoint_extraction_rejects_junk_trailing_chars():
    from chimera.protocol.analyzer import ProtocolAnalyzer
    analyzer = ProtocolAnalyzer()
    endpoints = analyzer.extract_endpoints([
        "Contact us at https://example.com/api.",
        "See https://evil.com/path,https://evil2.com/",
    ])
    urls = [e["url"] for e in endpoints]
    # Trailing period must not be part of any URL
    assert not any(u.endswith(".") for u in urls), urls
    # Comma-concatenated URLs must NOT be stored as a single URL
    assert not any("," in u for u in urls), urls
    # But a valid URL from the first string should still be captured
    assert any(u.startswith("https://example.com") for u in urls), urls


def test_grpc_requires_evidence_not_just_string_match():
    from chimera.protocol.analyzer import ProtocolAnalyzer
    analyzer = ProtocolAnalyzer()
    # Weak match: "grpc" appears in log messages only
    weak = analyzer.detect_protocols(["# grpc is cool", "log: grpc not used"])
    assert weak["has_grpc"] is False, weak

    # Strong match: MIME type or package path
    strong = analyzer.detect_protocols([
        "application/grpc",
        "io.grpc.stub.ClientCalls",
    ])
    assert strong["has_grpc"] is True, strong
