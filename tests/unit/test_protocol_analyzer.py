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
