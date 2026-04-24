"""Firebase config extraction and misconfiguration detection."""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class FirebaseAnalyzer:
    def extract_config(self, unpack_dir: Path, platform: str) -> dict:
        unpack_dir = Path(unpack_dir)
        result = {
            "project_id": None,
            "api_key": None,
            "database_url": None,
            "storage_bucket": None,
            "app_id": None,
            "errors": [],
        }

        if platform == "android":
            config_path = unpack_dir / "google-services.json"
            if not config_path.exists():
                # Try in assets or res
                for candidate in unpack_dir.rglob("google-services.json"):
                    config_path = candidate
                    break
            if config_path.exists():
                try:
                    config = json.loads(config_path.read_text())
                    result["project_id"] = config.get("project_info", {}).get("project_id")
                    result["database_url"] = config.get("project_info", {}).get("firebase_url")
                    result["storage_bucket"] = config.get("project_info", {}).get("storage_bucket")
                    clients = config.get("client", [])
                    if clients:
                        result["app_id"] = clients[0].get("client_info", {}).get("mobilesdk_app_id")
                        api_keys = clients[0].get("api_key", [])
                        if api_keys:
                            result["api_key"] = api_keys[0].get("current_key")
                except (json.JSONDecodeError, KeyError) as e:
                    msg = f"Failed to parse google-services.json: {e}"
                    logger.warning(msg)
                    result["errors"].append(msg)

        elif platform == "ios":
            for plist_path in unpack_dir.rglob("GoogleService-Info.plist"):
                try:
                    import plistlib
                    config = plistlib.loads(plist_path.read_bytes())
                    result["project_id"] = config.get("PROJECT_ID")
                    result["api_key"] = config.get("API_KEY")
                    result["database_url"] = config.get("DATABASE_URL")
                    result["storage_bucket"] = config.get("STORAGE_BUCKET")
                    result["app_id"] = config.get("GOOGLE_APP_ID")
                except (ValueError, KeyError, OSError) as e:
                    msg = f"Failed to parse GoogleService-Info.plist: {e}"
                    logger.warning(msg)
                    result["errors"].append(msg)
                break

        return result

    def check_misconfigurations(
        self, config: dict, rules_text: str | None = None,
    ) -> list[dict]:
        """Flag Firebase findings. Severity defaults to "info" on mere presence;
        upgrades to "high" when rules_text contains evidence of public access."""
        findings: list[dict] = []
        severity = self._severity_from_rules(rules_text)

        db_url = config.get("database_url")
        if db_url:
            findings.append({
                "rule_id": "DATA-001",
                "title": "Firebase Realtime Database URL exposed",
                "severity": severity,
                "description": f"Firebase database URL found: {db_url}. Check if rules allow public read/write.",
                "location": "google-services.json / GoogleService-Info.plist",
            })

        bucket = config.get("storage_bucket")
        if bucket:
            findings.append({
                "rule_id": "DATA-001",
                "title": "Firebase Storage bucket exposed",
                "severity": severity,
                "description": f"Storage bucket: {bucket}. Check if bucket rules allow public access.",
                "location": "google-services.json / GoogleService-Info.plist",
            })

        return findings

    @staticmethod
    def _severity_from_rules(rules_text: str | None) -> str:
        """Return 'high' if rules_text shows evidence of public access, else 'info'."""
        if rules_text is None:
            return "info"
        # Case-insensitive substring match on the key rules-gone-wrong indicators.
        lower = rules_text.lower()
        if '".read": true' in lower or '".write": true' in lower:
            return "high"
        return "info"
