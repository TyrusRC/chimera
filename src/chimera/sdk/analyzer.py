"""SDK fingerprinting — identify third-party libraries in apps."""

from __future__ import annotations

from chimera.sdk.signatures import SDK_SIGNATURES


class SDKAnalyzer:
    def __init__(self):
        self._signatures = SDK_SIGNATURES

    def detect_from_packages(self, packages: list[str]) -> list[dict]:
        detected = []
        seen = set()
        for pkg in packages:
            for sig in self._signatures:
                if pkg.startswith(sig["package"]) and sig["name"] not in seen:
                    seen.add(sig["name"])
                    detected.append({
                        "name": sig["name"],
                        "package": sig["package"],
                        "category": sig["category"],
                        "risk": sig["risk"],
                        "matched_package": pkg,
                    })
        return detected

    def detect_from_classes(self, class_names: list[str]) -> list[dict]:
        """Detect SDKs from ObjC/Swift class names (iOS)."""
        detected = []
        ios_signatures = {
            "FB": {"name": "Facebook SDK", "category": "social"},
            "AF": {"name": "AppsFlyer", "category": "analytics"},
            "GA": {"name": "Google Analytics", "category": "analytics"},
            "FIR": {"name": "Firebase", "category": "analytics"},
            "Adjust": {"name": "Adjust", "category": "analytics"},
            "Sentry": {"name": "Sentry", "category": "crash_reporting"},
            "Stripe": {"name": "Stripe", "category": "payment"},
            "Braintree": {"name": "Braintree", "category": "payment"},
        }
        seen = set()
        for cls in class_names:
            for prefix, info in ios_signatures.items():
                if cls.startswith(prefix) and info["name"] not in seen:
                    seen.add(info["name"])
                    detected.append({
                        "name": info["name"],
                        "category": info["category"],
                        "risk": "clean",
                        "matched_class": cls,
                    })
        return detected

    def summarize(self, detected: list[dict]) -> dict:
        categories = {}
        for sdk in detected:
            cat = sdk["category"]
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(sdk["name"])
        return {
            "total": len(detected),
            "categories": categories,
            "suspicious": [s for s in detected if s.get("risk") == "suspicious"],
        }
