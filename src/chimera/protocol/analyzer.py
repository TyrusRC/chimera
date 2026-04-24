"""Protocol analyzer — detect and extract API protocols from app binaries."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Endpoint:
    url: str
    protocol: str   # rest, grpc, graphql, websocket
    method: str | None = None


class ProtocolAnalyzer:
    _GRPC_EVIDENCE = (
        "application/grpc",
        "io.grpc.",
        "grpc.proto",
    )

    def detect_protocols(self, strings: list[str]) -> dict:
        combined = " ".join(strings)
        has_grpc = any(ev in combined for ev in self._GRPC_EVIDENCE)
        return {
            "has_rest": bool(re.search(r"https?://", combined)),
            "has_grpc": has_grpc,
            "has_graphql": bool(re.search(r"/graphql|query\s*\{|mutation\s*\{", combined, re.IGNORECASE)),
            "has_websocket": bool(re.search(r"wss?://|Sec-WebSocket|WebSocket", combined)),
            "has_protobuf": bool(re.search(r"\.proto\b|protobuf|google\.protobuf", combined, re.IGNORECASE)),
        }

    def extract_endpoints(self, strings: list[str]) -> list[dict]:
        from urllib.parse import urlparse
        endpoints = []
        seen = set()
        for s in strings:
            for url in re.findall(r"(https?://[^\s'\"<>]+)", s):
                cleaned = url.rstrip("/.,;:)")
                if "," in cleaned:  # guards against concatenated URLs
                    continue
                try:
                    parsed = urlparse(cleaned)
                except ValueError:
                    continue
                if parsed.scheme not in ("http", "https") or not parsed.netloc:
                    continue
                if cleaned not in seen and len(cleaned) > 15:
                    seen.add(cleaned)
                    endpoints.append({"url": cleaned, "protocol": "rest"})

            for url in re.findall(r"(wss?://[^\s'\"<>]+)", s):
                cleaned = url.rstrip("/.,;:)")
                if "," in cleaned:
                    continue
                try:
                    parsed = urlparse(cleaned)
                except ValueError:
                    continue
                if parsed.scheme not in ("ws", "wss") or not parsed.netloc:
                    continue
                if cleaned not in seen:
                    seen.add(cleaned)
                    endpoints.append({"url": cleaned, "protocol": "websocket"})

        return endpoints
