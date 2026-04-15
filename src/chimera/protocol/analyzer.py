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
    def detect_protocols(self, strings: list[str]) -> dict:
        combined = " ".join(strings)
        return {
            "has_rest": bool(re.search(r"https?://", combined)),
            "has_grpc": bool(re.search(r"grpc|application/grpc|\bprotobuf\b", combined, re.IGNORECASE)),
            "has_graphql": bool(re.search(r"/graphql|query\s*\{|mutation\s*\{", combined, re.IGNORECASE)),
            "has_websocket": bool(re.search(r"wss?://|Sec-WebSocket|WebSocket", combined)),
            "has_protobuf": bool(re.search(r"\.proto\b|protobuf|google\.protobuf", combined, re.IGNORECASE)),
        }

    def extract_endpoints(self, strings: list[str]) -> list[dict]:
        endpoints = []
        seen = set()
        for s in strings:
            urls = re.findall(r"(https?://[^\s'\"<>]+)", s)
            for url in urls:
                url = url.rstrip("/.,;:)")
                if url not in seen and len(url) > 15:
                    seen.add(url)
                    endpoints.append({
                        "url": url,
                        "protocol": "rest",
                    })

            ws_urls = re.findall(r"(wss?://[^\s'\"<>]+)", s)
            for url in ws_urls:
                url = url.rstrip("/.,;:)")
                if url not in seen:
                    seen.add(url)
                    endpoints.append({"url": url, "protocol": "websocket"})

        return endpoints
