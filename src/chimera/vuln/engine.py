"""Vulnerability engine — orchestrates all rules against a scan context."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from chimera.vuln.finding import Finding
from chimera.vuln.ranker import rank_findings
from chimera.vuln.rules.base import ScanContext
from chimera.vuln.rules.manifest import ManifestAnalyzer
from chimera.vuln.rules.auth import AuthRules
from chimera.vuln.rules.data import DataRules
from chimera.vuln.rules.network import NetworkRules
from chimera.vuln.rules.crypto import CryptoRules
from chimera.vuln.rules.webview import WebViewRules
from chimera.vuln.rules.ios_plist import IosPlistRules


class VulnEngine:
    def __init__(self):
        self._rules = [
            ManifestAnalyzer(),
            AuthRules(),
            DataRules(),
            NetworkRules(),
            CryptoRules(),
            WebViewRules(),
            IosPlistRules(),
        ]

    async def scan(
        self,
        platform: str,
        manifest_xml: Optional[str] = None,
        jadx_sources_dir: Optional[Path] = None,
        native_libs: Optional[list[Path]] = None,
        strings: Optional[list[dict]] = None,
        unpack_dir: Optional[Path] = None,
        ios_plist: Optional[dict] = None,
        ios_entitlements: Optional[dict] = None,
    ) -> list[Finding]:
        context = ScanContext(
            platform=platform,
            manifest_xml=manifest_xml,
            jadx_sources_dir=jadx_sources_dir,
            native_libs=native_libs,
            strings=strings,
            unpack_dir=unpack_dir,
        )
        context.ios_plist = ios_plist or {}
        context.ios_entitlements = ios_entitlements or {}

        all_findings: list[Finding] = []
        for rule in self._rules:
            if platform in rule.platforms():
                findings = await rule.scan(context)
                all_findings.extend(findings)

        return rank_findings(all_findings)
