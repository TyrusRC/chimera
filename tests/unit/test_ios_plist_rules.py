import pytest
import plistlib
from chimera.vuln.rules.ios_plist import IosPlistRules
from chimera.vuln.rules.base import ScanContext


@pytest.fixture
def plist_data():
    return {
        "CFBundleIdentifier": "com.example.testapp",
        "CFBundleName": "TestApp",
        "MinimumOSVersion": "15.0",
        "CFBundleURLTypes": [
            {"CFBundleURLSchemes": ["testapp", "fb123456"]}
        ],
        "NSAppTransportSecurity": {
            "NSAllowsArbitraryLoads": True,
            "NSExceptionDomains": {
                "insecure.example.com": {
                    "NSExceptionAllowsInsecureHTTPLoads": True,
                }
            },
        },
        "LSApplicationQueriesSchemes": ["whatsapp"],
    }


@pytest.fixture
def context(plist_data):
    return ScanContext(
        platform="ios",
        manifest_xml=plistlib.dumps(plist_data).decode("utf-8", errors="replace"),
    )


class TestIosPlistRules:
    async def test_detects_ats_disabled(self, plist_data):
        rules = IosPlistRules()
        ctx = ScanContext(platform="ios")
        ctx.ios_plist = plist_data
        findings = await rules.scan(ctx)
        net = [f for f in findings if f.rule_id == "NET-002"]
        assert len(net) >= 1
        assert any("ArbitraryLoads" in f.description for f in net)

    async def test_detects_url_schemes(self, plist_data):
        rules = IosPlistRules()
        ctx = ScanContext(platform="ios")
        ctx.ios_plist = plist_data
        findings = await rules.scan(ctx)
        url = [f for f in findings if f.rule_id == "URL-001"]
        assert len(url) >= 1
        assert any("testapp" in f.description for f in url)

    async def test_detects_get_task_allow(self):
        rules = IosPlistRules()
        ctx = ScanContext(platform="ios")
        ctx.ios_plist = {}
        ctx.ios_entitlements = {"get-task-allow": True}
        findings = await rules.scan(ctx)
        debug = [f for f in findings if "get-task-allow" in f.title.lower() or "debuggable" in f.title.lower()]
        assert len(debug) >= 1

    async def test_skips_android(self):
        rules = IosPlistRules()
        ctx = ScanContext(platform="android")
        findings = await rules.scan(ctx)
        assert len(findings) == 0
