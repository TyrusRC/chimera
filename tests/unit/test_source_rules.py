import pytest
from pathlib import Path
from chimera.vuln.rules.base import ScanContext
from chimera.vuln.rules.auth import AuthRules
from chimera.vuln.rules.data import DataRules
from chimera.vuln.rules.network import NetworkRules
from chimera.vuln.rules.crypto import CryptoRules
from chimera.vuln.rules.webview import WebViewRules


@pytest.fixture
def java_sources(tmp_path):
    """Create fake decompiled Java sources with known vulnerabilities."""
    src = tmp_path / "sources"
    src.mkdir()

    # Auth issues
    (src / "com" / "example").mkdir(parents=True)
    (src / "com" / "example" / "Config.java").write_text(
        'public class Config {\n'
        '    public static final String API_KEY = "sk-live-abc123def456";\n'
        '    public static final String JWT_SECRET = "my-super-secret-jwt-key";\n'
        '    public static final String MAPS_KEY = "AIzaSyB-test-maps-key";\n'
        '}\n'
    )

    # Data logging
    (src / "com" / "example" / "AuthManager.java").write_text(
        'public class AuthManager {\n'
        '    public void login(String token) {\n'
        '        Log.d("AUTH", "Token: " + token);\n'
        '        SharedPreferences.Editor editor = prefs.edit();\n'
        '        editor.putString("auth_token", token);\n'
        '        editor.apply();\n'
        '    }\n'
        '}\n'
    )

    # Network
    (src / "com" / "example" / "UnsafeTrust.java").write_text(
        'public class UnsafeTrust implements X509TrustManager {\n'
        '    public void checkServerTrusted(X509Certificate[] chain, String auth) {\n'
        '        // trust all\n'
        '    }\n'
        '}\n'
    )

    # Crypto
    (src / "com" / "example" / "CryptoHelper.java").write_text(
        'public class CryptoHelper {\n'
        '    public byte[] encrypt(byte[] data) {\n'
        '        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");\n'
        '        Random random = new java.util.Random();\n'
        '        MessageDigest md = MessageDigest.getInstance("MD5");\n'
        '        return cipher.doFinal(data);\n'
        '    }\n'
        '}\n'
    )

    # WebView
    (src / "com" / "example" / "WebActivity.java").write_text(
        'public class WebActivity {\n'
        '    public void setup(WebView wv) {\n'
        '        wv.getSettings().setJavaScriptEnabled(true);\n'
        '        wv.addJavascriptInterface(new Bridge(), "android");\n'
        '        wv.getSettings().setAllowFileAccess(true);\n'
        '        wv.getSettings().setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);\n'
        '    }\n'
        '}\n'
    )
    return src


@pytest.fixture
def context(java_sources):
    return ScanContext(platform="android", jadx_sources_dir=java_sources)


class TestAuthRules:
    async def test_detects_hardcoded_secrets(self, context):
        findings = await AuthRules().scan(context)
        auth_001 = [f for f in findings if f.rule_id == "AUTH-001"]
        assert len(auth_001) >= 1
        # Should find JWT_SECRET and API_KEY but NOT MAPS_KEY (excluded)
        descriptions = " ".join(f.description for f in auth_001)
        assert "jwt" in descriptions.lower() or "sk-live" in descriptions.lower()

    async def test_detects_token_in_prefs(self, context):
        findings = await AuthRules().scan(context)
        auth_003 = [f for f in findings if f.rule_id == "AUTH-003"]
        assert len(auth_003) >= 1


class TestDataRules:
    async def test_detects_sensitive_logging(self, context):
        findings = await DataRules().scan(context)
        data_004 = [f for f in findings if f.rule_id == "DATA-004"]
        assert len(data_004) >= 1


class TestNetworkRules:
    async def test_detects_trust_all(self, context):
        findings = await NetworkRules().scan(context)
        net_003 = [f for f in findings if f.rule_id == "NET-003"]
        assert len(net_003) >= 1


class TestCryptoRules:
    async def test_detects_ecb_mode(self, context):
        findings = await CryptoRules().scan(context)
        crypto_001 = [f for f in findings if f.rule_id == "CRYPTO-001"]
        assert len(crypto_001) >= 1

    async def test_detects_weak_prng(self, context):
        findings = await CryptoRules().scan(context)
        crypto_003 = [f for f in findings if f.rule_id == "CRYPTO-003"]
        assert len(crypto_003) >= 1

    async def test_detects_md5(self, context):
        findings = await CryptoRules().scan(context)
        crypto_004 = [f for f in findings if f.rule_id == "CRYPTO-004"]
        assert len(crypto_004) >= 1


class TestWebViewRules:
    async def test_detects_js_interface(self, context):
        findings = await WebViewRules().scan(context)
        web_001 = [f for f in findings if f.rule_id == "WEB-001"]
        assert len(web_001) >= 1

    async def test_detects_file_access(self, context):
        findings = await WebViewRules().scan(context)
        web_003 = [f for f in findings if f.rule_id == "WEB-003"]
        assert len(web_003) >= 1
