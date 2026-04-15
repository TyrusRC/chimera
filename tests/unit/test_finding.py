import pytest
from chimera.vuln.finding import Finding, Severity, Confidence, Status


class TestSeverity:
    def test_ordering(self):
        assert Severity.CRITICAL.weight > Severity.HIGH.weight
        assert Severity.HIGH.weight > Severity.MEDIUM.weight
        assert Severity.MEDIUM.weight > Severity.LOW.weight

    def test_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"


class TestFinding:
    def test_create(self):
        f = Finding(
            rule_id="AUTH-001",
            severity=Severity.CRITICAL,
            title="Hardcoded JWT secret",
            description="JWT signing key found in BuildConfig",
            location="com/example/BuildConfig.java:15",
        )
        assert f.rule_id == "AUTH-001"
        assert f.severity == Severity.CRITICAL
        assert f.confidence == Confidence.UNVERIFIED
        assert f.status == Status.OPEN

    def test_confirm(self):
        f = Finding(
            rule_id="NET-003", severity=Severity.HIGH,
            title="Trust-all TrustManager",
            description="Custom TrustManager accepts all certificates",
            location="com/example/ssl/UnsafeTrustManager.java:22",
        )
        f.confirm("Frida: MITM succeeded without cert pinning bypass")
        assert f.confidence == Confidence.CONFIRMED
        assert f.evidence_dynamic == "Frida: MITM succeeded without cert pinning bypass"

    def test_mark_false_positive(self):
        f = Finding(
            rule_id="DATA-004", severity=Severity.MEDIUM,
            title="Logging sensitive data",
            description="Log.d with auth token",
            location="com/example/AuthManager.java:45",
        )
        f.mark_false_positive("Only logs in debug builds, stripped in release")
        assert f.status == Status.FALSE_POSITIVE

    def test_to_dict(self):
        f = Finding(
            rule_id="CRYPTO-001", severity=Severity.HIGH,
            title="AES-ECB mode", description="Using ECB for sensitive data",
            location="com/example/Crypto.java:30",
            evidence_static="Cipher.getInstance(\"AES/ECB/PKCS5Padding\")",
        )
        d = f.to_dict()
        assert d["rule_id"] == "CRYPTO-001"
        assert d["severity"] == "high"
        assert d["evidence_static"] is not None
