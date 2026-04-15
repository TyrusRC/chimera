import json
from chimera.vuln.finding import Finding, Severity, Confidence
from chimera.report.sarif import generate_sarif


class TestSARIF:
    def test_generates_valid_sarif(self):
        findings = [
            Finding(
                rule_id="AUTH-001", severity=Severity.CRITICAL,
                title="Hardcoded JWT secret",
                description="Found JWT secret in BuildConfig",
                location="com/example/BuildConfig.java:15",
                evidence_static='JWT_SECRET = "my-secret"',
                masvs_category="MASVS-AUTH",
                mastg_test="MSTG-STORAGE-14",
            ),
            Finding(
                rule_id="CRYPTO-001", severity=Severity.HIGH,
                title="AES-ECB mode",
                description="ECB mode leaks patterns",
                location="com/example/Crypto.java:30",
                masvs_category="MASVS-CRYPTO",
            ),
        ]
        sarif = generate_sarif(findings, tool_name="chimera", tool_version="0.1.0")
        data = json.loads(sarif)

        assert data["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "chimera"
        assert len(run["results"]) == 2
        assert run["results"][0]["level"] == "error"  # critical → error
        assert run["results"][0]["ruleId"] == "AUTH-001"

    def test_empty_findings(self):
        sarif = generate_sarif([], tool_name="chimera", tool_version="0.1.0")
        data = json.loads(sarif)
        assert len(data["runs"][0]["results"]) == 0
