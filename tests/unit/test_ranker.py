from chimera.vuln.finding import Finding, Severity
from chimera.vuln.ranker import rank_findings


class TestRanker:
    def test_ranks_by_severity(self):
        findings = [
            Finding(rule_id="LOW-1", severity=Severity.LOW, title="low", description="", location="a"),
            Finding(rule_id="CRIT-1", severity=Severity.CRITICAL, title="crit", description="", location="b"),
            Finding(rule_id="HIGH-1", severity=Severity.HIGH, title="high", description="", location="c"),
        ]
        ranked = rank_findings(findings)
        assert ranked[0].severity == Severity.CRITICAL
        assert ranked[1].severity == Severity.HIGH
        assert ranked[2].severity == Severity.LOW

    def test_deduplicates(self):
        findings = [
            Finding(rule_id="AUTH-001", severity=Severity.CRITICAL, title="dup", description="same", location="a.java:10"),
            Finding(rule_id="AUTH-001", severity=Severity.CRITICAL, title="dup", description="same", location="a.java:10"),
        ]
        ranked = rank_findings(findings)
        assert len(ranked) == 1
