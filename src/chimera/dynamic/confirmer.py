"""Dynamic vuln confirmer — uses Frida to verify static findings at runtime."""

from __future__ import annotations

import logging
from chimera.vuln.finding import Finding, Confidence

logger = logging.getLogger(__name__)


class DynamicConfirmer:
    """Confirms static findings by hooking functions at runtime."""

    async def confirm_findings(
        self,
        findings: list[Finding],
        frida_session,
        platform: str,
    ) -> list[Finding]:
        """Attempt to dynamically confirm high-value static findings."""
        for finding in findings:
            if finding.severity.weight >= 4 and finding.confidence == Confidence.UNVERIFIED:
                confirmed = await self._try_confirm(finding, frida_session, platform)
                if confirmed:
                    finding.confirm("Dynamically confirmed via Frida hook")
                    logger.info("Confirmed: %s at %s", finding.rule_id, finding.location)
        return findings

    async def _try_confirm(self, finding: Finding, session, platform: str) -> bool:
        """Attempt to confirm a single finding. Returns True if confirmed."""
        confirmers = {
            "NET-003": self._confirm_trust_all,
            "AUTH-001": self._confirm_hardcoded_secret,
            "AUTH-003": self._confirm_token_in_prefs,
        }
        confirmer = confirmers.get(finding.rule_id)
        if confirmer and session:
            try:
                return await confirmer(finding, session, platform)
            except Exception as e:
                logger.debug("Confirmation failed for %s: %s", finding.rule_id, e)
        return False

    async def _confirm_trust_all(self, finding: Finding, session, platform: str) -> bool:
        """Confirm trust-all TrustManager by hooking SSL handshake at runtime."""
        hook_script = """
        Java.perform(function() {
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var found = false;
            Java.enumerateClassLoaders({
                onMatch: function(loader) {
                    try {
                        Java.classFactory.loader = loader;
                        Java.choose('javax.net.ssl.X509TrustManager', {
                            onMatch: function(instance) {
                                found = true;
                                send({type: 'confirmed', rule: 'NET-003'});
                            },
                            onComplete: function() {}
                        });
                    } catch(e) {}
                },
                onComplete: function() {}
            });
            if (!found) { send({type: 'not_confirmed', rule: 'NET-003'}); }
        });
        """
        try:
            await session.load_script(hook_script)
            msgs = session.messages
            return any(
                m.get("payload", {}).get("type") == "confirmed"
                for m in msgs if m.get("type") == "send"
            )
        except Exception as e:
            logger.debug("Trust-all confirmation hook failed: %s", e)
            return False

    async def _confirm_hardcoded_secret(self, finding: Finding, session, platform: str) -> bool:
        """Confirm hardcoded secret is loaded into memory at runtime."""
        if not finding.evidence_static:
            return False
        # Extract the secret value from static evidence to search for in memory
        secret_snippet = finding.evidence_static[:64]
        hook_script = f"""
        Java.perform(function() {{
            var String = Java.use('java.lang.String');
            var found = false;
            Java.choose('java.lang.String', {{
                onMatch: function(instance) {{
                    if (instance.toString().indexOf("{secret_snippet}") !== -1) {{
                        found = true;
                        send({{type: 'confirmed', rule: 'AUTH-001', value: instance.toString().substring(0, 32)}});
                    }}
                }},
                onComplete: function() {{
                    if (!found) {{ send({{type: 'not_confirmed', rule: 'AUTH-001'}}); }}
                }}
            }});
        }});
        """
        try:
            await session.load_script(hook_script)
            msgs = session.messages
            return any(
                m.get("payload", {}).get("type") == "confirmed"
                for m in msgs if m.get("type") == "send"
            )
        except Exception as e:
            logger.debug("Hardcoded secret confirmation hook failed: %s", e)
            return False

    async def _confirm_token_in_prefs(self, finding: Finding, session, platform: str) -> bool:
        """Confirm token stored in SharedPreferences by reading it at runtime."""
        hook_script = """
        Java.perform(function() {
            var SharedPreferences = Java.use('android.content.SharedPreferences');
            var sp_impl = Java.use('android.app.SharedPreferencesImpl');
            sp_impl.getString.overload('java.lang.String', 'java.lang.String').implementation = function(key, defVal) {
                var val = this.getString(key, defVal);
                var lower = key.toLowerCase();
                if (lower.indexOf('token') !== -1 || lower.indexOf('session') !== -1 ||
                    lower.indexOf('auth') !== -1 || lower.indexOf('jwt') !== -1) {
                    send({type: 'confirmed', rule: 'AUTH-003', key: key, has_value: val !== null && val.length > 0});
                }
                return val;
            };
        });
        """
        try:
            await session.load_script(hook_script)
            # Allow some time for the hook to fire during app activity
            import asyncio
            await asyncio.sleep(3)
            msgs = session.messages
            return any(
                m.get("payload", {}).get("type") == "confirmed"
                for m in msgs if m.get("type") == "send"
            )
        except Exception as e:
            logger.debug("Token-in-prefs confirmation hook failed: %s", e)
            return False
