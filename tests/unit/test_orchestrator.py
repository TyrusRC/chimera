from chimera.bypass.orchestrator import BypassOrchestrator
from chimera.bypass.detector import ProtectionProfile
from chimera.bypass.scripts import ScriptLoader


class TestScriptLoader:
    def test_loads_android_scripts(self):
        loader = ScriptLoader()
        scripts = loader.available_scripts("android")
        assert "root_bypass" in scripts
        assert "ssl_pinning" in scripts

    def test_loads_ios_scripts(self):
        loader = ScriptLoader()
        scripts = loader.available_scripts("ios")
        assert "jailbreak_bypass" in scripts
        assert "ssl_pinning" in scripts

    def test_get_script_source(self):
        loader = ScriptLoader()
        source = loader.get_script("android", "root_bypass")
        assert source is not None
        assert "Java.perform" in source


class TestBypassOrchestrator:
    def test_build_script_chain_android(self):
        profile = ProtectionProfile(
            has_anti_debug=True,
            has_anti_frida=True,
            has_root_detection=True,
            has_ssl_pinning=True,
        )
        orch = BypassOrchestrator()
        chain = orch.build_bypass_chain(profile, platform="android")
        names = [c["name"] for c in chain]
        assert "anti_debug" in names
        assert "root_bypass" in names
        assert "ssl_pinning" in names
        # Order check
        assert names.index("anti_debug") < names.index("root_bypass")
        assert names.index("root_bypass") < names.index("ssl_pinning")

    def test_build_script_chain_ios(self):
        profile = ProtectionProfile(
            has_jailbreak_detection=True,
            has_ssl_pinning=True,
        )
        orch = BypassOrchestrator()
        chain = orch.build_bypass_chain(profile, platform="ios")
        names = [c["name"] for c in chain]
        assert "jailbreak_bypass" in names
        assert "ssl_pinning" in names

    def test_no_protections_empty_chain(self):
        profile = ProtectionProfile()
        orch = BypassOrchestrator()
        chain = orch.build_bypass_chain(profile, platform="android")
        assert len(chain) == 0

    def test_combined_script(self):
        profile = ProtectionProfile(has_root_detection=True, has_ssl_pinning=True)
        orch = BypassOrchestrator()
        combined = orch.get_combined_script(profile, platform="android")
        assert "Java.perform" in combined
