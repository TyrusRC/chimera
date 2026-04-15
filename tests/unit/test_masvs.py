from chimera.vuln.masvs import masvs_for_rule, MASVS_CATEGORIES


class TestMASVS:
    def test_auth_maps_to_auth(self):
        result = masvs_for_rule("AUTH-001")
        assert result["category"] == "MASVS-AUTH"

    def test_data_maps_to_storage(self):
        result = masvs_for_rule("DATA-003")
        assert result["category"] == "MASVS-STORAGE"

    def test_net_maps_to_network(self):
        result = masvs_for_rule("NET-001")
        assert result["category"] == "MASVS-NETWORK"

    def test_crypto_maps_to_crypto(self):
        result = masvs_for_rule("CRYPTO-002")
        assert result["category"] == "MASVS-CRYPTO"

    def test_ipc_maps_to_platform(self):
        result = masvs_for_rule("IPC-001")
        assert result["category"] == "MASVS-PLATFORM"

    def test_web_maps_to_platform(self):
        result = masvs_for_rule("WEB-001")
        assert result["category"] == "MASVS-PLATFORM"

    def test_nat_maps_to_code(self):
        result = masvs_for_rule("NAT-002")
        assert result["category"] == "MASVS-CODE"

    def test_unknown_rule(self):
        result = masvs_for_rule("UNKNOWN-999")
        assert result["category"] == "MASVS-CODE"

    def test_has_mastg_test(self):
        result = masvs_for_rule("AUTH-001")
        assert result["mastg_test"] is not None
