/*
 * Windows PE packer / protector fingerprint rules.
 *
 * String-level + section-name patterns. Detection is best-effort:
 * polymorphic packers (e.g., later VMProtect generations) defeat
 * string matching, so the analyst should pair this with entropy
 * analysis from pe_header parser.
 */

rule UPX_PE
{
    meta:
        packer = "UPX"
        kind = "commercial_packer"
    strings:
        $upx = "UPX!" ascii
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx_dll = "UPX (https://upx.github.io)" ascii
    condition:
        2 of them
}

rule ASPack_PE
{
    meta:
        packer = "ASPack"
        kind = "commercial_packer"
    strings:
        $sec = ".aspack" ascii
        $adata = ".adata" ascii
        $ver = "ASPack" ascii
    condition:
        any of them
}

rule VMProtect_PE
{
    meta:
        packer = "VMProtect"
        kind = "commercial_packer"
    strings:
        $sec0 = ".vmp0" ascii
        $sec1 = ".vmp1" ascii
        $sec2 = ".vmp2" ascii
        $tag = "VMProtect" ascii wide
    condition:
        any of them
}

rule Themida_WinLicense_PE
{
    meta:
        packer = "Themida/WinLicense"
        kind = "commercial_packer"
    strings:
        $a = "Themida" ascii wide
        $b = "WinLicense" ascii wide
        $c = ".themida" ascii
        $d = ".winlice" ascii
    condition:
        any of them
}

rule MPRESS_PE
{
    meta:
        packer = "MPRESS"
        kind = "commercial_packer"
    strings:
        $sec1 = ".MPRESS1" ascii
        $sec2 = ".MPRESS2" ascii
    condition:
        any of them
}

rule PECompact_PE
{
    meta:
        packer = "PECompact"
        kind = "commercial_packer"
    strings:
        $a = "PECompact" ascii
        $b = "PEC2" ascii
    condition:
        any of them
}

rule Enigma_Protector_PE
{
    meta:
        packer = "Enigma Protector"
        kind = "commercial_packer"
    strings:
        $a = ".enigma1" ascii
        $b = ".enigma2" ascii
        $c = "Enigma Protector" ascii wide
    condition:
        any of them
}

rule NSIS_Wrapper_PE
{
    meta:
        packer = "NSIS"
        kind = "installer_wrapper"
    strings:
        $a = "Nullsoft.NSIS.exehead" ascii
        $b = "NullsoftInst" ascii
    condition:
        any of them
}
