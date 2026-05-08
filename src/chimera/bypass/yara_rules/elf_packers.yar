/*
 * ELF packer fingerprint rules. UPX is by far the most common on
 * Linux malware; everything else is a long tail.
 */

rule UPX_ELF
{
    meta:
        packer = "UPX"
        kind = "commercial_packer"
    strings:
        $upx_magic = "UPX!" ascii
        $upx_sec0 = ".UPX" ascii
        $upx_link = "UPX-Link" ascii
        $upx_url = "https://upx.github.io" ascii
    condition:
        any of them
}

rule kkrunchy_ELF
{
    meta:
        packer = "kkrunchy"
        kind = "commercial_packer"
    strings:
        $a = "kkrunchy" ascii
    condition:
        any of them
}

rule MEW_ELF
{
    meta:
        packer = "MEW"
        kind = "commercial_packer"
    strings:
        $a = "MEW" ascii
        $b = "PoCypt" ascii
    condition:
        all of them
}
