/*
 * Commercial packer / RASP fingerprint rules.
 *
 * String-level only — these aim at filenames, embedded class names,
 * and well-known runtime tags. Filename matching is layered on top by
 * the python adapter (see yara_scanner.py).
 */

rule Bangcle_Packer
{
    meta:
        packer = "Bangcle"
        kind = "commercial_packer"
    strings:
        $a = "libsecexe" ascii
        $b = "libsecmain" ascii
        $c = "com.SecShell.SecShell" ascii
    condition:
        any of them
}

rule Ijiami_Packer
{
    meta:
        packer = "Ijiami"
        kind = "commercial_packer"
    strings:
        $a = "libexec.so" ascii
        $b = "libexecmain.so" ascii
        $c = "com.shell.NativeApplication" ascii
    condition:
        any of them
}

rule Qihoo360_Packer
{
    meta:
        packer = "Qihoo360"
        kind = "commercial_packer"
    strings:
        $a = "libprotectClass.so" ascii
        $b = "com.qihoo.util.StubApp" ascii
    condition:
        any of them
}

rule TencentLegu_Packer
{
    meta:
        packer = "Tencent Legu"
        kind = "commercial_packer"
    strings:
        $a = "libshella" ascii
        $b = "libshellx" ascii
        $c = "com.tencent.StubShell" ascii
    condition:
        any of them
}

rule JiAGu_Packer
{
    meta:
        packer = "JiAGu"
        kind = "commercial_packer"
    strings:
        $a = "libjiagu.so" ascii
        $b = "libjiagu_64.so" ascii
        $c = "com.qihoo.util.StubApp" ascii
    condition:
        any of them
}

rule Promon_SHIELD
{
    meta:
        packer = "Promon SHIELD"
        kind = "commercial_packer"
    strings:
        $a = "Promon SHIELD" ascii wide
        $b = "libshield.so" ascii
        $c = "com.promon" ascii
    condition:
        any of them
}

rule Appdome_Wrapper
{
    meta:
        packer = "Appdome"
        kind = "commercial_packer"
    strings:
        $a = "libloader.appdome" ascii
        $b = "appdome" nocase ascii
        $c = "Appdome SDK" ascii wide
    condition:
        any of them
}

rule Verimatrix_XTD
{
    meta:
        packer = "Verimatrix"
        kind = "commercial_packer"
    strings:
        $a = "libencryption_" ascii
        $b = "verimatrix" nocase ascii
        $c = "VMX_" ascii
    condition:
        any of them
}

rule DexProtector_Native
{
    meta:
        packer = "DexProtector"
        kind = "commercial_packer"
    strings:
        $a = "DexProtector" ascii
        $b = "com.licel.dexprotector" ascii
        $c = "libdexprotector" ascii
    condition:
        any of them
}

rule Talsec_freeRASP
{
    meta:
        packer = "Talsec freeRASP"
        kind = "commercial_packer"
    strings:
        $a = "libtalsec" ascii
        $b = "com.aheaditec.talsec" ascii
        $c = "freeRASP" ascii
    condition:
        any of them
}
