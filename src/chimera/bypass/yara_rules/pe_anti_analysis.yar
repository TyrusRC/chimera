/*
 * Windows PE anti-analysis rules.
 *
 * These rules surface evidence that a sample expects to evade analysis
 * — anti-debug API combos, anti-VM strings, sandbox-evasion (long sleeps,
 * timing checks). Each rule has `kind = "anti_analysis"` and a
 * `category` that the report can group on.
 */

rule Anti_Debug_API_Combo
{
    meta:
        kind = "anti_analysis"
        category = "anti_debug"
    strings:
        $a = "IsDebuggerPresent" ascii
        $b = "CheckRemoteDebuggerPresent" ascii
        $c = "NtQueryInformationProcess" ascii
        $d = "OutputDebugString" ascii
    condition:
        2 of them
}

rule Anti_VM_Strings
{
    meta:
        kind = "anti_analysis"
        category = "anti_vm"
    strings:
        $vbox1 = "VBoxGuest" ascii wide
        $vbox2 = "VBoxService" ascii wide
        $vbox3 = "VirtualBox" ascii wide
        $vmware1 = "VMware" ascii wide
        $vmware2 = "vmtoolsd" ascii wide
        $qemu = "QEMU" ascii wide
        $hv = "Hyper-V" ascii wide
        $xen = "XenSource" ascii wide
    condition:
        2 of them
}

rule Sandbox_Evasion_Sleep_Patch
{
    meta:
        kind = "anti_analysis"
        category = "sandbox_evasion"
    strings:
        $sleep = "Sleep" ascii fullword
        $tick = "GetTickCount" ascii
        $perf = "QueryPerformanceCounter" ascii
    condition:
        $sleep and ($tick or $perf)
}

rule Process_Hollowing_API_Combo
{
    meta:
        kind = "anti_analysis"
        category = "process_injection"
    strings:
        $a = "NtUnmapViewOfSection" ascii
        $b = "NtCreateSection" ascii
        $c = "NtMapViewOfSection" ascii
        $d = "ZwUnmapViewOfSection" ascii
    condition:
        2 of them
}

rule Tool_Detection_Strings
{
    meta:
        kind = "anti_analysis"
        category = "tool_detection"
    strings:
        $a = "ollydbg" ascii nocase
        $b = "x64dbg" ascii nocase
        $c = "windbg" ascii nocase
        $d = "ImmunityDebugger" ascii
        $e = "ProcessHacker" ascii
        $f = "wireshark" ascii nocase
    condition:
        any of them
}
