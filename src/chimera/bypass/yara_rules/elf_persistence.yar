/*
 * Linux ELF persistence-mechanism fingerprints.
 * Surfaces evidence that a binary plans to install itself — cron entries,
 * systemd units, LD_PRELOAD/ld.so.preload manipulation, common backdoor paths.
 */

rule Cron_Persistence_Strings
{
    meta:
        kind = "persistence"
        category = "cron"
    strings:
        $a = "/etc/cron.d/" ascii
        $b = "/etc/crontab" ascii
        $c = "/var/spool/cron/" ascii
        $d = "@reboot" ascii
    condition:
        any of them
}

rule Systemd_Persistence_Strings
{
    meta:
        kind = "persistence"
        category = "systemd"
    strings:
        $a = "/etc/systemd/system/" ascii
        $b = "/lib/systemd/system/" ascii
        $c = ".service" ascii
        $d = "[Service]" ascii
        $e = "ExecStart=" ascii
        $f = "WantedBy=" ascii
    condition:
        ($a or $b) and ($c or $d or $e or $f)
}

rule LD_PRELOAD_Persistence
{
    meta:
        kind = "persistence"
        category = "ld_preload"
    strings:
        $a = "LD_PRELOAD" ascii
        $b = "/etc/ld.so.preload" ascii
    condition:
        any of them
}

rule Backdoor_Common_Paths
{
    meta:
        kind = "persistence"
        category = "common_backdoor_paths"
    strings:
        $a = "/tmp/.X" ascii
        $b = "/dev/shm/" ascii
        $c = "/usr/sbin/cron.update" ascii
        $d = "/etc/init.d/" ascii
        $e = ".bashrc" ascii
        $f = "/.ssh/authorized_keys" ascii
    condition:
        2 of them
}

rule SUID_Setuid_Combo
{
    meta:
        kind = "persistence"
        category = "privilege_escalation"
    strings:
        $a = "setuid" ascii fullword
        $b = "setgid" ascii fullword
        $c = "S_ISUID" ascii
        $d = "chmod" ascii fullword
    condition:
        2 of them
}
