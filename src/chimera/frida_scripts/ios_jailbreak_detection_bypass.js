// chimera-frida-script
// id: ios-jailbreak-detection-bypass
// name: iOS Jailbreak Detection Bypass
// description: Patches NSFileManager fileExistsAtPath, dlopen, fork/sysctl checks for common JB markers.
// platform: ios
// requires: ObjC runtime
// risk: medium

if (ObjC.available) {
    console.log("[chimera] iOS jailbreak-detection bypass loaded");

    var jb_paths = [
        "/Applications/Cydia.app", "/Applications/Sileo.app",
        "/Applications/Zebra.app", "/Applications/blackra1n.app",
        "/Applications/Snoop-itConfig.app",
        "/usr/sbin/sshd", "/etc/apt", "/private/var/lib/apt/",
        "/var/lib/apt", "/private/var/Users/", "/Library/MobileSubstrate",
        "/usr/libexec/sftp-server", "/usr/bin/ssh",
        "/var/log/syslog", "/bin/bash", "/bin/sh",
        "/private/var/jb", "/var/jb",
    ];

    // 1. NSFileManager fileExistsAtPath:
    try {
        var FM = ObjC.classes.NSFileManager;
        var orig = FM["- fileExistsAtPath:"];
        Interceptor.attach(orig.implementation, {
            onEnter: function (args) {
                this.path = ObjC.Object(args[2]).toString();
            },
            onLeave: function (retval) {
                for (var i = 0; i < jb_paths.length; i++) {
                    if (this.path.indexOf(jb_paths[i]) >= 0) {
                        console.log("[chimera] fileExistsAtPath(" + this.path + ") -> NO");
                        retval.replace(0);
                        return;
                    }
                }
            }
        });
    } catch (e) { /* fine */ }

    // 2. dlopen on /usr/lib/libsubstrate / /Library/MobileSubstrate
    try {
        var dlopen = Module.findExportByName(null, "dlopen");
        Interceptor.attach(dlopen, {
            onEnter: function (args) {
                this.path = args[0] ? Memory.readUtf8String(args[0]) : "";
                if (this.path && (this.path.indexOf("substrate") >= 0
                                  || this.path.indexOf("MobileSubstrate") >= 0
                                  || this.path.indexOf("frida") >= 0)) {
                    console.log("[chimera] blocked dlopen(" + this.path + ")");
                    args[0] = ptr(0);
                }
            }
        });
    } catch (e) { /* fine */ }

    // 3. fork() — many JB checks call fork to detect sandbox escape; succeed silently
    try {
        var fork = Module.findExportByName(null, "fork");
        Interceptor.replace(fork, new NativeCallback(function () {
            return -1;  // pretend fork failed (sandbox enforced)
        }, "int", []));
    } catch (e) { /* fine */ }

    console.log("[chimera] iOS jailbreak-detection bypass active");
}
