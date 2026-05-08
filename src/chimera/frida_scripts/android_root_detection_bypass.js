// chimera-frida-script
// id: android-root-detection-bypass
// name: Android Root Detection Bypass
// description: Patches RootBeer, Magisk hide checks, su lookups, build tags.
// platform: android
// requires: Java
// risk: medium

Java.perform(function () {
    console.log("[chimera] Android root-detection bypass loaded");

    // 1. RootBeer — return false on every check
    try {
        var RB = Java.use("com.scottyab.rootbeer.RootBeer");
        ["isRooted", "detectRootManagementApps", "detectPotentiallyDangerousApps",
         "checkForBinary", "checkForDangerousProps", "checkForBusyBoxBinary",
         "checkForRWPaths", "detectTestKeys"].forEach(function (m) {
            try {
                RB[m].implementation = function () {
                    console.log("[chimera] RootBeer." + m + " -> false");
                    return false;
                };
            } catch (e) { /* method absent */ }
        });
    } catch (e) { /* RootBeer absent */ }

    // 2. java.io.File.exists() — lie about /system/app/Superuser.apk etc.
    var File = Java.use("java.io.File");
    var blocked_paths = [
        "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su",
        "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su",
        "/su/bin/su", "/system/etc/init.d/99SuperSUDaemon",
        "/system/xbin/daemonsu", "/system/etc/.has_su_daemon",
        "/dev/com.koushikdutta.superuser.daemon/",
        "/sbin/.magisk", "/cache/.magisk", "/data/adb/magisk",
    ];
    var existsOverload = File.exists.overload();
    existsOverload.implementation = function () {
        var p = this.getAbsolutePath();
        for (var i = 0; i < blocked_paths.length; i++) {
            if (p.indexOf(blocked_paths[i]) === 0) {
                console.log("[chimera] File.exists(" + p + ") -> false (blocked)");
                return false;
            }
        }
        return existsOverload.call(this);
    };

    // 3. Build.TAGS — pretend it's "release-keys"
    try {
        var Build = Java.use("android.os.Build");
        Build.TAGS.value = "release-keys";
    } catch (e) { /* fine */ }

    // 4. Runtime.exec("which su") / ("su") — fail
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmd) {
            if (cmd && cmd.length > 0) {
                var first = cmd[0];
                if (first.indexOf("su") >= 0 || first.indexOf("which") >= 0) {
                    console.log("[chimera] blocked Runtime.exec(" + first + ")");
                    throw new (Java.use("java.io.IOException"))("not found");
                }
            }
            return this.exec.overload("[Ljava.lang.String;").call(this, cmd);
        };
    } catch (e) { /* fine */ }

    console.log("[chimera] Android root-detection bypass active");
});
