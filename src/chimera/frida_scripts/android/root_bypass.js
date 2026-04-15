// Chimera: Android root detection bypass
Java.perform(function() {
    // RootBeer
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function() { return false; };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() { return false; };
        send({ type: "bypass", name: "rootbeer", status: "ok" });
    } catch(e) {}

    // File.exists for su paths
    try {
        var File = Java.use("java.io.File");
        var origExists = File.exists;
        var suPaths = ["/sbin/su", "/system/bin/su", "/system/xbin/su",
                       "/data/local/su", "/data/local/bin/su",
                       "/system/app/Superuser.apk", "/system/etc/init.d/99SuperSUDaemon"];
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            for (var i = 0; i < suPaths.length; i++) {
                if (path === suPaths[i]) return false;
            }
            return origExists.call(this);
        };
        send({ type: "bypass", name: "file_exists_su", status: "ok" });
    } catch(e) {}

    // Build.TAGS
    try {
        var Build = Java.use("android.os.Build");
        Build.TAGS.value = "release-keys";
        send({ type: "bypass", name: "build_tags", status: "ok" });
    } catch(e) {}
});
