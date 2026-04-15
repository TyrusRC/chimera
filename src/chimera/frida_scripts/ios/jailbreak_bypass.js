// Chimera: iOS jailbreak detection bypass
if (ObjC.available) {
    // canOpenURL bypass
    try {
        var NSURL = ObjC.classes.NSURL;
        var UIApplication = ObjC.classes.UIApplication;
        var origCanOpen = UIApplication["- canOpenURL:"];
        Interceptor.attach(origCanOpen.implementation, {
            onEnter: function(args) {
                var url = new ObjC.Object(args[2]).toString();
                if (url.indexOf("cydia") !== -1 || url.indexOf("sileo") !== -1) {
                    this.block = true;
                }
            },
            onLeave: function(retval) {
                if (this.block) retval.replace(0);
            }
        });
        send({ type: "bypass", name: "canOpenURL", status: "ok" });
    } catch(e) {}

    // NSFileManager fileExistsAtPath
    try {
        var NSFileManager = ObjC.classes.NSFileManager;
        var origExists = NSFileManager["- fileExistsAtPath:"];
        var jbPaths = ["/Applications/Cydia.app", "/Applications/Sileo.app",
                       "/usr/sbin/sshd", "/usr/bin/ssh", "/etc/apt",
                       "/bin/bash", "/Library/MobileSubstrate"];
        Interceptor.attach(origExists.implementation, {
            onEnter: function(args) {
                var path = new ObjC.Object(args[2]).toString();
                for (var i = 0; i < jbPaths.length; i++) {
                    if (path.indexOf(jbPaths[i]) !== -1) {
                        this.block = true;
                        break;
                    }
                }
            },
            onLeave: function(retval) {
                if (this.block) retval.replace(0);
            }
        });
        send({ type: "bypass", name: "fileExistsAtPath", status: "ok" });
    } catch(e) {}

    // fork() bypass
    try {
        var fork = Module.findExportByName("libsystem_kernel.dylib", "fork");
        if (fork) {
            Interceptor.attach(fork, {
                onLeave: function(retval) { retval.replace(-1); }
            });
        }
        send({ type: "bypass", name: "fork", status: "ok" });
    } catch(e) {}
}
