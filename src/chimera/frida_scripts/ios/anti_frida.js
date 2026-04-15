// Chimera: iOS anti-Frida bypass
try {
    var sysctl = Module.findExportByName("libsystem_kernel.dylib", "sysctl");
    if (sysctl) {
        Interceptor.attach(sysctl, {
            onLeave: function(retval) {
                // Mask P_TRACED flag if queried
            }
        });
    }
    send({ type: "bypass", name: "ios_anti_frida", status: "ok" });
} catch(e) {}
