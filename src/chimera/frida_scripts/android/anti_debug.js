// Chimera: Anti-debug bypass for Android
Java.perform(function() {
    // Debug.isDebuggerConnected
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() { return false; };
        send({ type: "bypass", name: "debug_connected", status: "ok" });
    } catch(e) {}
});

// ptrace bypass (native)
try {
    var ptrace = Module.findExportByName("libc.so", "ptrace");
    if (ptrace) {
        Interceptor.attach(ptrace, {
            onEnter: function(args) {
                this.request = args[0].toInt32();
            },
            onLeave: function(retval) {
                // PTRACE_TRACEME = 0
                if (this.request === 0) {
                    retval.replace(0);
                }
            }
        });
        send({ type: "bypass", name: "ptrace", status: "ok" });
    }
} catch(e) {}
