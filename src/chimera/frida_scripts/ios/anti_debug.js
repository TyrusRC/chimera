// Chimera: iOS anti-debug bypass
try {
    var ptrace = Module.findExportByName("libsystem_kernel.dylib", "ptrace");
    if (ptrace) {
        Interceptor.attach(ptrace, {
            onEnter: function(args) {
                // PT_DENY_ATTACH = 31
                if (args[0].toInt32() === 31) {
                    this.deny = true;
                    args[0] = ptr(0);
                }
            },
            onLeave: function(retval) {
                if (this.deny) retval.replace(0);
            }
        });
        send({ type: "bypass", name: "ptrace_deny", status: "ok" });
    }
} catch(e) {}

// getppid bypass
try {
    var getppid = Module.findExportByName("libsystem_kernel.dylib", "getppid");
    if (getppid) {
        Interceptor.replace(getppid, new NativeCallback(function() {
            return 1; // launchd
        }, "int", []));
        send({ type: "bypass", name: "getppid", status: "ok" });
    }
} catch(e) {}
