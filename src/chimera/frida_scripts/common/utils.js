// Chimera Frida utilities
function log(tag, msg) {
    send({ type: "log", tag: tag, message: msg });
}
function hook(cls, method, impl) {
    try {
        var target = Java.use(cls);
        target[method].implementation = impl;
        log("hook", "Hooked " + cls + "." + method);
    } catch(e) {
        log("hook", "Failed to hook " + cls + "." + method + ": " + e);
    }
}
