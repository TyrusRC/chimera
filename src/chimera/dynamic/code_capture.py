"""Dynamic code capture — hook classloaders/dlopen to intercept runtime-loaded code."""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_ANDROID_CAPTURE_SCRIPT = """
// Chimera: Dynamic code capture — Android
Java.perform(function() {
    // DexClassLoader
    try {
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        DexClassLoader.$init.implementation = function(dexPath, optimizedDir, libraryPath, parent) {
            send({ type: "code_capture", loader: "DexClassLoader", path: dexPath });
            // Read and send the DEX file
            var File = Java.use("java.io.File");
            var f = File.$new(dexPath);
            if (f.exists()) {
                send({ type: "code_capture_data", path: dexPath, size: f.length() });
            }
            return this.$init(dexPath, optimizedDir, libraryPath, parent);
        };
        send({ type: "hook", name: "DexClassLoader", status: "ok" });
    } catch(e) {}

    // InMemoryDexClassLoader (Android 8+)
    try {
        var InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
        InMemoryDexClassLoader.$init.overload("java.nio.ByteBuffer", "java.lang.ClassLoader").implementation = function(buf, parent) {
            send({ type: "code_capture", loader: "InMemoryDexClassLoader", size: buf.remaining() });
            return this.$init(buf, parent);
        };
        send({ type: "hook", name: "InMemoryDexClassLoader", status: "ok" });
    } catch(e) {}

    // System.loadLibrary
    try {
        var System = Java.use("java.lang.System");
        System.loadLibrary.implementation = function(lib) {
            send({ type: "code_capture", loader: "System.loadLibrary", library: lib });
            return this.loadLibrary(lib);
        };
        send({ type: "hook", name: "System.loadLibrary", status: "ok" });
    } catch(e) {}

    // System.load
    try {
        var System = Java.use("java.lang.System");
        System.load.implementation = function(path) {
            send({ type: "code_capture", loader: "System.load", path: path });
            return this.load(path);
        };
        send({ type: "hook", name: "System.load", status: "ok" });
    } catch(e) {}
});
"""

_IOS_CAPTURE_SCRIPT = """
// Chimera: Dynamic code capture — iOS
// dlopen hook
try {
    var dlopen = Module.findExportByName(null, "dlopen");
    if (dlopen) {
        Interceptor.attach(dlopen, {
            onEnter: function(args) {
                var path = args[0].readUtf8String();
                if (path) {
                    send({ type: "code_capture", loader: "dlopen", path: path });
                }
            }
        });
        send({ type: "hook", name: "dlopen", status: "ok" });
    }
} catch(e) {}

// NSBundle.load
try {
    if (ObjC.available) {
        var NSBundle = ObjC.classes.NSBundle;
        var origLoad = NSBundle["- load"];
        Interceptor.attach(origLoad.implementation, {
            onEnter: function(args) {
                var bundle = new ObjC.Object(args[0]);
                send({ type: "code_capture", loader: "NSBundle.load",
                       path: bundle.bundlePath().toString() });
            }
        });
        send({ type: "hook", name: "NSBundle.load", status: "ok" });
    }
} catch(e) {}
"""


class DynamicCodeCapture:
    def __init__(self, output_dir: Path | None = None):
        self.output_dir = Path(output_dir) if output_dir else Path.cwd() / "chimera_captured"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.captured_files: list[dict] = []

    def get_capture_script(self, platform: str) -> str:
        if platform == "android":
            return _ANDROID_CAPTURE_SCRIPT
        elif platform == "ios":
            return _IOS_CAPTURE_SCRIPT
        return ""

    def process_message(self, message: dict) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict) and payload.get("type") == "code_capture":
                self.captured_files.append(payload)
                logger.info("Captured dynamic code: %s via %s",
                           payload.get("path", payload.get("library", "?")),
                           payload.get("loader", "?"))

    def get_captured(self) -> list[dict]:
        return list(self.captured_files)
