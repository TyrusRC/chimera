// Chimera: iOS SSL pinning bypass
try {
    // SecTrustEvaluateWithError
    var SecTrustEvaluateWithError = Module.findExportByName("Security", "SecTrustEvaluateWithError");
    if (SecTrustEvaluateWithError) {
        Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
            if (error !== NULL) Memory.writePointer(error, NULL);
            return 1; // true = trusted
        }, "bool", ["pointer", "pointer"]));
        send({ type: "bypass", name: "SecTrustEvaluateWithError", status: "ok" });
    }

    // SecTrustEvaluate (legacy)
    var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
    if (SecTrustEvaluate) {
        Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
            // kSecTrustResultProceed = 1
            if (result !== NULL) Memory.writeU32(result, 1);
            return 0; // errSecSuccess
        }, "int", ["pointer", "pointer"]));
        send({ type: "bypass", name: "SecTrustEvaluate", status: "ok" });
    }
} catch(e) {}
