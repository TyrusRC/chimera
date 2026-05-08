// chimera-frida-script
// id: ios-ssl-pinning-bypass
// name: iOS SSL Pinning Bypass
// description: Bypasses NSURLSession, AFNetworking, TrustKit-iOS pinning.
// platform: ios
// requires: ObjC runtime, AFNetworking (optional), TrustKit (optional)
// risk: high

if (ObjC.available) {
    console.log("[chimera] iOS SSL pinning bypass loaded");

    // 1. NSURLSession default delegate — return performDefaultHandling
    try {
        var URLSession = ObjC.classes.NSURLSession;
        var origMethod = URLSession["- URLSession:didReceiveChallenge:completionHandler:"];
        if (origMethod) {
            Interceptor.attach(origMethod.implementation, {
                onEnter: function (args) {
                    console.log("[chimera] NSURLSession challenge intercepted");
                }
            });
        }
    } catch (e) { /* fine */ }

    // 2. AFNetworking — AFSecurityPolicy.evaluateServerTrust
    try {
        var AFSP = ObjC.classes.AFSecurityPolicy;
        if (AFSP) {
            var sel = AFSP["- evaluateServerTrust:forDomain:"];
            if (sel) {
                Interceptor.replace(sel.implementation, new NativeCallback(function (self, _cmd, trust, domain) {
                    console.log("[chimera] AFSecurityPolicy bypass");
                    return 1;  // YES
                }, "bool", ["pointer", "pointer", "pointer", "pointer"]));
            }
        }
    } catch (e) { /* fine */ }

    // 3. SecTrustEvaluate / SecTrustEvaluateWithError — force trusted
    try {
        var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
        if (SecTrustEvaluate) {
            Interceptor.replace(SecTrustEvaluate, new NativeCallback(function (trust, result) {
                Memory.writePointer(result, 1);  // kSecTrustResultProceed
                return 0;
            }, "int", ["pointer", "pointer"]));
        }
        var SecTrustEvaluateWithError = Module.findExportByName("Security", "SecTrustEvaluateWithError");
        if (SecTrustEvaluateWithError) {
            Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function (trust, error) {
                return 1;
            }, "bool", ["pointer", "pointer"]));
        }
    } catch (e) { console.log("[chimera] Sec hook failed: " + e); }

    // 4. TrustKit-iOS
    try {
        var TSKPinningValidator = ObjC.classes.TSKPinningValidator;
        if (TSKPinningValidator) {
            var sel = TSKPinningValidator["- evaluateTrust:forHostname:"];
            if (sel) {
                Interceptor.replace(sel.implementation, new NativeCallback(function () {
                    console.log("[chimera] TrustKit iOS bypass");
                    return 0;  // TSKTrustEvaluationSuccess
                }, "int", ["pointer", "pointer", "pointer", "pointer"]));
            }
        }
    } catch (e) { /* fine */ }

    console.log("[chimera] iOS SSL pinning bypass active");
}
