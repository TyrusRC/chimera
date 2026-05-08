// chimera-frida-script
// id: android-ssl-pinning-bypass
// name: Android SSL Pinning Bypass
// description: Bypasses TrustManagerImpl, OkHttp CertificatePinner, TrustKit, BoringSSL.
// platform: android
// requires: Java, OkHttp (optional), TrustKit (optional)
// risk: high

Java.perform(function () {
    console.log("[chimera] Android SSL pinning bypass loaded");

    // 1. android.security.NetworkSecurityConfig — neutralize
    try {
        var NSC = Java.use("android.security.net.config.NetworkSecurityConfig");
        NSC.isCertificateTransparencyVerificationRequired.implementation = function () {
            return false;
        };
    } catch (e) { /* not present on every API level */ }

    // 2. javax.net.ssl.TrustManagerFactory — install permissive trust manager
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var TrustManager = Java.registerClass({
            name: "com.chimera.PermissiveTrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var TrustManagers = [TrustManager.$new()];
        var SSLContextInit = SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        );
        SSLContextInit.implementation = function (keyManager, trustManager, secureRandom) {
            console.log("[chimera] SSLContext.init hooked");
            SSLContextInit.call(this, keyManager, TrustManagers, secureRandom);
        };
    } catch (e) { console.log("[chimera] TrustManager hook failed: " + e); }

    // 3. OkHttp 3.x / 4.x CertificatePinner.check
    try {
        var CertPinner = Java.use("okhttp3.CertificatePinner");
        CertPinner.check.overload("java.lang.String", "java.util.List").implementation = function (h, p) {
            console.log("[chimera] OkHttp CertificatePinner.check bypassed for " + h);
            return;
        };
    } catch (e) { /* OkHttp absent */ }

    // 4. TrustKit pinning
    try {
        var TrustKit = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
        TrustKit.verify.overload(
            "java.lang.String", "javax.net.ssl.SSLSession"
        ).implementation = function (h, s) {
            console.log("[chimera] TrustKit verify bypassed for " + h);
            return true;
        };
    } catch (e) { /* TrustKit absent */ }

    // 5. Conscrypt (BoringSSL backend used by modern Android)
    try {
        var Platform = Java.use("okhttp3.internal.platform.Platform");
        if (Platform.trustManager) {
            Platform.trustManager.implementation = function (sslSocketFactory) {
                return null;
            };
        }
    } catch (e) { /* fine */ }

    console.log("[chimera] Android SSL pinning bypass active");
});
