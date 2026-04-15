// Chimera: SSL pinning bypass for Android
Java.perform(function() {
    // OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
            send({ type: "bypass", name: "okhttp3_pinning", hostname: hostname, status: "ok" });
        };
    } catch(e) {}

    // TrustManager
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.checkTrustedRecursive.implementation = function() {
            return Java.use("java.util.ArrayList").$new();
        };
        send({ type: "bypass", name: "trustmanager", status: "ok" });
    } catch(e) {}

    // Generic X509TrustManager
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var TrustManager = Java.registerClass({
            name: "chimera.BypassTrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        var ctx = SSLContext.getInstance("TLS");
        ctx.init(null, [TrustManager.$new()], null);
        SSLContext.setDefault(ctx);
        send({ type: "bypass", name: "x509_trustmanager", status: "ok" });
    } catch(e) {}
});
