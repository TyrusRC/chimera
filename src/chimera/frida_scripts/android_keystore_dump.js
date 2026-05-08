// chimera-frida-script
// id: android-keystore-dump
// name: Android Keystore Dump
// description: Logs keystore alias enumeration, key creation, and stored secrets.
// platform: android
// requires: Java
// risk: low

Java.perform(function () {
    console.log("[chimera] Android Keystore dump loaded");

    var KS = Java.use("java.security.KeyStore");

    // 1. Log every alias() lookup
    var aliasesOverload = KS.aliases.overload();
    aliasesOverload.implementation = function () {
        var en = aliasesOverload.call(this);
        try {
            var allKeys = Java.use("java.util.Collections").list(en);
            var size = allKeys.size();
            var keys = [];
            for (var i = 0; i < size; i++) {
                keys.push(allKeys.get(i).toString());
            }
            console.log("[chimera] KeyStore aliases: " + JSON.stringify(keys));
            return Java.use("java.util.Collections").enumeration(allKeys);
        } catch (e) {
            return en;
        }
    };

    // 2. Log every getKey(alias, password)
    var getKeyOverload = KS.getKey.overload("java.lang.String", "[C");
    getKeyOverload.implementation = function (alias, pw) {
        console.log("[chimera] KeyStore.getKey(" + alias + ")");
        return getKeyOverload.call(this, alias, pw);
    };

    // 3. Log SharedPreferences read/write — common shadow keystore
    try {
        var SP = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        var putStringOverload = SP.putString.overload("java.lang.String", "java.lang.String");
        putStringOverload.implementation = function (k, v) {
            console.log("[chimera] SharedPreferences.putString(" + k + ", " + v + ")");
            return putStringOverload.call(this, k, v);
        };
    } catch (e) { /* fine */ }

    console.log("[chimera] Android Keystore dump active");
});
