"""Known SDK signatures for fingerprinting third-party libraries."""

SDK_SIGNATURES = [
    # Analytics & Tracking
    {"name": "Firebase", "package": "com.google.firebase", "category": "analytics", "risk": "clean"},
    {"name": "Google Analytics", "package": "com.google.android.gms.analytics", "category": "analytics", "risk": "clean"},
    {"name": "Adjust", "package": "com.adjust.sdk", "category": "analytics", "risk": "clean"},
    {"name": "AppsFlyer", "package": "com.appsflyer", "category": "analytics", "risk": "clean"},
    {"name": "Mixpanel", "package": "com.mixpanel", "category": "analytics", "risk": "clean"},
    {"name": "Amplitude", "package": "com.amplitude", "category": "analytics", "risk": "clean"},
    {"name": "Segment", "package": "com.segment.analytics", "category": "analytics", "risk": "clean"},
    {"name": "Flurry", "package": "com.flurry", "category": "analytics", "risk": "clean"},
    {"name": "Branch", "package": "io.branch", "category": "analytics", "risk": "clean"},
    {"name": "Kochava", "package": "com.kochava", "category": "analytics", "risk": "clean"},
    {"name": "OneSignal", "package": "com.onesignal", "category": "analytics", "risk": "clean"},

    # Ads
    {"name": "AdMob", "package": "com.google.android.gms.ads", "category": "ads", "risk": "clean"},
    {"name": "Facebook Ads", "package": "com.facebook.ads", "category": "ads", "risk": "clean"},
    {"name": "Unity Ads", "package": "com.unity3d.ads", "category": "ads", "risk": "clean"},
    {"name": "IronSource", "package": "com.ironsource", "category": "ads", "risk": "clean"},
    {"name": "AppLovin", "package": "com.applovin", "category": "ads", "risk": "clean"},
    {"name": "Vungle", "package": "com.vungle", "category": "ads", "risk": "clean"},

    # Networking — note OkHttp's actual published package is `okhttp3`,
    # not `com.squareup.okhttp3`. Match both for safety.
    # OkHttp / Retrofit / OkIO ship under their bare top-level packages
    # (`okhttp3`, `okio`, `retrofit2`); the `com.squareup.*` aliases existed
    # historically. Match either path under the same SDK name.
    {"name": "OkHttp", "package": "okhttp3", "category": "networking", "risk": "clean"},
    {"name": "OkHttp", "package": "com.squareup.okhttp3", "category": "networking", "risk": "clean"},
    {"name": "OkIO", "package": "okio", "category": "networking", "risk": "clean"},
    {"name": "Retrofit", "package": "retrofit2", "category": "networking", "risk": "clean"},
    {"name": "Retrofit", "package": "com.squareup.retrofit2", "category": "networking", "risk": "clean"},
    {"name": "Volley", "package": "com.android.volley", "category": "networking", "risk": "clean"},
    {"name": "Apollo GraphQL", "package": "com.apollographql.apollo3", "category": "networking", "risk": "clean"},
    {"name": "Ktor", "package": "io.ktor", "category": "networking", "risk": "clean"},

    # Image / media
    {"name": "Glide", "package": "com.bumptech.glide", "category": "media", "risk": "clean"},
    {"name": "Picasso", "package": "com.squareup.picasso", "category": "media", "risk": "clean"},
    {"name": "Coil", "package": "coil", "category": "media", "risk": "clean"},
    {"name": "Fresco", "package": "com.facebook.drawee", "category": "media", "risk": "clean"},
    {"name": "ExoPlayer", "package": "com.google.android.exoplayer2", "category": "media", "risk": "clean"},
    {"name": "ZXing", "package": "com.google.zxing", "category": "media", "risk": "clean"},

    # Crash Reporting / observability
    {"name": "Sentry", "package": "io.sentry", "category": "crash_reporting", "risk": "clean"},
    {"name": "Crashlytics", "package": "com.google.firebase.crashlytics", "category": "crash_reporting", "risk": "clean"},
    {"name": "Bugsnag", "package": "com.bugsnag", "category": "crash_reporting", "risk": "clean"},
    {"name": "ACRA", "package": "org.acra", "category": "crash_reporting", "risk": "clean"},
    {"name": "Datadog", "package": "com.datadog", "category": "crash_reporting", "risk": "clean"},
    {"name": "New Relic", "package": "com.newrelic", "category": "crash_reporting", "risk": "clean"},

    # Social
    {"name": "Facebook SDK", "package": "com.facebook", "category": "social", "risk": "clean"},
    {"name": "Twitter SDK", "package": "com.twitter", "category": "social", "risk": "clean"},
    {"name": "Google Sign-In", "package": "com.google.android.gms.auth", "category": "auth", "risk": "clean"},
    {"name": "AppAuth", "package": "net.openid.appauth", "category": "auth", "risk": "clean"},

    # Payment
    {"name": "Stripe", "package": "com.stripe", "category": "payment", "risk": "clean"},
    {"name": "Braintree", "package": "com.braintreepayments", "category": "payment", "risk": "clean"},
    {"name": "PayPal", "package": "com.paypal", "category": "payment", "risk": "clean"},

    # JSON / serialization
    {"name": "Gson", "package": "com.google.gson", "category": "serialization", "risk": "clean"},
    {"name": "Jackson", "package": "com.fasterxml.jackson", "category": "serialization", "risk": "clean"},
    {"name": "Moshi", "package": "com.squareup.moshi", "category": "serialization", "risk": "clean"},
    {"name": "kotlinx.serialization", "package": "kotlinx.serialization", "category": "serialization", "risk": "clean"},

    # Reactive / DI
    {"name": "RxJava", "package": "io.reactivex", "category": "reactive", "risk": "clean"},
    {"name": "RxJava3", "package": "io.reactivex.rxjava3", "category": "reactive", "risk": "clean"},
    {"name": "Dagger", "package": "dagger", "category": "di", "risk": "clean"},
    {"name": "Hilt", "package": "dagger.hilt", "category": "di", "risk": "clean"},
    {"name": "Koin", "package": "org.koin", "category": "di", "risk": "clean"},

    # Cross-platform
    {"name": "React Native", "package": "com.facebook.react", "category": "framework", "risk": "clean"},
    {"name": "Flutter Engine", "package": "io.flutter", "category": "framework", "risk": "clean"},
    {"name": "Xamarin", "package": "mono.android", "category": "framework", "risk": "clean"},
    {"name": "Cordova", "package": "org.apache.cordova", "category": "framework", "risk": "clean"},

    # Security (detection = interesting for RE)
    {"name": "RootBeer", "package": "com.scottyab.rootbeer", "category": "security", "risk": "clean"},
    {"name": "SafetyNet", "package": "com.google.android.gms.safetynet", "category": "security", "risk": "clean"},
    {"name": "Play Integrity", "package": "com.google.android.play.core.integrity", "category": "security", "risk": "clean"},
    {"name": "DexGuard", "package": "com.guardsquare", "category": "security", "risk": "clean"},
    {"name": "Talsec", "package": "com.aheaditec.talsec", "category": "security", "risk": "clean"},
    {"name": "Tink (crypto)", "package": "com.google.crypto.tink", "category": "security", "risk": "clean"},
    {"name": "BouncyCastle", "package": "org.bouncycastle", "category": "security", "risk": "clean"},

    # Suspicious
    {"name": "Xposed Framework", "package": "de.robv.android.xposed", "category": "suspicious", "risk": "suspicious"},
]
