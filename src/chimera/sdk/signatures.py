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

    # Ads
    {"name": "AdMob", "package": "com.google.android.gms.ads", "category": "ads", "risk": "clean"},
    {"name": "Facebook Ads", "package": "com.facebook.ads", "category": "ads", "risk": "clean"},
    {"name": "Unity Ads", "package": "com.unity3d.ads", "category": "ads", "risk": "clean"},
    {"name": "IronSource", "package": "com.ironsource", "category": "ads", "risk": "clean"},
    {"name": "AppLovin", "package": "com.applovin", "category": "ads", "risk": "clean"},

    # Networking
    {"name": "OkHttp", "package": "com.squareup.okhttp3", "category": "networking", "risk": "clean"},
    {"name": "Retrofit", "package": "com.squareup.retrofit2", "category": "networking", "risk": "clean"},
    {"name": "Volley", "package": "com.android.volley", "category": "networking", "risk": "clean"},

    # Crash Reporting
    {"name": "Sentry", "package": "io.sentry", "category": "crash_reporting", "risk": "clean"},
    {"name": "Crashlytics", "package": "com.google.firebase.crashlytics", "category": "crash_reporting", "risk": "clean"},
    {"name": "Bugsnag", "package": "com.bugsnag", "category": "crash_reporting", "risk": "clean"},

    # Social
    {"name": "Facebook SDK", "package": "com.facebook", "category": "social", "risk": "clean"},
    {"name": "Twitter SDK", "package": "com.twitter", "category": "social", "risk": "clean"},
    {"name": "Google Sign-In", "package": "com.google.android.gms.auth", "category": "auth", "risk": "clean"},

    # Payment
    {"name": "Stripe", "package": "com.stripe", "category": "payment", "risk": "clean"},
    {"name": "Braintree", "package": "com.braintreepayments", "category": "payment", "risk": "clean"},

    # Cross-platform
    {"name": "React Native", "package": "com.facebook.react", "category": "framework", "risk": "clean"},
    {"name": "Flutter Engine", "package": "io.flutter", "category": "framework", "risk": "clean"},
    {"name": "Xamarin", "package": "mono.android", "category": "framework", "risk": "clean"},
    {"name": "Cordova", "package": "org.apache.cordova", "category": "framework", "risk": "clean"},

    # Security (detection = interesting for RE)
    {"name": "RootBeer", "package": "com.scottyab.rootbeer", "category": "security", "risk": "clean"},
    {"name": "SafetyNet", "package": "com.google.android.gms.safetynet", "category": "security", "risk": "clean"},
    {"name": "DexGuard", "package": "com.guardsquare", "category": "security", "risk": "clean"},
    {"name": "Talsec", "package": "com.aheaditec.talsec", "category": "security", "risk": "clean"},

    # Suspicious
    {"name": "Xposed Framework", "package": "de.robv.android.xposed", "category": "suspicious", "risk": "suspicious"},
]
