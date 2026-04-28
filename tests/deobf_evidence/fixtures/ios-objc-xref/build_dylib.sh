#!/usr/bin/env bash
# Build the sample.dylib used by the ObjC xref evidence test.
# Requires macOS with Xcode command-line tools.
set -euo pipefail

OUT="${1:-sample.dylib}"
SRC="$(mktemp -t Greeter.XXXXXX).m"
trap 'rm -f "$SRC"' EXIT

cat > "$SRC" <<'EOF'
#import <Foundation/Foundation.h>

@protocol Greetable <NSObject>
- (NSString *)greet;
@end

@interface Greeter : NSObject <Greetable>
@property (nonatomic, copy) NSString *name;
- (NSString *)greet;
- (void)reset;
@end

@implementation Greeter
- (NSString *)greet { return [NSString stringWithFormat:@"Hello, %@", self.name]; }
- (void)reset { self.name = @""; }
@end

@interface Greeter (Logging)
- (void)logGreeting;
@end

@implementation Greeter (Logging)
- (void)logGreeting { NSLog(@"%@", [self greet]); }
@end

@interface AppDelegate : NSObject
- (void)application;
@end

@implementation AppDelegate
- (void)application {}
@end
EOF

xcrun --sdk iphoneos clang \
    -arch arm64 \
    -dynamiclib \
    -framework Foundation \
    -o "$OUT" \
    "$SRC"

echo "Built $OUT"
