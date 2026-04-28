#!/usr/bin/env bash
# Build the sample.dylib used by the ObjC xref evidence test.
# Requires macOS with Xcode command-line tools.
set -euo pipefail

OUT="${1:-sample.dylib}"

cat > /tmp/Greeter.m <<'EOF'
#import <Foundation/Foundation.h>

@interface Greeter : NSObject
@property (nonatomic, copy) NSString *name;
- (NSString *)greet;
@end

@implementation Greeter
- (NSString *)greet { return [NSString stringWithFormat:@"Hello, %@", self.name]; }
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
    /tmp/Greeter.m

echo "Built $OUT"
