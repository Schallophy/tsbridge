// swift-tools-version:5.9
import PackageDescription

// Wraps the prebuilt dynamic library for SwiftUI.
//
// The C API arrives as an XCFramework (`Vendor/litespeak.xcframework`), which is
// the only vendored-binary shape SwiftPM can both link and *embed* without
// unsafe flags: a plain `.linkedLibrary("litespeak")` plus a `-L` path would need
// `unsafeFlags`, and a package that uses those cannot be consumed as a
// dependency by another package — it would work here and break every app that
// adds it.
//
// The framework holds the universal `liblitespeak.dylib` and the real
// `include/litespeak.h`; `tools/build-macos.sh` produces it, so there is no second
// copy of the header to drift.
//
// Swift sees the raw C API under the module `litespeak` and wraps it in
// `Sources/LiteSpeak/LiteSpeak.swift`; nothing is generated.
let package = Package(
    name: "LiteSpeak",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "LiteSpeak", targets: ["LiteSpeak"]),
    ],
    targets: [
        .binaryTarget(name: "litespeak", path: "Vendor/litespeak.xcframework"),
        .target(
            name: "LiteSpeak",
            dependencies: ["litespeak"],
            path: "Sources/LiteSpeak"
        ),
    ]
)
