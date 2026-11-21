// swift-tools-version:5.9
import PackageDescription

// Wraps the prebuilt dynamic library for SwiftUI.
//
// The C API arrives as an XCFramework (`Vendor/tsbridge.xcframework`), which is
// the only vendored-binary shape SwiftPM can both link and *embed* without
// unsafe flags: a plain `.linkedLibrary("tsbridge")` plus a `-L` path would need
// `unsafeFlags`, and a package that uses those cannot be consumed as a
// dependency by another package — it would work here and break every app that
// adds it.
//
// The framework holds the universal `libtsbridge.dylib` and the real
// `include/tsbridge.h`; `tools/build-macos.sh` produces it, so there is no second
// copy of the header to drift.
//
// Swift sees the raw C API under the module `tsbridge` and wraps it in
// `Sources/TSBridge/TSBridge.swift`; nothing is generated.
let package = Package(
    name: "TSBridge",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "TSBridge", targets: ["TSBridge"]),
    ],
    targets: [
        .binaryTarget(name: "tsbridge", path: "Vendor/tsbridge.xcframework"),
        .target(
            name: "TSBridge",
            dependencies: ["tsbridge"],
            path: "Sources/TSBridge"
        ),
    ]
)
