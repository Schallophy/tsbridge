# Vendor

`Package.swift` expects `tsbridge.xcframework` here. It is a **build artifact**,
not checked in — a binary in the repository ages out of sync with the source that
produced it, and the whole point of this repository is that a checkout can be
rebuilt.

Produce it with:

```sh
./tools/build-macos.sh
cd ../swift && swift build
```

The framework contains the universal `libtsbridge.dylib` (install name
`@rpath/libtsbridge.dylib`) and the real `include/tsbridge.h`, so a Swift caller
and a C caller always see the same declarations.
