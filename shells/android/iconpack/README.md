# Icon pack

`dark.ts3_iconpack` is the upstream release artifact, committed verbatim:

- release: `v1.0.1` — <https://github.com/randomhost/teamspeak-dark/releases/tag/1.0.1>
- asset: `dark.ts3_iconpack`
- sha256: `1c6d4958372f88a2011616ee4fe21bc60c291c8b97c4d4259af430475000d3bd`

It is the TeamSpeak addon format: a zip with `package.ini` and `gfx/dark/*.svg`.
Do not re-zip it — the point of committing the published file is that its bytes
can be compared against the release. The 197 SVGs are identical to the ones in
the repository at `66d732f2`, so either source produces the same icons.

The build converts it, it is not read at runtime:

```
./gradlew :app:buildIconpack
```

`tools/svg2vector.py --pack` turns each `gfx/dark/*.svg` into
`build/generated/iconpackRes/drawable/icon_<name>.xml`; nothing under
`app/src/main/res/drawable` is tracked. The converter refuses shapes it cannot
express exactly (radial gradients, rounded rects, stroked paths) rather than
approximating them.

One icon, `moderated`, is converted from `tools/iconpack-overrides/moderated.svg`
instead: the pack draws its "M" as `<text>` in a macOS-only font, which cannot be
outlined portably. That override is the only icon-related file kept in the tree
outside this directory.

The pack is BSD-3-Clause; the licence text ships inside the APK as
`app/src/main/assets/licenses/LICENSE-TEAMSPEAK-ICONS`.
