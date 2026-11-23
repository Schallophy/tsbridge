# Runs the C ABI smoke test against the freshly built library.
#
#   ./tools/smoke.ps1            # target\debug
#   ./tools/smoke.ps1 -Release   # target\release, i.e. the artifact that ships
#
# On Windows it drives MSVC via vcvars64; the test itself is plain C so it also
# builds with any C compiler on Linux/macOS (see tools/smoke.c).

param(
    [switch]$Release
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

# Both profiles are worth testing: the debug build catches ABI mistakes quickly,
# the release build is the one whose optimised code a shell actually loads.
$profile = if ($Release) { "release" } else { "debug" }
$dll = "target\$profile\tsbridge.dll"
if (-not (Test-Path $dll)) { throw "build first: cargo build $(if ($Release) { '--release' }) -p tsbridge" }
$importLib = Join-Path (Split-Path -Parent $dll) "tsbridge.dll.lib"

# vswhere knows where Build Tools live; the install path carries a version that
# changes between machines (2022, 18, …), so it must not be hardcoded.
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found; install VS Build Tools with the C++ workload" }
$install = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $install) { throw "no Visual Studio installation with the C++ workload" }
$vcvars = Join-Path $install "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found under $install" }

$outDir = "out"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$exe = Join-Path $outDir "smoke.exe"

# vcvars64 must run in cmd; then compile /utf-8 so a header or source file saved
# as UTF-8 does not draw C4819, and /Fo keeps the object out of the repo root.
$script = "call `"$vcvars`" >nul && cl /nologo /W4 /utf-8 /Iinclude tools\smoke.c `"$importLib`" /Fo`"$outDir\smoke.obj`" /Fe`"$exe`""
cmd /c $script
if ($LASTEXITCODE -ne 0) { throw "compilation failed" }

# The DLL has to sit next to the exe for the loader to find it.
Copy-Item $dll (Join-Path $outDir "tsbridge.dll") -Force
& $exe
if ($LASTEXITCODE -ne 0) { throw "smoke test failed ($profile)" }
