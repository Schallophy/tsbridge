# Runs the C ABI smoke test against the freshly built library.
#
#   ./tools/smoke.ps1
#
# On Windows it drives MSVC via vcvars64; the test itself is plain C so it also
# builds with any C compiler on Linux/macOS (see tools/smoke.c).

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$dll = "target\debug\tsbridge.dll"
if (-not (Test-Path $dll)) { throw "build first: cargo build -p tsbridge" }

$buildTools = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools"
$vcvars = Join-Path $buildTools "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found; install VS Build Tools with the C++ workload" }

$outDir = "out"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$exe = Join-Path $outDir "smoke.exe"

# vcvars64 must run in cmd; then compile /utf-8 so a header or source file saved
# as UTF-8 does not draw C4819, and /Fo keeps the object out of the repo root.
$script = "call `"$vcvars`" >nul && cl /nologo /W4 /utf-8 /Iinclude tools\smoke.c target\debug\tsbridge.dll.lib /Fo`"$outDir\smoke.obj`" /Fe`"$exe`""
cmd /c $script
if ($LASTEXITCODE -ne 0) { throw "compilation failed" }

# The DLL has to sit next to the exe for the loader to find it.
Copy-Item $dll (Join-Path $outDir "tsbridge.dll") -Force
& $exe
if ($LASTEXITCODE -ne 0) { throw "smoke test failed" }
