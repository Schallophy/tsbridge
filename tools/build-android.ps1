# Builds libtsbridge_jni.so for Android and, when a sibling checkout exists,
# installs it into the tsdroid app's jniLibs directory.
#
# Copying is a separate, explicit flag (`-Sync`) rather than automatic: a build
# that failed must never leave the previous .so in place looking like the new
# code shipped.
#
# Requires: cargo-ndk, the Android NDK (r27c / 27.2.12479018), cmake and ninja —
# audiopus compiles the libopus C sources through them.
#
#   ./tools/build-android.ps1                  build only
#   ./tools/build-android.ps1 -Sync            build, then copy into ../tsdroid
#   ./tools/build-android.ps1 -Abi arm64-v8a   pick the ABI (default arm64-v8a)

param(
    [string]$Abi = "arm64-v8a",
    [switch]$Sync,
    [string]$AppDir = ""
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$sdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME }
       elseif ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT }
       else { Join-Path $env:LOCALAPPDATA "Android\Sdk" }

if (-not $env:ANDROID_NDK_HOME) {
    $ndk = (Get-ChildItem (Join-Path $sdk "ndk") -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | Select-Object -First 1)
    if (-not $ndk) {
        throw "No NDK under $sdk\ndk. Install one with: sdkmanager --install 'ndk;27.2.12479018'"
    }
    $env:ANDROID_NDK_HOME = $ndk.FullName
}
$env:ANDROID_NDK = $env:ANDROID_NDK_HOME
Write-Host "NDK: $env:ANDROID_NDK_HOME"

# Prefer the SDK's bundled CMake, then a system CMake.
$sdkCmake = (Get-ChildItem (Join-Path $sdk "cmake") -Directory -ErrorAction SilentlyContinue |
             Sort-Object Name -Descending | Select-Object -First 1)
if ($sdkCmake -and (Test-Path (Join-Path $sdkCmake.FullName "bin\cmake.exe"))) {
    $env:PATH = (Join-Path $sdkCmake.FullName "bin") + ";$env:PATH"
}
$systemCmake = "C:\Program Files\CMake\bin"
if (Test-Path (Join-Path $systemCmake "cmake.exe")) {
    $env:PATH = "$systemCmake;$env:PATH"
    # Opus's CMakeLists still declares cmake_minimum_required(VERSION 3.0);
    # CMake 4 refuses it unless this escape hatch is set.
    $env:CMAKE_POLICY_VERSION_MINIMUM = "3.5"
}

# CMake otherwise picks the Visual Studio generator, which cannot cross-compile.
$env:CMAKE_GENERATOR = "Ninja"

# Cargo writes its progress to stderr. Under `$ErrorActionPreference = "Stop"`,
# PowerShell 5.1 turns any native stderr output into a terminating
# NativeCommandError — which made this script abort on a *successful* build, and
# when the preference is merely relaxed the same text still prints as a red error
# record. Running the native tool through `cmd /c` with `2>&1` folds both streams
# into stdout, so only the exit code decides whether the build worked.
function Invoke-NativeCargo {
    param([string]$Arguments)
    cmd /c "cargo $Arguments 2>&1"
    if ($LASTEXITCODE -ne 0) { throw "cargo $Arguments failed with exit code $LASTEXITCODE" }
}

Invoke-NativeCargo "ndk -t $Abi -o out/android build --release -p tsbridge-jni"

$so = Join-Path "out\android" "$Abi\libtsbridge_jni.so"
if (-not (Test-Path $so)) { throw "expected $so" }
$size = [math]::Round((Get-Item $so).Length / 1MB, 2)
Write-Host "Built: $so ($size MB)"

if ($Sync) {
    if (-not $AppDir) { $AppDir = Join-Path (Split-Path -Parent (Get-Location)) "tsdroid" }
    $dest = Join-Path $AppDir "app\src\main\jniLibs\$Abi"
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item $so -Destination $dest -Force
    Write-Host "Installed into: $dest"
}
