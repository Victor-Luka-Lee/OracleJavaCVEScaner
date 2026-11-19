[CmdletBinding()]
param(
    [string]$Python = "python",
    [switch]$SkipInstall,
    [switch]$SkipTests,
    [switch]$SkipSmoke
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$DistRoot = Join-Path $ProjectRoot "dist"
$BuildRoot = Join-Path $ProjectRoot "build"
$VenvRoot = Join-Path $ProjectRoot ".build-venv-windows"
$PackageRoot = Join-Path $BuildRoot "packages-windows"

function Assert-SafeBuildPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $allowed = [IO.Path]::GetFullPath($BuildRoot) + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($allowed, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to modify a path outside the build directory: $full"
    }
}

function Reset-Stage([string]$Path) {
    Assert-SafeBuildPath $Path
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
    New-Item -ItemType Directory -Path $Path | Out-Null
}

Write-Host "[1/9] Checking Python and build architecture"
$Version = & $Python -c "import platform,sys; print('.'.join(map(str, sys.version_info[:3]))); print(platform.machine())"
if ($LASTEXITCODE -ne 0) { throw "Cannot run Python: $Python" }
if (-not $Version[0].StartsWith("3.12.")) { throw "Validated Python 3.12.x is required: $($Version[0])" }
if (-not [Environment]::Is64BitProcess) { throw "Windows x64 Python is required." }

Write-Host "[2/9] Preparing isolated build environment"
if (-not $SkipInstall) {
    & $Python -m venv --clear $VenvRoot
    if ($LASTEXITCODE -ne 0) { throw "Failed to create build virtual environment" }
}
$VenvPython = Join-Path $VenvRoot "Scripts\python.exe"
if (-not (Test-Path -LiteralPath $VenvPython)) { throw "Build virtual environment is missing: $VenvPython" }
$env:PYTHONUTF8 = "1"

Write-Host "[3/9] Installing pinned dependencies"
if (-not $SkipInstall) {
    & $VenvPython -m pip install --disable-pip-version-check "pip==24.3.1"
    if ($LASTEXITCODE -ne 0) { throw "Failed to install pinned pip" }
    & $VenvPython -m pip install --disable-pip-version-check -e "${ProjectRoot}[build,ui]"
    if ($LASTEXITCODE -ne 0) { throw "Failed to install JVI build dependencies" }
}

Write-Host "[4/9] Running pytest"
New-Item -ItemType Directory -Force -Path $DistRoot, $BuildRoot | Out-Null
if (-not $SkipTests) {
    & $VenvPython -m pytest --basetemp (Join-Path $BuildRoot "pytest-windows")
    if ($LASTEXITCODE -ne 0) { throw "pytest failed" }
}

$OneFile = Join-Path $DistRoot "JVI.exe"
$OneDir = Join-Path $DistRoot "JVI-onedir"
foreach ($target in @($OneFile, $OneDir)) {
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
}
$env:JVI_PROJECT_ROOT = $ProjectRoot

Write-Host "[5/9] Building PyInstaller one-file"
$env:JVI_BUILD_MODE = "onefile"
& $VenvPython -m PyInstaller --noconfirm --clean `
    --distpath $DistRoot `
    --workpath (Join-Path $BuildRoot "pyinstaller-windows-onefile") `
    (Join-Path $ProjectRoot "packaging\jvi_cli.spec")
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $OneFile)) { throw "Windows one-file build failed" }

Write-Host "[6/9] Building PyInstaller one-folder"
$env:JVI_BUILD_MODE = "onedir"
& $VenvPython -m PyInstaller --noconfirm --clean `
    --distpath $DistRoot `
    --workpath (Join-Path $BuildRoot "pyinstaller-windows-onedir") `
    (Join-Path $ProjectRoot "packaging\jvi_cli.spec")
$OneDirExe = Join-Path $OneDir "JVI.exe"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $OneDirExe)) { throw "Windows one-folder build failed" }

Write-Host "[7/9] Running standalone executable smoke test"
if (-not $SkipSmoke) {
    & $VenvPython (Join-Path $ProjectRoot "scripts\smoke_test.py") $OneFile `
        --peer $OneDirExe `
        --project-root $ProjectRoot `
        --expected-format pe `
        --one-click `
        --relocate-onefile
    if ($LASTEXITCODE -ne 0) { throw "Windows smoke test failed" }
}

Write-Host "[8/9] Creating release ZIP files"
$OneFileStage = Join-Path $PackageRoot "onefile"
$OneDirStage = Join-Path $PackageRoot "onedir"
Reset-Stage $OneFileStage
Reset-Stage $OneDirStage
Copy-Item -LiteralPath $OneFile -Destination (Join-Path $OneFileStage "JVI.exe")
Copy-Item -LiteralPath (Join-Path $ProjectRoot "JVI-OneClick.cmd") -Destination $OneFileStage
Copy-Item -LiteralPath (Join-Path $ProjectRoot "packaging\README.txt") -Destination $OneFileStage
Copy-Item -Path (Join-Path $OneDir "*") -Destination $OneDirStage -Recurse
Copy-Item -LiteralPath (Join-Path $ProjectRoot "JVI-OneClick.cmd") -Destination $OneDirStage
Copy-Item -LiteralPath (Join-Path $ProjectRoot "packaging\README.txt") -Destination $OneDirStage

$OneFileZip = Join-Path $DistRoot "JVI-Windows-x64.zip"
$OneDirZip = Join-Path $DistRoot "JVI-Windows-x64-onedir.zip"
foreach ($archive in @($OneFileZip, $OneDirZip)) {
    if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
}
Compress-Archive -Path (Join-Path $OneFileStage "*") -DestinationPath $OneFileZip -CompressionLevel Optimal
Compress-Archive -Path (Join-Path $OneDirStage "*") -DestinationPath $OneDirZip -CompressionLevel Optimal

Write-Host "[9/9] Generating SHA-256 and summary"
$ChecksumFile = Join-Path $DistRoot "SHA256SUMS-Windows.txt"
$ChecksumLines = foreach ($archive in @($OneFileZip, $OneDirZip)) {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    "$hash  $([IO.Path]::GetFileName($archive))"
}
[IO.File]::WriteAllLines($ChecksumFile, $ChecksumLines, [Text.UTF8Encoding]::new($false))

Write-Host "PyInstaller: $(& $VenvPython -m PyInstaller --version)"
Write-Host "One-file: $OneFile"
Write-Host "One-folder: $OneDir"
Write-Host "Release ZIP: $OneFileZip"
Write-Host "Fallback ZIP: $OneDirZip"
Write-Host "Checksums: $ChecksumFile"
