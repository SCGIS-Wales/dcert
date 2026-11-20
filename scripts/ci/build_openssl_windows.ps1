# Build the pinned OpenSSL (scripts/openssl_floor.yaml, windows_source) as
# static libraries for the Windows release build, and export the variables
# openssl-sys needs. Run from the repository root in an MSVC developer
# environment (ilammy/msvc-dev-cmd) with Perl and NASM on PATH.
#
# Why not the `vendored` feature: openssl-src ships only the 3.6 and 4.0
# branches, and openssl-sys 0.9 cannot select 4.0. Building the official 3.5 LTS
# source ourselves keeps the Windows binary on a supported branch.
#
# Parameters: -Prefix is the install directory (restored from a cache when it
# already holds a build).
param(
    [Parameter(Mandatory = $true)][string]$Prefix
)
$ErrorActionPreference = "Stop"

function Invoke-Checked([scriptblock]$Command) {
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "command failed with exit code ${LASTEXITCODE}: $Command" }
}

$version = (python scripts/ci/openssl_pin.py version).Trim()
$url = (python scripts/ci/openssl_pin.py url).Trim()
$sha256 = (python scripts/ci/openssl_pin.py sha256).Trim()

if (-not (Test-Path (Join-Path $Prefix "lib/libcrypto.lib"))) {
    $work = Join-Path $env:RUNNER_TEMP "openssl-src"
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $archive = Join-Path $work "openssl-$version.tar.gz"

    Write-Host "Downloading OpenSSL $version"
    Invoke-WebRequest -Uri $url -OutFile $archive

    # Step 1: verify the checksum pinned in the repository. Next: extract.
    $actual = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()
    if ($actual -ne $sha256) {
        throw "SHA256 mismatch for $url`n expected $sha256`n actual   $actual"
    }

    Invoke-Checked { tar -xzf $archive -C $work }
    Push-Location (Join-Path $work "openssl-$version")
    try {
        # Step 2: static, no tests or docs; the legacy provider matches the
        # `legacy` feature the vendored build had. Next: build and install.
        Invoke-Checked {
            perl Configure VC-WIN64A no-shared no-tests no-docs enable-legacy `
                "--prefix=$Prefix" "--openssldir=$Prefix\ssl"
        }
        Invoke-Checked { nmake /S }
        Invoke-Checked { nmake /S install_sw }
    } finally {
        Pop-Location
    }
}

if (-not (Test-Path (Join-Path $Prefix "lib/libcrypto.lib"))) {
    throw "OpenSSL build produced no libcrypto.lib under $Prefix"
}

# Export for later steps. openssl-sys links the static libraries.
"OPENSSL_DIR=$Prefix" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
"OPENSSL_STATIC=1" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8
Write-Host "OpenSSL $version ready in $Prefix"
