$ErrorActionPreference = 'Stop'

$toolsDir = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"

# Install-ChocolateyZipPackage records the unzipped files and Chocolatey removes
# the generated shims automatically on uninstall. Remove the extracted binaries
# explicitly as a safeguard.
foreach ($exe in @('dcert.exe', 'dcert-mcp.exe')) {
  $path = Join-Path $toolsDir $exe
  if (Test-Path $path) {
    Remove-Item $path -Force -ErrorAction SilentlyContinue
  }
}
