$ErrorActionPreference = 'Stop'

$toolsDir = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"
$version  = '__VERSION__'
$url64    = "https://github.com/SCGIS-Wales/dcert/releases/download/v$version/dcert-x86_64-pc-windows-msvc.zip"

$packageArgs = @{
  packageName    = 'dcert'
  unzipLocation  = $toolsDir
  url64bit       = $url64
  checksum64     = '__SHA256__'
  checksumType64 = 'sha256'
}

# Downloads the verified release zip and unzips dcert.exe / dcert-mcp.exe into
# $toolsDir. Chocolatey auto-generates PATH shims for the .exe files.
Install-ChocolateyZipPackage @packageArgs
