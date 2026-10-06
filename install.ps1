param([string]$Instance)
$ErrorActionPreference = 'Stop'
$Version = '0.1.0-alpha.19'
$Repository = 'jianmosier/chat2local'
$NodeVersion = 'v24.21.0'
if ($env:OS -ne 'Windows_NT' -or [Environment]::OSVersion.Version.Major -lt 10) { throw 'Windows 10 or newer is required.' }
$Architecture = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
$Arch = switch ($Architecture.ToUpperInvariant()) { 'AMD64' { 'x64' }; 'ARM64' { 'arm64' }; default { throw 'Unsupported CPU architecture.' } }
$Base = Join-Path $env:LOCALAPPDATA 'Chat2Local\bootstrap'
[IO.Directory]::CreateDirectory($Base) | Out-Null
if ((Get-Item -LiteralPath $Base).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Bootstrap directory cannot be a link.' }
$Lock = Join-Path $Base '.bootstrap-lock'
if (Test-Path -LiteralPath $Lock) { throw 'Another bootstrap is active, or an interrupted lock needs review. No process was stopped.' }
New-Item -ItemType Directory -Path $Lock -ErrorAction Stop | Out-Null
$Stage = Join-Path $Base ('.download-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($Stage) | Out-Null
$OldPath = $env:PATH
$OldNpm = $env:CHAT2LOCAL_NPM_CLI
function Get-VerifiedDownload([string]$Url, [string]$Destination) {
    if (-not $Url.StartsWith('https://')) { throw 'HTTPS is required.' }
    & curl.exe --fail --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 5 --connect-timeout 20 --max-time 300 --max-filesize 150000000 $Url --output $Destination
    if ($LASTEXITCODE -ne 0) { throw 'Download did not complete. No downloaded program was launched.' }
}
try {
    Write-Host "[chat2local $Version] Preparing Windows/$Arch..."
    $Runtime = "node-$NodeVersion-win-$Arch"
    $RuntimeArchive = "$Runtime.zip"
    $Checksums = Join-Path $Stage 'node-checksums.txt'
    Get-VerifiedDownload "https://nodejs.org/dist/$NodeVersion/SHASUMS256.txt" $Checksums
    $Record = @(Get-Content -LiteralPath $Checksums | Where-Object { ($_ -split '\s+')[-1] -eq $RuntimeArchive })
    if ($Record.Count -ne 1) { throw 'Official runtime checksum not found.' }
    $Expected = ($Record[0] -split '\s+')[0]
    if ($Expected -notmatch '^[a-f0-9]{64}$') { throw 'Invalid runtime checksum.' }
    $RuntimeZip = Join-Path $Stage 'node.zip'
    Get-VerifiedDownload "https://nodejs.org/dist/$NodeVersion/$RuntimeArchive" $RuntimeZip
    if ((Get-FileHash -LiteralPath $RuntimeZip -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected) { throw 'Runtime checksum mismatch.' }
    Expand-Archive -LiteralPath $RuntimeZip -DestinationPath $Stage
    $Node = Join-Path $Stage "$Runtime\node.exe"
    $Release = "https://github.com/$Repository/releases/download/v$Version"
    $SourceName = "chat2local-source-v$Version.tar.gz"
    $SourceChecksum = Join-Path $Stage 'source.sha256'
    Get-VerifiedDownload "$Release/$SourceName.sha256" $SourceChecksum
    $Expected = ((Get-Content -LiteralPath $SourceChecksum -TotalCount 1) -split '\s+')[0]
    if ($Expected -notmatch '^[a-f0-9]{64}$') { throw 'Invalid source checksum.' }
    $Archive = Join-Path $Stage 'source.tar.gz'
    Get-VerifiedDownload "$Release/$SourceName" $Archive
    if ((Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected) { throw 'Source checksum mismatch.' }
    $Names = @(& tar.exe -tzf $Archive)
    if ($LASTEXITCODE -ne 0 -or $Names.Count -eq 0 -or @($Names | Where-Object { $_ -notmatch '^chat2local/' -or $_ -match '(^|/)\.\.(/|$)|\\' }).Count -gt 0) { throw 'Unsafe source archive.' }
    & tar.exe -xzf $Archive -C $Stage
    if ($LASTEXITCODE -ne 0) { throw 'Source extraction failed.' }
    $Source = Join-Path $Base "source-$Version"
    if (Test-Path -LiteralPath $Source) {
        if ((Get-Item -LiteralPath $Source).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Existing source directory is a link.' }
        & $Node (Join-Path $Stage 'chat2local\scripts\check-source.mjs') $Source (Join-Path $Stage 'chat2local\SOURCE-SHA256.json')
        if ($LASTEXITCODE -ne 0) { throw 'Existing source differs; it was not overwritten.' }
    } else { Move-Item -LiteralPath (Join-Path $Stage 'chat2local') -Destination $Source }
    $env:PATH = (Join-Path $Stage $Runtime) + ';' + $env:PATH
    $env:CHAT2LOCAL_NPM_CLI = Join-Path $Stage "$Runtime\node_modules\npm\bin\npm-cli.js"
    $Arguments = @('--use-env-proxy', (Join-Path $Source 'scripts\setup-selfhost.mjs'))
    if ($Instance) { $Arguments += @('--instance', $Instance) }
    & $Node @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'chat2local setup did not complete. See the message above; retained configuration was not reset.' }
} finally {
    $env:PATH = $OldPath
    $env:CHAT2LOCAL_NPM_CLI = $OldNpm
    Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Lock -Force -ErrorAction SilentlyContinue
}
