#requires -Version 5.1

<#
    构建 HistoryPortunus 发布候选。

    参数面从第一天就对齐 Diana 发布器的调用契约
    （`Publish-OneHistoryModule.ps1` 按 -Configuration / -OutputRoot / -HistoryVulcanPackageRoot 调用）。
    HistoryAurora 因为只收 -Configuration，补进发布登记当天就炸在这里——这个教训不必再吃一次。

    给了 OutputRoot 就只扁平交付内容，不碰 z-Publish：版本化目录与归档由发布器统一做，
    两边都做会让 history/ 出现同一版本的两份。
#>

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$OutputRoot,

    [string]$HistoryVulcanPackageRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$componentRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $componentRoot

$propsText = Get-Content -LiteralPath (Join-Path $componentRoot 'PortunusVersion.props') -Raw -Encoding UTF8
$versionMatch = [regex]::Match($propsText, '<HistoryPortunusVersion>(?<v>[^<]+)</HistoryPortunusVersion>')
if (-not $versionMatch.Success) {
    throw 'PortunusVersion.props does not declare HistoryPortunusVersion'
}
$version = $versionMatch.Groups['v'].Value

$manifestPath = Join-Path $componentRoot 'module.manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.version -ne $version) {
    throw "module.manifest.json ($($manifest.version)) 与 PortunusVersion.props ($version) 不一致"
}

$buildProperties = @('-p:NuGetAudit=false')
if (-not [string]::IsNullOrWhiteSpace($HistoryVulcanPackageRoot)) {
    $buildProperties += "-p:HistoryVulcanPackageRoot=$HistoryVulcanPackageRoot"
}
& dotnet build (Join-Path $repoRoot 'HistoryPortunus.sln') -c $Configuration --nologo @buildProperties
if ($LASTEXITCODE -ne 0) { throw "build failed with exit code $LASTEXITCODE" }

$output = Join-Path $componentRoot "bin\$Configuration\net8.0"
if (-not (Test-Path -LiteralPath $output)) { throw "build output missing: $output" }

$stage = Join-Path ([System.IO.Path]::GetTempPath()) ("HistoryPortunus-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage -Force | Out-Null
try {
    foreach ($name in @('HistoryPortunus.dll', 'HistoryPortunus.xml', 'module.manifest.json')) {
        $source = Join-Path $output $name
        if (-not (Test-Path -LiteralPath $source)) { throw "expected artifact missing: $source" }
        Copy-Item -LiteralPath $source -Destination (Join-Path $stage $name) -Force
    }

    # SHA256SUMS 覆盖包内全部有效载荷，排除自身与 history/。
    $lines = Get-ChildItem -LiteralPath $stage -Recurse -File | ForEach-Object {
        $relative = $_.FullName.Substring($stage.Length + 1).Replace('\', '/')
        if ($relative -eq 'SHA256SUMS' -or $relative -like 'history/*') { return }
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
        "$hash  $relative"
    } | Where-Object { $_ }

    # 必须无 BOM：宿主 RuntimeModuleDiscoverySource 按 ^[0-9A-Fa-f]{64}  <路径>$ 逐行匹配，
    # BOM 会让首行匹配失败，整个包被判 invalid-checksum 而静默跳过。
    # Set-Content -Encoding utf8 在 Windows PowerShell 5.1 下写的是带 BOM 的 UTF-8，不能用。
    [System.IO.File]::WriteAllLines(
        (Join-Path $stage 'SHA256SUMS'),
        [string[]]$lines,
        (New-Object System.Text.UTF8Encoding $false))

    if (-not [string]::IsNullOrWhiteSpace($OutputRoot)) {
        $staged = [IO.Path]::GetFullPath($OutputRoot)
        New-Item -ItemType Directory -Path $staged -Force | Out-Null
        Get-ChildItem -LiteralPath $staged -Force | Remove-Item -Recurse -Force
        Copy-Item -Path (Join-Path $stage '*') -Destination $staged -Recurse -Force
        Write-Host "HistoryPortunus $version staged for the publisher: $staged"
        return
    }

    $publishRoot = Join-Path $repoRoot 'z-Publish'
    $historyRoot = Join-Path $publishRoot 'history'
    New-Item -ItemType Directory -Path $historyRoot -Force | Out-Null
    Get-ChildItem -LiteralPath $publishRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'HistoryPortunus-v*' -and $_.Name -ne "HistoryPortunus-v$version" } |
        ForEach-Object {
            $archive = Join-Path $historyRoot $_.Name
            if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Recurse -Force }
            Move-Item -LiteralPath $_.FullName -Destination $archive
        }

    $candidate = Join-Path $publishRoot "HistoryPortunus-v$version"
    if (Test-Path -LiteralPath $candidate) { Remove-Item -LiteralPath $candidate -Recurse -Force }
    New-Item -ItemType Directory -Path $candidate -Force | Out-Null
    Copy-Item -Path (Join-Path $stage '*') -Destination $candidate -Recurse -Force

    Write-Host "HistoryPortunus $version packaged: $candidate"
}
finally {
    if (Test-Path -LiteralPath $stage) {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
}
