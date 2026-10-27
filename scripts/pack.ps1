# 打包（Windows）：编译、把程序与清单放进 dist/stage、用 hhh-im-pack 打成 .hhhim 并写版本索引。
# 用法：powershell -File scripts/pack.ps1 [-Publish] [-SignKey <私钥文件>]
#   -Publish：打好后发到清单 source 写的仓库；令牌放环境变量 HHH_IM_PUBLISH_TOKEN（或 GITHUB_TOKEN / GITLAB_TOKEN），不写进任何文件。
#   -SignKey：用官方私钥给版本索引签名（Cindy IM 是官方插件，HHH 只认签过的版本）。
# hhh-im-pack 没装时：cargo install --git https://github.com/MagicLizi/hhh-im-sdk --tag v0.14.0 hhh-im-protocol --features transport,package
param([switch]$Publish, [string]$SignKey)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
cargo build --release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$stage = Join-Path $root 'dist/stage'
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item hhh-im-provider.json, logo.svg $stage
Copy-Item target/release/friend-im.exe $stage
# notes.md 保留全部历史；包索引只放当前版本的说明，不能把整份历史塞进 2000 字预算。
$manifest = Get-Content -LiteralPath (Join-Path $root 'hhh-im-provider.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$notes = Get-Content -LiteralPath (Join-Path $root 'notes.md') -Raw -Encoding UTF8
$pattern = '(?ms)^###\s+' + [regex]::Escape($manifest.version) + '\s*\r?\n(.*?)(?=^###\s|\z)'
$section = [regex]::Match($notes, $pattern)
if (-not $section.Success) { throw "notes.md 缺少当前版本的更新说明" }
$notesFile = Join-Path $root 'dist/pack-notes.md'
[System.IO.File]::WriteAllText($notesFile, $section.Groups[1].Value.Trim(), [System.Text.UTF8Encoding]::new($false))
$pack = @($stage, '--target', 'windows-x64', '--out', (Join-Path $root 'dist'), '--notes', $notesFile)
if ($SignKey) { $pack += @('--sign-key', $SignKey) }
if ($Publish) { $pack += '--publish' }
hhh-im-pack @pack
exit $LASTEXITCODE
