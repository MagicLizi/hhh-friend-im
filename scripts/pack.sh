#!/bin/sh
# 打包（macOS / Linux）：编译、把程序与清单放进 dist/stage、用 hhh-im-pack 打成 .hhhim 并写版本索引。
# 用法：scripts/pack.sh [--publish] [--sign-key <私钥文件>]（参数原样交给 hhh-im-pack）
#   --publish：打好后发到清单 source 写的仓库；令牌放环境变量 HHH_IM_PUBLISH_TOKEN（或 GITHUB_TOKEN / GITLAB_TOKEN），不写进任何文件。
# 目标按这台电脑（M 芯片 Mac 出 macos-arm64，Intel Mac 出 macos-x64，Linux 出 linux-x64 / linux-arm64）。
# hhh-im-pack 没装时：cargo install --git https://github.com/MagicLizi/hhh-im-sdk --tag v0.15.0 hhh-im-protocol --features transport,package
set -eu
cd "$(dirname "$0")/.."
cargo build --release
rm -rf dist/stage
mkdir -p dist/stage
cp hhh-im-provider.json logo.svg dist/stage/
cp target/release/friend-im dist/stage/
hhh-im-pack dist/stage --out dist --notes notes.md "$@"
