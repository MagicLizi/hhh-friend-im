#!/usr/bin/env bash
# 装编 iPhone / iPad 版（wasm32-wasip2）用的 wasi-sdk，按这台机器的系统选包，WASI_SDK_PATH 写进 GITHUB_ENV。
# 本文件由 MagicLizi/hhh-release 统一维护（plugin-files/），插件仓库里不要直接改。
# 环境变量：WASI_SDK_VERSION 主版本号，如 34
set -euo pipefail
version="${WASI_SDK_VERSION:?没有 WASI_SDK_VERSION}"
case "$RUNNER_OS-$RUNNER_ARCH" in
    Linux-X64) host=x86_64-linux ;;
    Linux-ARM64) host=arm64-linux ;;
    macOS-ARM64) host=arm64-macos ;;
    macOS-X64) host=x86_64-macos ;;
    Windows-X64) host=x86_64-windows ;;
    *) echo "::error::wasi-sdk 没有 $RUNNER_OS-$RUNNER_ARCH 的包。"; exit 1 ;;
esac
name="wasi-sdk-${version}.0-${host}"
# 自己的机器上装一次留着用（几个仓库可能同时在装，各解压到自己的临时目录再挪过去）；GitHub 的机器每次都是新的。
root="$HOME/.hhh-wasi-sdk"
if [ ! -x "$root/$name/bin/clang" ] && [ ! -x "$root/$name/bin/clang.exe" ]; then
    mkdir -p "$root"
    work="$(mktemp -d "$root/.partial.XXXXXX")"
    curl -fsSL "https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${version}/${name}.tar.gz" \
        | tar -xz -C "$work"
    rm -rf "$root/$name"
    mv "$work/$name" "$root/$name"
    rm -rf "$work"
fi
path="$root/$name"
if command -v cygpath >/dev/null 2>&1; then
    path="$(cygpath -m "$path")"
fi
echo "WASI_SDK_PATH=$path" >> "$GITHUB_ENV"
echo "wasi-sdk：$path"
