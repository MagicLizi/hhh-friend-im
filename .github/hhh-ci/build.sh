#!/usr/bin/env bash
# 按一个系统编译插件，把清单、标志与程序放进 dist/stage-<系统>/（之后由 assemble.sh 统一打包）。
# 编译要的环境由前一步 prepare.sh 写好。
# 本文件由 MagicLizi/hhh-release 统一维护（plugin-files/），插件仓库里不要直接改。
# 环境变量（由 hhh-plugin.yml 按 plan 的结果给）：
#   HHH_TARGET 系统  HHH_RUST_TARGET Rust 目标  HHH_EXT 程序扩展名  HHH_BINARY 程序名
#   HHH_LOGO 清单里的标志路径  HHH_CARGO_ARGS cargo build 额外参数
set -euo pipefail
target="$HHH_TARGET"
triple="$HHH_RUST_TARGET"

# 这次编进去的包（cargo 的 JSON 消息），放 target/ 里：不进上传的 dist/，Windows 上也不用换路径写法。
mkdir -p target
units="target/hhh-build-units-$target.json"
# shellcheck disable=SC2086 # 额外参数按空格分开
cargo build --release --locked --target "$triple" ${HHH_CARGO_ARGS:-} --message-format=json-render-diagnostics > "$units"

# iPhone / iPad 版联网只能用 SDK 的 hhh-im-net：reqwest 在 wasm32 上只有浏览器版本，iPhone 上的 HHH 跑不了
# （简单用法可能编得过，运行时才失败，所以按这次实际编进去的包查）。
if [ "$triple" = wasm32-wasip2 ]; then
    if ! python3 - "$units" <<'PY'
import json, sys
built = set()
for line in open(sys.argv[1], encoding="utf-8"):
    if line.startswith("{"):
        message = json.loads(line)
        if message.get("reason") == "compiler-artifact":
            built.add(message["target"]["name"])
sys.exit(1 if "reqwest" in built else 0)
PY
    then
        echo "::error::iPhone 版（wasm32-wasip2）里编进了 reqwest：它在 wasm32 上只有浏览器版本，iPhone 上的 HHH 跑不了。联网改用 SDK 的 hhh-im-net（电脑上它就是 reqwest，代码里把 reqwest:: 换成 hhh_im_net::），见 hhh-im-sdk 的 README。"
        echo "谁带进来的 reqwest："
        cargo tree --locked --target "$triple" -e normal -i reqwest 2>/dev/null || true
        exit 1
    fi
fi

stage="dist/stage-$target"
rm -rf "$stage"
mkdir -p "$stage"
cp hhh-im-provider.json "$stage/"
if [ -n "${HHH_LOGO:-}" ]; then
    mkdir -p "$stage/$(dirname "$HHH_LOGO")"
    cp "$HHH_LOGO" "$stage/$HHH_LOGO"
fi
cp "target/$triple/release/$HHH_BINARY$HHH_EXT" "$stage/"
echo "已放进 ${stage}："
ls -la "$stage"
