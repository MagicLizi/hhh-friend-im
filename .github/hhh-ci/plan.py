"""读插件仓库的 CI 配置与清单，算出这次要编哪些系统（给 hhh-plugin.yml 的 plan 一步用）。

本文件由 MagicLizi/hhh-release 统一维护（plugin-files/），插件仓库里不要直接改；改正本后同步过来。

配置在插件仓库的 .github/hhh-plugin.json：
  targets        发布时要出的系统（必填）：windows-x64 / macos-arm64 / macos-x64 / linux-x64 / linux-arm64 / wasm32-wasip2
  checkTargets   平时检查（PR、推 main）只编哪些系统；不写同 targets（私有仓库按分钟计费时用它省 Mac 机器）
  cargoArgs      cargo build 额外参数，如 ["--bin", "friend-im"]
  binary         程序名；不写用清单的 command
  lint           true 时跑 cargo fmt --check 与 cargo clippy --all-targets（零警告）
  selfCheckArgs  hhh-im-check 额外参数，如 ["--mock"]
  prepare        某个系统编译前先跑的命令，如 {"windows-x64": "python scripts/prepare-build-tools.py"}
  dropTargets    这次发布有意不再出的系统（不写时新版本的系统不能比上一个正式版本少）

自己的机器：插件仓库的 Actions 变量 HHH_RUNNER_WINDOWS / HHH_RUNNER_MACOS 写自托管 runner 的标签时，Windows 版在
带这个标签的 Windows 机器上编，Mac 版与 iPhone 版在 Mac 机器上编，没写用 GitHub 的机器；Linux 版总在 GitHub 的机器上编。
公开仓库要先把外人 PR 设成每次都要批准（见 README）：外人 PR 能改本文件与工作流，挡住它的只有仓库设置，不是这里的代码。

环境变量 HHH_RELEASE=true 表示这是一次发布（建草稿），否则只是检查。结果写进 GITHUB_OUTPUT。
"""
import json
import os
import re
import sys
from pathlib import Path

# 系统 → (GitHub 机器, Rust 目标, 能不能在这台机器上直接运行, 清单 os 里要写的值, 程序扩展名, 可以改在哪种自己的机器上编)
TARGETS = {
    "windows-x64": ("windows-latest", "x86_64-pc-windows-msvc", True, "windows", ".exe", "windows"),
    "macos-arm64": ("macos-latest", "aarch64-apple-darwin", True, "macos", "", "macos"),
    "macos-x64": ("macos-latest", "x86_64-apple-darwin", False, "macos", "", "macos"),
    "linux-x64": ("ubuntu-latest", "x86_64-unknown-linux-gnu", True, "linux", "", None),
    "linux-arm64": ("ubuntu-24.04-arm", "aarch64-unknown-linux-gnu", True, "linux", "", None),
    "wasm32-wasip2": ("ubuntu-latest", "wasm32-wasip2", False, "ios", ".wasm", "macos"),
}
CONFIG = Path(".github/hhh-plugin.json")
MANIFEST = Path("hhh-im-provider.json")
KNOWN_KEYS = {"targets", "checkTargets", "cargoArgs", "binary", "lint", "selfCheckArgs", "prepare", "dropTargets"}
# 自己的机器 → 指定它的 Actions 变量（值是自托管 runner 的标签）。
SELF_HOSTED = {"windows": "HHH_RUNNER_WINDOWS", "macos": "HHH_RUNNER_MACOS"}


def fail(message: str) -> None:
    print(f"::error::{message}")
    sys.exit(1)


def runners() -> dict[str, list[str]]:
    """设了变量的系统 → 自己机器的 runs-on。"""
    chosen = {}
    for os_name, variable in SELF_HOSTED.items():
        label = os.environ.get(variable, "").strip()
        if not label:
            continue
        if not re.fullmatch(r"[A-Za-z0-9._-]+", label):
            fail(f"Actions 变量 {variable} 要写成一个自托管 runner 标签（字母、数字、. _ -），现在是 {label!r}。")
        chosen[os_name] = ["self-hosted", label]
    return chosen


def target_list(config: dict, key: str) -> list[str]:
    value = config.get(key)
    if not isinstance(value, list) or not value or not all(isinstance(t, str) for t in value):
        fail(f"{CONFIG} 的 {key} 要写成非空的系统列表。")
    unknown = [t for t in value if t not in TARGETS]
    if unknown:
        fail(f"{CONFIG} 的 {key} 里有不认识的系统：{', '.join(unknown)}（认识的：{', '.join(TARGETS)}）。")
    if len(set(value)) != len(value):
        fail(f"{CONFIG} 的 {key} 里有重复的系统。")
    return value


def main() -> None:
    if not CONFIG.is_file():
        fail(f"缺少 {CONFIG}：写明这个插件要出哪些系统（见 hhh-release 的 README）。")
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    extra = set(config) - KNOWN_KEYS
    if extra:
        fail(f"{CONFIG} 里有不认识的字段：{', '.join(sorted(extra))}。")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    targets = target_list(config, "targets")
    check_targets = target_list(config, "checkTargets") if "checkTargets" in config else targets
    outside = [t for t in check_targets if t not in targets]
    if outside:
        fail(f"checkTargets 里的 {', '.join(outside)} 不在 targets 里。")
    drop = config.get("dropTargets", [])
    if not isinstance(drop, list) or not all(t in TARGETS for t in drop):
        fail(f"{CONFIG} 的 dropTargets 要写成系统列表。")

    declared = set(manifest.get("os") or [])
    for target in targets:
        need = TARGETS[target][3]
        if need not in declared:
            fail(f"要出 {target} 的包，但清单 {MANIFEST} 的 os 没写 {need}。")

    version = manifest.get("version", "")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        fail(f"清单版本号 {version!r} 不是 主.次.修订。")
    command = manifest.get("command", "")
    binary = config.get("binary") or Path(command).name
    if not binary or Path(binary).suffix in (".exe", ".wasm"):
        fail("程序名要写成不带扩展名的名字（清单 command 或配置 binary）。")

    lock = Path("Cargo.lock").read_text(encoding="utf-8") if Path("Cargo.lock").is_file() else ""
    found = re.search(r'name = "hhh-im-protocol"\nversion = "[^"]+"\nsource = "git\+https://github\.com/MagicLizi/hhh-im-sdk\?tag=([^#"]+)', lock)
    if not found:
        fail("Cargo.lock 里找不到从 hhh-im-sdk 正式标签取的 hhh-im-protocol（发布只认正式标签，不认分支、提交或本机路径）。")
    sdk_tag = found.group(1)

    release = os.environ.get("HHH_RELEASE") == "true"
    chosen = targets if release else check_targets
    natives = [t for t in chosen if TARGETS[t][2]]
    lint_on = natives[0] if config.get("lint") and natives else None
    prepare = config.get("prepare", {})
    own = runners()
    include = []
    for target in chosen:
        runner, triple, native, _, ext, host = TARGETS[target]
        include.append({
            "target": target,
            "runner": own.get(host, runner),
            "rust_target": triple,
            "native": native,
            "ext": ext,
            "lint": target == lint_on,
            "prepare": prepare.get(target, ""),
        })

    outputs = {
        "matrix": json.dumps({"include": include}, ensure_ascii=False),
        "targets": " ".join(chosen),
        "drop_targets": " ".join(drop),
        "id": manifest.get("id", ""),
        "version": version,
        "binary": binary,
        "logo": manifest.get("logo", ""),
        "cargo_args": " ".join(config.get("cargoArgs", [])),
        "self_check_args": " ".join(config.get("selfCheckArgs", [])),
        "sdk_tag": sdk_tag,
        "release": "true" if release else "false",
    }
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:
        for key, value in outputs.items():
            out.write(f"{key}={value}\n")
    mode = "发布（建草稿）" if release else "检查"
    print(f"{manifest.get('id')} {version}：{mode}，系统 {' '.join(chosen)}，SDK {sdk_tag}")


if __name__ == "__main__":
    main()
