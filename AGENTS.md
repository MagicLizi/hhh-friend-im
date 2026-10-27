# 写 HHH IM 插件的规矩（给 agent）

这个仓库是一个 HHH IM 插件。不管用哪个 agent 打开，都按这里的规矩写；`CLAUDE.md` 只是指到这里。

## 先读

1. 协议：[hhh-im-sdk/docs/protocol-v1.md](https://github.com/MagicLizi/hhh-im-sdk/blob/main/docs/protocol-v1.md)。每个方法的参数与结果都以它为准，
   Rust 类型在 `hhh-im-protocol`（`types`、`method`、`platform` 模块）。
2. 发版本规范：[hhh-im-sdk/docs/release.md](https://github.com/MagicLizi/hhh-im-sdk/blob/main/docs/release.md)。
3. 本仓库的 `src/main.rs`：最小可用的骨架（不用登录、一个示例群、发什么回什么），从它改起。

## 插件只做三件事

- **和平台说话**：登录、收消息、发消息、读资源，都在插件里。
- **翻成统一格式**：平台的消息、会话、人员、表情翻成协议的类型；平台特有的写法不要原样漏给 HHH。
- **声明能力与参数**：`initialize` 里如实声明平台能做什么（`platform`、`capabilities`）和要用户填什么（`settings`）；做不到的不声明。

聊天记录、凭据、配置都交给 HHH，插件自己不存：

- 凭据（登录后的令牌、会话材料）用 `credential/save` 交给 HHH；下次启动从 `session/open` 的 `credential` 拿回来。
- 同步位置随 `events/push` 的 `syncState` 交给 HHH（只推一次的平台必带）；下次从 `session/open` 的 `syncState` 接着推。
- 用户要填的参数在 `settings` 里声明，HHH 生成表单、保存、在 `session/open` 的 `settings` 里给你。
- 临时文件只放 `initialize` 给的 `tempDir`（随时可能被清空）。

Windows 上程序按窗口程序编（`src/main.rs` 开头的 `windows_subsystem`），HHH 拉起时不弹控制台窗口；标准输入输出照样能用，不要删。

iPhone / iPad 上 HHH 在 App 里跑插件的 WASM 组件（`wasm32-wasip2`，`scripts/pack-ios.sh` 打包）。同一份代码，平台差别只收在这几处，
改动要两边都编得过：标准输入输出（`src/wasi_stdio.rs`）、HTTP 客户端（`client::web`：原生是 reqwest，WASI 是 `client/src/web_wasi.rs`）、
按主机名连接（`client/src/wasi_net.rs`）、读写文件（`src/server/resources.rs` 里的小封装）；WASI 上不做局域网直连、tokio 用单线程运行时。
插件只看得见 `tempDir`，不能起子进程、不能开线程。

## 协议表达不了时

提给协议（在 [hhh-im-sdk](https://github.com/MagicLizi/hhh-im-sdk/issues) 提 issue，写清楚要什么、为什么所有 IM 都可能需要），
不要求 HHH 给自己开特例，也不在插件里绕路伪造协议没有的东西。HHH 的 IM 层不认识任何一家 IM，所有 IM 的界面与交互都一样。

## 清单 `hhh-im-provider.json`

| 字段 | 怎么填 |
|---|---|
| `id` | 插件编号：小写字母开头，只含 `a-z0-9-`，2–32 字符。**发布后不能改**（HHH 靠它认同一个插件，改了聊天记录不跟过去） |
| `name` | 给用户看的名字 |
| `version` | `主.次.修订`，每次发版本往上加 |
| `command` | 程序相对清单的路径；不写扩展名，打 Windows 包时自动指向 `.exe` |
| `args` | 启动参数（可选） |
| `os` | 支持的系统：`windows` / `macos` / `linux` / `ios`（iPhone / iPad，WASM 包） |
| `logo` | 标志文件（svg / png / jpg / webp，96 KB 以内） |
| `publisher`、`homepage` | 发布者、主页 |
| `imType` | 和别的插件是同一种 IM 时写成同一个值（同一种同一时间只用一个）；不写自成一类 |
| `source` | 更新来源（GitHub / GitLab / 网址），HHH 只从这里检查、下载新版本 |
| `minHost` | 不用自己写：打包工具按 `Cargo.lock` 里锁定的协议包写“需要的 IM SDK 版本”（hhh-im-sdk 0.10.0 起） |

## 改完必须

1. `cargo build --release` 通过。
2. 跑自检：`hhh-im-check <插件文件夹>/hhh-im-provider.json`，全部通过（没装：`cargo install --git https://github.com/MagicLizi/hhh-im-sdk --tag v0.14.0 hhh-im-protocol --features transport,package`）。
   开发时清单可以指向 `target/release` 里的程序，或先跑 `scripts/pack` 用 `dist/stage`。
3. 在 HHH 里试一遍：设置 → IM → 添加 IM → 文件夹，选 `dist/stage`（或你的插件文件夹），登录、收发消息都走一遍。

## 发版本

用「发版本」skill：步骤正本是私有中控仓库 `MagicLizi/hhh-release` 的 `RELEASING.md`，agent 拟好版本号和更新说明、和用户确认后一次发完。发布只在 hhh-release 里做；要出哪些系统写在 `.github/hhh-plugin.json`。

- `.github/workflows/hhh-plugin.yml`、`.github/hhh-ci/` 与发版 skill 由 hhh-release 统一维护、同步过来，不在这里改。
- 官方私钥只在 hhh-release 的 Secrets 里，**永远不进这个仓库**：不复制进来，不写进脚本或配置，也不贴进对话。
