# 好友申请与批准

`core/src/friends.rs` 定义独立签名的申请信封：双方账号身份、来源群或好友链接令牌、申请编号，以及分别加密给双方账号钥匙的验证消息。消息最多 80 个 Unicode 字符，不作为聊天消息发送，不在服务器或日志存明文。客户端核对发送设备的历史签名身份；账号身份已变化时旧验证消息不可读。

服务端账号账本是关系事实来源。Pending 不产生会话；接收方 Accept 将申请状态、双方私聊签名链和钥匙封装放进同一事务。双向申请返回同一条待处理申请，不自动同意；重复操作按申请编号返回既有结果。Reject 仅接收方、Withdraw 仅发送方；终态不会被另一台设备覆盖。来源群成员、好友令牌或账号身份失效时申请过期。

通用宿主声明 `people.friendRequests`，调用 `contacts/requests` 的 list/send/resend/respond；首次调用后插件才发 `contacts/requestsChanged`，旧宿主不会收到新通知。插件以页大小 50 读取，通知只表示需要重读，重连后仍可查询权威状态；UI 后台每 30 秒、打开时每 5 秒及恢复焦点补查。已有好友走只读名片和既有私聊，`contacts/add` 不再允许绕过批准创建新关系。

新服务端 `Welcome.friend_requests=true`；旧服务端未声明时客户端报不支持，不退回直接建私聊。升级先备份、升级服务器（SQLite schema 3，保留旧好友和历史），再配套发布 SDK/宿主及插件。旧服务器拒绝新版库；恢复旧备份会丢失备份后的操作，不是无损降级。这里只描述顺序，不自动执行发布或部署。

验证：`core/src/friends.rs` 的加密测试、服务器 `tests/friend_approval.rs`、插件 `tests/scenarios/group_contacts.rs`。消息验收必须由对端收到并解密；仅发送成功不足以通过。局域网接收通道关闭时不确认送达，服务器继续补发，回归在 `client/src/lan.rs`。

## 本地联调与发布前提

当前清单固定的 SDK v0.18.0 尚未包含 `contacts/requests`。开发检查使用外置 Cargo 配置，把 `https://github.com/MagicLizi/hhh-im-sdk` 的 `hhh-im-protocol` 补丁指向本次 HHH 源码里的同名目录，再以 `cargo --config <配置路径> ...` 构建及测试；不要把本机绝对路径提交到清单。`scripts/test-group-contacts.py --sdk <目录>` 会为独立测试工程生成同等补丁。

正式 SDK 发布后须更新依赖标签与 Cargo.lock，并在没有本地补丁时重跑构建、自检和 CI，再提交插件 PR。当前源码完成不代表已能用旧 SDK 独立构建或已在正式服务启用。
