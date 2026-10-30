# 群成员名片端到端测试

`group_contacts.rs` 复用服务器仓库的测试签发方、临时服务和插件宿主，使用独立测试账号，不访问线上服务或真实联系人。覆盖只读查关系、群成员列表、自己/群外成员拒绝、并发申请幂等、对方批准、重连与双向消息实际接收解密、离群拒绝。

在插件根目录执行（路径按实际位置填写）：

```sh
python scripts/test-group-contacts.py --server ../hhh-friend-im-server --server-ref origin/main --sdk ../hhh/hhh-im-protocol --out ../friend-contacts-check
```

需要包含 `contacts/requests` 的 HHH SDK 和好友批准服务端源码。`--server-working-tree` 可在新的输出目录测试尚未提交的服务器改动；不传时归档指定提交。脚本使用任务插件和 SDK 的本地依赖，不修改服务器工作区，不部署服务。

Windows 双桌面夹具加 `--desktop-host <HHH源码目录>`，生成并构建 `approval-desktop` 示例。`desktop_approval.rs` 只创建临时签发方和服务器，给两个桌面分配独立设备，以宿主隔离凭据 API 写入测试凭据；恢复密钥不输出。受控过期与冷却只修改临时数据库，不改系统时钟。退出写入 ready 文件同名 `.stop`。

在 HHH 任务目录用构建工具包裹上面的命令，再执行 `node hhh-friend/frontend/tests/browser/im-friend-approval-desktop.mjs --fixture <approval-desktop.exe> --release <本地签名测试包目录> --public-key <测试公钥>`；`--links` 单独补验好友链接、列表重申与已有好友历史。测试包只能使用任务测试签名，不使用生产私钥。视频、截图和结果写入本任务 evidence，结束关闭两个桌面和临时服务。
