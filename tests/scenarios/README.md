# 群成员名片端到端测试

`group_contacts.rs` 复用服务器仓库的测试签发方、临时服务和插件宿主，使用独立测试账号，不访问线上服务或真实联系人。覆盖只读查关系、群成员列表、自己/群外成员拒绝、并发添加复用、消息发送、离群拒绝。

在插件根目录执行（路径按实际位置填写）：

```sh
python scripts/test-group-contacts.py --server ../hhh-friend-im-server --server-ref origin/main --sdk ../hhh/hhh-im-protocol --out ../friend-contacts-check
```

需要包含成员名片能力的 HHH SDK 源码。脚本将指定服务器提交归档到测试目录，使用任务插件和 SDK 的本地依赖；不会修改服务器工作区，也不部署服务。测试目录可保留复用 Cargo 缓存。
