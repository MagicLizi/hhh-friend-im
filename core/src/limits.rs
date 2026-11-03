//! 两边共用的上限。服务器按这些值拒绝请求；客户端照着这些值提前拦住，不白跑一趟。
//! 任何 Cindy 账号都能登录服务器，所以每一项都必须有上限，防止被刷（契约 §8）。

/// 每个账号的电脑（不含恢复密钥）：一个人 10 台电脑足够，再多多半是被刷。
pub const MAX_DEVICES: usize = 10;
/// 单个文件明文上限：100 MiB。
pub const FILE_PLAIN_MAX: u64 = 100 * 1024 * 1024;
/// 转交频率：每台设备每秒 200 帧、每分钟 6000 帧（对账一帧很小，大文件按 512 KiB 分帧）。
pub const RELAY_PER_SECOND: u32 = 200;
/// 见 [`RELAY_PER_SECOND`]。
pub const RELAY_PER_MINUTE: u32 = 6000;
/// 一条连接排队等发的转交帧合计多少字节：到了就回“不在线”，慢设备拖不垮服务器内存。
pub const RELAY_QUEUE_BYTES: usize = 32 * 1024 * 1024;
/// 群人数。
pub const GROUP_MAX_MEMBERS: usize = crate::conv::GROUP_MAX_MEMBERS;
/// 每个账号同时进行的批准请求。
pub const JOIN_CONCURRENT: usize = 1;
/// 每个账号每小时最多发起的批准请求。
pub const JOIN_PER_HOUR: u32 = 10;
/// 一次批准最多输错几次（契约 S21）。
pub const JOIN_MAX_ATTEMPTS: u32 = 5;
/// 批准请求多久没处理自动作废（契约 S20）：10 分钟。
pub const JOIN_TTL_MS: i64 = 10 * 60 * 1000;
/// 群邀请链接默认有效期：7 天。
pub const INVITE_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// 每台电脑的推送队列：满了服务器断开它，让它按序号补拉，慢电脑拖不垮服务器内存。
pub const PUSH_QUEUE: usize = 1000;
/// WebSocket 每一帧（请求体）上限：1 MiB。
pub const FRAME_MAX_BYTES: usize = 1024 * 1024;
/// 补拉每批最多几条。
pub const SYNC_PAGE_MAX: u32 = 500;
/// 补拉一次回执的大致字节上限：到了就分页（至少给一条）。
pub const RESPONSE_SOFT_MAX_BYTES: usize = 4 * 1024 * 1024;
/// 客户端接收单帧的上限：回执按 [`RESPONSE_SOFT_MAX_BYTES`] 分页，再留出单条最大消息和 JSON 的余量。
pub const CLIENT_FRAME_MAX_BYTES: usize = 16 * 1024 * 1024;
/// 一个请求里会话签名链最多几环（移出 + 换代这类批量操作用不了几环）。
pub const CONV_LINKS_PER_REQUEST: usize = 8;
/// 一个请求里账号签名链最多几环。
pub const ACCOUNT_LINKS_PER_REQUEST: usize = 4;
/// 一次查资料最多几个账号。
pub const PROFILES_PER_REQUEST: usize = 256;
