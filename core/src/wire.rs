//! 插件（经客户端库）和服务器之间的格式。全部定义在这里，两边按同一个版本编译，保证对得上。
//!
//! 每台电脑一条 WebSocket 长连接，每一帧一个 JSON（二进制字段是 base64url）：
//!
//! 1. 连上后服务器先发 `{"t":"challenge",...}`（一次性随机数）。
//! 2. 客户端的第一个请求必须是 `hello`：带登录方式和对随机数的签名（证明电脑私钥在手里）。
//! 3. 之后客户端发 `{"id":n,"req":{"op":...}}`，服务器回 `{"t":"res","id":n,"res":{"op":...}}`
//!    或 `{"t":"err","id":n,"err":{"code":...,"message":...}}`。
//! 4. 服务器随时可能主动推送 `{"t":"push","push":{"kind":...}}`。
//!
//! 文件内容不走 WebSocket，按段走 HTTPS（`PUT` / `HEAD` / `GET /v1/files/{编号}`，带登录凭证）。
//!
//! 同步：服务器给每条消息、撤回、会话签名链变化、钥匙封装、账号签名链变化一个全局递增的日志序号。
//! 电脑在线时服务器直接推；重连后带上次的序号补拉（[`Request::Sync`]），不漏不重。

use serde::{Deserialize, Serialize};

use crate::account::AccountLink;
use crate::bytes::{Bytes, Fixed};
use crate::conv::{ConvKind, ConvLink};
use crate::crypto::{self, Sealed, ctx};
use crate::error::Result;
use crate::ids::{ConvId, DeviceId, FileId, InviteId, MsgId, RequestId, Uid};
use crate::keys::{DevicePublic, DeviceSecret};
use crate::message::Envelope;
use crate::reading::{ReadingEnvelope, StoredReading};

/// 接口版本。
pub const PROTOCOL_VERSION: u32 = 1;

/// 客户端发的一帧。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientFrame {
    /// 请求编号，回执带同一个编号。
    pub id: u64,
    /// 请求。
    pub req: Request,
}

/// 服务器发的一帧。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ServerFrame {
    /// 连上后的第一帧：一次性随机数。
    Challenge {
        /// 服务器的接口版本。
        protocol: u32,
        /// 一次性随机数，`hello` 里要签它。
        nonce: Fixed<32>,
        /// 服务器时间（毫秒）。
        server_time_ms: i64,
    },
    /// 成功的回执。
    Res {
        /// 请求编号。
        id: u64,
        /// 结果。
        res: Response,
    },
    /// 失败的回执。
    Err {
        /// 请求编号。
        id: u64,
        /// 错误。
        err: WireError,
    },
    /// 服务器主动推送。
    Push {
        /// 推送内容。
        push: Push,
    },
}

/// `hello` 的登录方式。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HelloAuth {
    /// Cindy 身份凭证：每台电脑只在第一次连接时交一次，服务器核对后发自己的登录凭证。
    Cindy {
        /// Cindy access token。
        token: String,
    },
    /// 服务器之前发的登录凭证。
    Session {
        /// 登录凭证。
        token: Bytes,
    },
}

/// 登录设备的类别。只用于设备列表和批准提示，不参与密钥计算。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    #[default]
    Computer,
    Mobile,
    Unknown,
}

impl DeviceKind {
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Computer | Self::Unknown)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Computer => "电脑",
            Self::Mobile => "手机或平板",
            Self::Unknown => "设备",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Computer => "computer",
            Self::Mobile => "mobile",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value {
            "computer" => Self::Computer,
            "mobile" => Self::Mobile,
            _ => Self::Unknown,
        }
    }
}

/// `hello` 里对随机数的签名内容。
fn hello_message(nonce: &Fixed<32>, device: &DevicePublic) -> Vec<u8> {
    crypto::frame(&[&nonce.0, &device.to_bytes()])
}

/// 客户端：对服务器的随机数签名。
pub fn sign_hello(secret: &DeviceSecret, nonce: &Fixed<32>) -> Fixed<64> {
    secret.sign(ctx::HELLO, &hello_message(nonce, &secret.public()))
}

/// 服务器：核对 `hello` 的签名。
pub fn check_hello(device: &DevicePublic, nonce: &Fixed<32>, sig: &Fixed<64>) -> Result<()> {
    device.verify(ctx::HELLO, &hello_message(nonce, device), sig)
}

/// 封装给某台电脑的一份账号钥匙种子。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceKeyBox {
    /// 收件电脑（或恢复密钥）。
    pub device: DeviceId,
    /// 封装结果。
    pub sealed: Sealed,
}

/// 账号钥匙某一代：给每台电脑和恢复密钥的封装，加上旧钥匙链。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountKeyBundle {
    /// 第几代。
    pub generation: u32,
    /// 封装。
    pub boxes: Vec<DeviceKeyBox>,
    /// 用这一代加密的上一代种子（第一代没有）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<Bytes>,
}

/// 封装给某个成员账号钥匙的一份会话钥匙种子。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberKeyBox {
    /// 成员。
    pub uid: Uid,
    /// 成员账号的重置轮次。
    pub account_epoch: u32,
    /// 成员账号钥匙的代数。
    pub account_generation: u32,
    /// 封装结果。
    pub sealed: Sealed,
}

/// 会话钥匙某一代：给成员的封装，加上旧钥匙链。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvKeyBundle {
    /// 第几代。
    pub generation: u32,
    /// 封装。
    pub boxes: Vec<MemberKeyBox>,
    /// 用这一代加密的上一代种子。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<Bytes>,
}

/// 群邀请链接对应的会话种子（用链接里的钥匙包起来，服务器解不开）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteSeed {
    /// 邀请编号。
    pub invite: InviteId,
    /// 包起来的是第几代。
    pub generation: u32,
    /// 包起来的种子。
    pub seed: Bytes,
}

/// 请求。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Submit an encrypted, signed request; never creates a conversation.
    FriendRequestSend {
        envelope: crate::friends::FriendRequestEnvelope,
    },
    FriendRequests {
        before: Option<u64>,
        limit: u32,
        incoming: bool,
        peer: Option<Uid>,
    },
    FriendRequestGet {
        request: RequestId,
    },
    FriendRequestAccept {
        request: RequestId,
        link: ConvLink,
        keys: ConvKeyBundle,
    },
    FriendRequestReject {
        request: RequestId,
    },
    FriendRequestWithdraw {
        request: RequestId,
    },
    /// 第一个请求：登录。
    Hello {
        /// 客户端的接口版本。
        protocol: u32,
        /// 登录方式。
        auth: HelloAuth,
        /// 这台电脑的公钥。
        device: DevicePublic,
        /// 电脑名。
        name: String,
        /// 设备类别；旧客户端没有这个字段时按电脑处理。
        #[serde(default, skip_serializing_if = "DeviceKind::is_unknown")]
        kind: DeviceKind,
        /// 对随机数的签名。
        sig: Fixed<64>,
    },
    /// 取某账号的签名链（`epoch` 为空取当前一轮；只取序号大于 `after` 的环）。
    GetChain {
        /// 账号。
        uid: Uid,
        /// 重置轮次。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        epoch: Option<u32>,
        /// 从哪一环之后取。
        #[serde(default)]
        after: u64,
    },
    /// 开通：第一台电脑提交第一环和账号钥匙第一代。
    Provision {
        /// 第一环。
        eldest: AccountLink,
        /// 账号钥匙第一代。
        keys: AccountKeyBundle,
    },
    /// 接账号签名链（移除电脑、换代、换恢复密钥、退出登录）；有换代时带新一代的封装。
    AppendAccount {
        /// 新的环。
        links: Vec<AccountLink>,
        /// 新一代账号钥匙。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        keys: Option<AccountKeyBundle>,
    },
    /// 重置账号（契约 S7）：新的一轮从第一环开始，自动退出所有群。
    Reset {
        /// 新一轮的第一环。
        eldest: AccountLink,
        /// 新一轮账号钥匙第一代。
        keys: AccountKeyBundle,
    },
    /// 取封装给这台电脑的账号钥匙（当前一轮的全部代）和旧钥匙链。
    GetAccountKeys,
    /// 新电脑用恢复密钥加入前：取封装给恢复密钥的账号钥匙（只有恢复密钥打得开）。
    GetRecoveryKeys,
    /// 列出本账号的电脑。
    ListDevices,
    /// 新电脑：发起批准请求（SPAKE2 第一步）。
    JoinStart {
        /// SPAKE2 第一步的消息。
        pake: Bytes,
        /// 新电脑的证明（[`crate::account::device_proof`]），旧电脑签“加电脑”时原样放进去。
        proof: Fixed<64>,
    },
    /// 新电脑：上一次旧电脑输错了，用新的第一步再试一次（计一次错）。
    JoinRetry {
        /// 批准请求。
        request: RequestId,
        /// 新的第一步消息。
        pake: Bytes,
    },
    /// 新电脑：核对过旧电脑的确认码，回自己的确认码。
    JoinConfirm {
        /// 批准请求。
        request: RequestId,
        /// 第几次尝试。
        attempt: u32,
        /// 确认码。
        confirm: Fixed<32>,
    },
    /// 新电脑：不等了（改用恢复密钥或关掉）。
    JoinCancel {
        /// 批准请求。
        request: RequestId,
    },
    /// 旧电脑：用户输入 4 个词后回应。
    JoinRespond {
        /// 批准请求。
        request: RequestId,
        /// 第几次尝试。
        attempt: u32,
        /// SPAKE2 回应。
        pake: Bytes,
        /// 确认码。
        confirm: Fixed<32>,
    },
    /// 旧电脑：确认码对上后批准：签“加电脑”并把账号钥匙封装给新电脑，一个请求提交。
    JoinApprove {
        /// 批准请求。
        request: RequestId,
        /// “加电脑”这一环。
        link: AccountLink,
        /// 封装给新电脑的账号钥匙当前一代。
        keys: AccountKeyBundle,
    },
    /// 旧电脑：拒绝。
    JoinReject {
        /// 批准请求。
        request: RequestId,
    },
    /// 列出待处理的批准请求（卡片上的问题行）。
    ListJoinRequests,
    /// 新电脑：用恢复密钥签“加电脑”加入（契约 S3）。
    JoinWithRecovery {
        /// “加电脑”这一环（恢复密钥签）。
        link: AccountLink,
        /// 封装给新电脑自己的账号钥匙当前一代。
        keys: AccountKeyBundle,
    },
    /// 取我的好友链接编号（没有就新建）。
    GetFriendLink,
    /// 换一条好友链接，旧的立即失效（契约 S8）。
    RotateFriendLink,
    /// 按好友链接编号查对方。
    ResolveFriendLink {
        /// 编号。
        token: Bytes,
    },
    /// 查一批账号的名字与身份指纹。
    GetProfiles {
        /// 账号。
        uids: Vec<Uid>,
    },
    /// 建会话（私聊、群）。
    CreateConv {
        /// 第一环。
        link: ConvLink,
        /// 钥匙第一代。
        keys: ConvKeyBundle,
    },
    /// 接会话签名链（邀请、移出 + 换代、退群、换代、改资料、发 / 作废邀请）。
    AppendConv {
        /// 会话。
        conv: ConvId,
        /// 新的环（按顺序）。
        links: Vec<ConvLink>,
        /// 新一代或给新成员的封装。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        keys: Option<ConvKeyBundle>,
        /// 发群邀请时，链接钥匙包起来的会话种子。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        invite: Option<InviteSeed>,
    },
    /// 给还没有当前一代封装的成员补发（凭邀请加入的人加入时群已经换过代）。
    GrantConvKeys {
        /// 会话。
        conv: ConvId,
        /// 当前一代的补发封装。
        keys: ConvKeyBundle,
    },
    /// 取会话签名链（序号大于 `after` 的环）。
    GetConv {
        /// 会话。
        conv: ConvId,
        /// 从哪一环之后取。
        #[serde(default)]
        after: u64,
    },
    /// 取封装给我的会话钥匙和旧钥匙链。
    GetConvKeys {
        /// 会话。
        conv: ConvId,
    },
    /// 列出我所在（和离开过）的会话。
    ListConvs,
    /// 按邀请编号取群邀请（凭链接加入前）。
    GetInvite {
        /// 邀请编号。
        invite: InviteId,
    },
    /// 凭群邀请链接加入。
    JoinByInvite {
        /// 会话。
        conv: ConvId,
        /// “凭邀请加入”这一环。
        link: ConvLink,
        /// 封装给自己账号钥匙的会话种子。
        keys: ConvKeyBundle,
    },
    /// 发消息（按会话与消息编号去重：同一条重发返回同一个序号）。
    Send {
        /// 信封。
        env: Envelope,
    },
    /// 直连发送的第一步：只落库，暂不向任何在线电脑推送。
    ///
    /// 客户端随后把服务器返回的日志序号提交给已经完成局域网暂存的电脑，
    /// 再用 [`ReleaseMessage`] 向没有直连成功的电脑补发。
    SendLan {
        /// 信封。
        env: Envelope,
    },
    /// 释放一条已落库的直连消息，跳过已经由局域网提交的电脑。
    ReleaseMessage {
        /// 会话。
        conv: ConvId,
        /// 消息编号。
        id: MsgId,
        /// 已经由局域网收到的电脑。
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        direct_devices: Vec<DeviceId>,
    },
    /// 按会话往前翻历史（`before` 为空从最新开始）。
    History {
        /// 会话。
        conv: ConvId,
        /// 取日志序号小于它的。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        before: Option<u64>,
        /// 最多几条。
        limit: u32,
        /// 只要服务器时间不早于它的（毫秒，含）。第 1 版之后加的可选字段：不带时与旧帧一字不差。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        since_ms: Option<i64>,
        /// 只要服务器时间不晚于它的（毫秒，含）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        until_ms: Option<i64>,
    },
    /// 会话活动：自己所在的会话里 `since_ms` 起有消息的，每个会话给最早、最新一条的服务器时间（不碰内容）。
    Activity {
        /// 从这个时间起（毫秒，含）。
        since_ms: i64,
    },
    /// 补拉日志序号大于 `since` 的事件。
    Sync {
        /// 上次处理到的序号。
        since: u64,
        /// 最多几条。
        limit: u32,
    },
    /// 新建一个文件（之后按段 `PUT /v1/files/{编号}`）。
    FileCreate {
        /// 文件属于哪个会话。
        conv: ConvId,
        /// 密文总字节数。
        size: u64,
    },
    /// 保活。
    Ping,
    /// 阅读扩展的精确消息查询；不推进任何阅读位置。
    ReadingMessages {
        conv: ConvId,
        ids: Vec<MsgId>,
    },
    /// 分页取各设备最新的加密阅读记录。after 是服务端记录序号。
    ReadingGet {
        conv: ConvId,
        after: u64,
        limit: u32,
    },
    /// 写本设备的下一版加密阅读记录；相同记录幂等，旧版不能覆盖新版。
    ReadingSet {
        envelope: ReadingEnvelope,
    },
}

/// 账号签名链的一环 + 服务器日志序号。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountEntry {
    /// 服务器日志序号。
    pub log: u64,
    /// 这一环。
    pub link: AccountLink,
}

/// 会话签名链的一环 + 服务器日志序号。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvEntry {
    /// 服务器日志序号。
    pub log: u64,
    /// 这一环。
    pub link: ConvLink,
}

/// 一个会话在一段时间里的活动（[`Request::Activity`] 的结果）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvActivity {
    /// 会话。
    pub conv: ConvId,
    /// 这段时间里最早一条消息的服务器时间（毫秒）。
    pub first_ms: i64,
    /// 最新一条的服务器时间（毫秒）。
    pub latest_ms: i64,
}

/// 这台电脑的状态。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    /// 账号还没开通：这台电脑可以开通。
    Unprovisioned,
    /// 账号已开通、这台电脑还没被批准：只能走批准流程，拿不到任何会话内容。
    Pending,
    /// 已批准。
    Active,
}

/// 一个账号对外的资料。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountInfo {
    /// 账号。
    pub uid: Uid,
    /// 名字（来自 Cindy）。
    pub name: String,
    /// 当前重置轮次。
    pub epoch: u32,
    /// 当前这一轮的身份指纹（还没开通为空）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eldest: Option<Fixed<32>>,
}

/// 一台电脑的信息（“我的电脑”）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// 电脑编号。
    pub id: DeviceId,
    /// 电脑名。
    pub name: String,
    /// 加入时间（毫秒）。
    pub joined_ms: i64,
    /// 最近在线（毫秒）。
    pub last_seen_ms: i64,
    /// 现在是否在线。
    pub online: bool,
    /// 设备类别；旧服务器或旧客户端没有时按电脑处理。
    #[serde(default, skip_serializing_if = "DeviceKind::is_unknown")]
    pub kind: DeviceKind,
}

/// 一个待处理的批准请求。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequestInfo {
    /// 批准请求。
    pub request: RequestId,
    /// 新电脑的公钥。
    pub device: DevicePublic,
    /// 新电脑名。
    pub name: String,
    /// 新设备类别；旧服务器没有时按电脑处理。
    #[serde(default, skip_serializing_if = "DeviceKind::is_unknown")]
    pub kind: DeviceKind,
    /// 发起时间（毫秒）。
    pub created_ms: i64,
    /// 作废时间（毫秒）。
    pub expires_ms: i64,
    /// 当前第几次尝试。
    pub attempt: u32,
    /// 当前尝试的 SPAKE2 第一步。
    pub pake: Bytes,
    /// 新电脑的证明。
    pub proof: Fixed<64>,
}

/// 会话列表的一项。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvSummary {
    /// 会话。
    pub conv: ConvId,
    /// 类型。
    pub kind: ConvKind,
    /// 签名链最新序号。
    pub chain_seq: u64,
    /// 最新一条消息的日志序号（没有为 0）。
    pub last_log: u64,
    /// 我现在是否是成员（离开过的会话也列出，用来看离开前的历史）。
    pub member: bool,
}

/// 服务器存的一条消息。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredMessage {
    /// 日志序号。
    pub log: u64,
    /// 服务器收到的时间（毫秒）。
    pub ts_ms: i64,
    /// 信封（被撤回的消息密文已删，`ct` 为空）。
    pub env: Envelope,
    /// 是否已被撤回。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub recalled: bool,
}

/// 同步事件。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// 新消息（含撤回消息本身）。
    Message {
        /// 消息。
        msg: StoredMessage,
    },
    /// 会话签名链接了一环（含建会话）。
    ConvLink {
        /// 会话。
        conv: ConvId,
        /// 这一环。
        link: ConvLink,
    },
    /// 有新的会话钥匙封装给我（换代或补发）。
    ConvKeys {
        /// 会话。
        conv: ConvId,
        /// 第几代。
        generation: u32,
    },
    /// 某账号（自己或聊过的人）的签名链接了一环（加 / 移除电脑、换代、重置）。
    AccountLink {
        /// 账号。
        uid: Uid,
        /// 重置轮次。
        epoch: u32,
        /// 这一环。
        link: AccountLink,
    },
}

/// 一条同步事件 + 日志序号。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncEvent {
    /// 日志序号。
    pub log: u64,
    /// 服务器时间（毫秒）。
    pub ts_ms: i64,
    /// 事件。
    pub event: Event,
}

/// `hello` 成功后的回执。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Welcome {
    /// New DMs require the recipient's explicit approval.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub friend_requests: bool,
    /// 可选扩展：没有该字段的旧服务器不提供阅读方法。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reading: bool,
    /// 账号。
    pub uid: Uid,
    /// 名字（来自 Cindy）。
    pub name: String,
    /// 当前重置轮次。
    pub epoch: u32,
    /// 这台电脑的状态。
    pub status: DeviceStatus,
    /// 新发的登录凭证（用 Cindy 凭证登录时才有）：插件交给 HHH 存凭据，之后用它登录。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<Bytes>,
    /// 账号签名链当前一轮的最新序号（没开通为 0）。
    pub chain_seq: u64,
    /// 有电脑退出了自己、账号钥匙还没换代：本机已批准时应先换代。
    pub rotation_needed: bool,
    /// 当前日志序号：新电脑从这里开始同步，之前的历史按会话翻页补读。
    pub sync_head: u64,
}

/// 回执。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Response {
    FriendRequest {
        request: Box<crate::friends::StoredFriendRequest>,
    },
    FriendRequests {
        requests: Vec<crate::friends::StoredFriendRequest>,
        next: Option<u64>,
        pending: u32,
    },
    /// 阅读范围内的确切消息。
    ReadingMessages { messages: Vec<StoredMessage> },
    /// 最新阅读记录分页。
    ReadingPage {
        records: Vec<StoredReading>,
        more: bool,
    },
    /// 平台已接受这份阅读记录。
    ReadingSaved { log: u64 },
    /// 登录成功。
    Welcome {
        /// 内容。
        welcome: Welcome,
    },
    /// 账号签名链。
    Chain {
        /// 账号。
        uid: Uid,
        /// 这是哪一轮。
        epoch: u32,
        /// 当前一轮。
        current_epoch: u32,
        /// 环。
        entries: Vec<AccountEntry>,
    },
    /// 成功，无内容。
    Done,
    /// 已写入，带日志序号。
    Appended {
        /// 最后一项的日志序号。
        log: u64,
    },
    /// 封装给这台电脑的账号钥匙。
    AccountKeys {
        /// 哪一轮。
        epoch: u32,
        /// 各代的封装（只含这台电脑能开的）。
        boxes: Vec<GenerationBox>,
        /// 各代的旧钥匙链。
        prev: Vec<GenerationWrap>,
    },
    /// 本账号的电脑。
    Devices {
        /// 现在还在的电脑。
        devices: Vec<DeviceInfo>,
    },
    /// 批准请求已发起。
    JoinStarted {
        /// 批准请求。
        request: RequestId,
        /// 第几次尝试。
        attempt: u32,
        /// 作废时间（毫秒）。
        expires_ms: i64,
        /// 发起时（不是重试）：这个账号已登录的电脑，新电脑据此说清该去哪台批准、哪台在线（契约 v3 S2）。
        /// 只有名字与时间；旧服务器不给，旧客户端不认。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        devices: Option<Vec<DeviceInfo>>,
    },
    /// 待处理的批准请求。
    JoinRequests {
        /// 请求。
        requests: Vec<JoinRequestInfo>,
    },
    /// 好友链接编号。
    FriendLink {
        /// 编号。
        token: Bytes,
    },
    /// 账号资料。
    Profiles {
        /// 资料。
        profiles: Vec<AccountInfo>,
    },
    /// 会话已建。
    ConvCreated {
        /// 会话。
        conv: ConvId,
        /// 日志序号。
        log: u64,
    },
    /// 会话签名链。
    ConvChain {
        /// 会话。
        conv: ConvId,
        /// 环。
        entries: Vec<ConvEntry>,
    },
    /// 封装给我的会话钥匙。
    ConvKeys {
        /// 会话。
        conv: ConvId,
        /// 各代封装给我的（可能对应我账号钥匙的不同代）。
        boxes: Vec<ConvGenerationBox>,
        /// 各代的旧钥匙链。
        prev: Vec<GenerationWrap>,
    },
    /// 会话列表。
    Convs {
        /// 会话。
        convs: Vec<ConvSummary>,
    },
    /// 群邀请。
    Invite {
        /// 会话。
        conv: ConvId,
        /// 包起来的种子是第几代。
        generation: u32,
        /// 包起来的种子。
        seed: Bytes,
        /// 会话签名链。
        entries: Vec<ConvEntry>,
    },
    /// 消息已收下。
    Sent {
        /// 日志序号。
        log: u64,
        /// 服务器时间（毫秒）。
        ts_ms: i64,
    },
    /// 一页历史（从新到旧）。
    Messages {
        /// 消息。
        items: Vec<StoredMessage>,
        /// 是否还有更早的。
        more: bool,
    },
    /// 会话活动（按最新一条从新到旧）。
    Activity {
        /// 每个会话一项。
        items: Vec<ConvActivity>,
    },
    /// 一批同步事件。
    SyncBatch {
        /// 事件（按日志序号递增）。
        events: Vec<SyncEvent>,
        /// 下次从哪里接着拉。
        next: u64,
        /// 是否还有。
        more: bool,
    },
    /// 文件已建。
    FileCreated {
        /// 文件编号。
        file: FileId,
    },
    /// 保活回执。
    Pong,
}

/// 某一代账号钥匙封装给这台电脑的一份。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationBox {
    /// 第几代。
    pub generation: u32,
    /// 封装。
    pub sealed: Sealed,
}

/// 某一代的旧钥匙链（用这一代加密的上一代种子）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationWrap {
    /// 第几代。
    pub generation: u32,
    /// 包起来的上一代种子。
    pub wrapped: Bytes,
}

/// 某一代会话钥匙封装给我的一份。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvGenerationBox {
    /// 会话钥匙第几代。
    pub generation: u32,
    /// 封装给我账号的哪一轮。
    pub account_epoch: u32,
    /// 封装给我账号钥匙的哪一代。
    pub account_generation: u32,
    /// 封装。
    pub sealed: Sealed,
}

/// 批准请求结束的原因。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinCloseReason {
    /// 已批准。
    Approved,
    /// 旧电脑拒绝。
    Rejected,
    /// 10 分钟没处理。
    Expired,
    /// 输错 5 次。
    TooManyAttempts,
    /// 新电脑不等了。
    Cancelled,
}

/// 服务器推送。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Push {
    /// Only delivered to connections that subscribed via friend-request methods.
    FriendRequestsChanged,
    /// 只发给主动调用阅读扩展的连接，不进入旧客户端的补拉事件流。
    ReadingChanged { conv: ConvId },
    /// 同步事件。
    Event {
        /// 事件。
        event: SyncEvent,
    },
    /// 给已批准的电脑：有新电脑请求加入。
    JoinRequested {
        /// 请求。
        request: JoinRequestInfo,
    },
    /// 给新电脑：旧电脑回应了。
    JoinAnswered {
        /// 批准请求。
        request: RequestId,
        /// 第几次尝试。
        attempt: u32,
        /// SPAKE2 回应。
        pake: Bytes,
        /// 旧电脑的确认码。
        confirm: Fixed<32>,
    },
    /// 给回应的那台旧电脑：新电脑回了确认码。
    JoinConfirmed {
        /// 批准请求。
        request: RequestId,
        /// 第几次尝试。
        attempt: u32,
        /// 新电脑的确认码。
        confirm: Fixed<32>,
    },
    /// 给已批准的电脑：上一次输错了，新电脑重新开始了一次尝试。
    JoinRetry {
        /// 批准请求。
        request: RequestId,
        /// 第几次尝试。
        attempt: u32,
        /// 新的第一步消息。
        pake: Bytes,
    },
    /// 批准请求结束（两边同时收到）。
    JoinClosed {
        /// 批准请求。
        request: RequestId,
        /// 原因。
        reason: JoinCloseReason,
    },
    /// 给被移除的电脑：你已被移出账号，连接随即关闭。
    DeviceRemoved,
}

/// 错误码。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// 请求格式不对。
    BadRequest,
    /// 没登录、凭证无效或过期。
    Unauthorized,
    /// 这台电脑还没被批准。
    NotApproved,
    /// 这台电脑已被移出账号。
    DeviceRemoved,
    /// 没有权限。
    Forbidden,
    /// 不存在。
    NotFound,
    /// 冲突（签名链头已变、私聊已存在、账号已开通）。
    Conflict,
    /// 签名链、钥匙封装校验不过。
    Invalid,
    /// 超出上限。
    LimitExceeded,
    /// 发送太频繁。
    RateLimited,
    /// 会话钥匙需要先换代（有人离开或成员换了账号钥匙）。
    RotationRequired,
    /// 已过期。
    Expired,
    /// 接口版本不兼容。
    Unsupported,
    /// 服务器内部错误。
    Internal,
}

/// 错误。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct WireError {
    /// 错误码。
    pub code: ErrorCode,
    /// 给开发者看的说明（不含任何密文、钥匙、凭证）。
    pub message: String,
}

impl WireError {
    /// 构造。
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_have_stable_shape() {
        let frame = ClientFrame {
            id: 7,
            req: Request::Ping,
        };
        assert_eq!(
            serde_json::to_string(&frame).unwrap(),
            r#"{"id":7,"req":{"op":"ping"}}"#
        );
        let res = ServerFrame::Res {
            id: 7,
            res: Response::Pong,
        };
        assert_eq!(
            serde_json::to_string(&res).unwrap(),
            r#"{"t":"res","id":7,"res":{"op":"pong"}}"#
        );
        let err = ServerFrame::Err {
            id: 8,
            err: WireError::new(ErrorCode::RateLimited, "慢一点"),
        };
        assert_eq!(
            serde_json::to_string(&err).unwrap(),
            r#"{"t":"err","id":8,"err":{"code":"rate_limited","message":"慢一点"}}"#
        );
        let push = ServerFrame::Push {
            push: Push::DeviceRemoved,
        };
        assert_eq!(
            serde_json::to_string(&push).unwrap(),
            r#"{"t":"push","push":{"kind":"device_removed"}}"#
        );
    }

    #[test]
    fn nested_tagged_enums_round_trip() {
        let frame = ServerFrame::Push {
            push: Push::Event {
                event: SyncEvent {
                    log: 3,
                    ts_ms: 4,
                    event: Event::ConvKeys {
                        conv: ConvId::random(),
                        generation: 2,
                    },
                },
            },
        };
        let json = serde_json::to_string(&frame).unwrap();
        assert_eq!(serde_json::from_str::<ServerFrame>(&json).unwrap(), frame);
        let hello = ClientFrame {
            id: 1,
            req: Request::Hello {
                protocol: PROTOCOL_VERSION,
                auth: HelloAuth::Session {
                    token: Bytes(vec![1, 2]),
                },
                device: DeviceSecret::generate().public(),
                name: "台式机".into(),
                kind: DeviceKind::Computer,
                sig: Fixed([0; 64]),
            },
        };
        let json = serde_json::to_string(&hello).unwrap();
        assert_eq!(serde_json::from_str::<ClientFrame>(&json).unwrap(), hello);
    }

    #[test]
    fn hello_signature_binds_nonce_and_device() {
        let secret = DeviceSecret::generate();
        let nonce = Fixed(crypto::random());
        let sig = sign_hello(&secret, &nonce);
        assert!(check_hello(&secret.public(), &nonce, &sig).is_ok());
        assert!(check_hello(&secret.public(), &Fixed(crypto::random()), &sig).is_err());
        assert!(check_hello(&DeviceSecret::generate().public(), &nonce, &sig).is_err());
    }

    #[test]
    fn unknown_ops_are_rejected() {
        assert!(
            serde_json::from_str::<ClientFrame>(r#"{"id":1,"req":{"op":"drop_tables"}}"#).is_err()
        );
    }

    // 已登录的电脑名单是可选字段：旧服务器的回执照样读（没有名单），新回执带上名单能读回来。
    #[test]
    fn join_started_reads_with_and_without_devices() {
        let request = RequestId::random();
        let old = format!(
            r#"{{"op":"join_started","request":"{}","attempt":1,"expires_ms":9}}"#,
            request.as_str()
        );
        let Response::JoinStarted { devices, .. } = serde_json::from_str(&old).unwrap() else {
            panic!()
        };
        assert_eq!(devices, None);
        let res = Response::JoinStarted {
            request,
            attempt: 1,
            expires_ms: 9,
            devices: Some(vec![DeviceInfo {
                id: DeviceId::random(),
                name: "台式机".into(),
                joined_ms: 1,
                last_seen_ms: 2,
                online: false,
                kind: DeviceKind::Computer,
            }]),
        };
        assert_eq!(
            serde_json::from_str::<Response>(&serde_json::to_string(&res).unwrap()).unwrap(),
            res
        );
    }

    #[test]
    fn lan_send_and_release_requests_round_trip() {
        let env = Envelope {
            conv: ConvId::random(),
            id: MsgId::random(),
            generation: 1,
            sender: Uid::random(),
            sender_eldest: Fixed([0; 32]),
            device: DeviceId::random(),
            recall: None,
            ct: Bytes(vec![1, 2, 3]),
        };
        let send = ClientFrame {
            id: 8,
            req: Request::SendLan { env: env.clone() },
        };
        let decoded: ClientFrame =
            serde_json::from_str(&serde_json::to_string(&send).unwrap()).unwrap();
        assert_eq!(decoded, send);
        let release = ClientFrame {
            id: 9,
            req: Request::ReleaseMessage {
                conv: env.conv,
                id: env.id,
                direct_devices: vec![DeviceId::random()],
            },
        };
        let decoded: ClientFrame =
            serde_json::from_str(&serde_json::to_string(&release).unwrap()).unwrap();
        assert_eq!(decoded, release);
    }
}
