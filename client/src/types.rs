//! 客户端库对外的类型：配置、凭据、推给上层（插件）的更新、解开的消息、会话里的系统提示。

use std::fmt;

use friend_im_core::bytes::{Bytes, Fixed};
use friend_im_core::conv::{ConvChange, ConvKind, ConvLink, MemberRef, RemoveReason, Via};
use friend_im_core::ids::{ConvId, DeviceId, InviteId, MsgId, RequestId, Uid};
use friend_im_core::keys::DeviceSecret;
use friend_im_core::message::Content;
use friend_im_core::wire::{DeviceInfo, DeviceStatus, JoinCloseReason, JoinRequestInfo};
use friend_im_core::words::JoinCode;
use serde::{Deserialize, Serialize};

/// 连接配置。
#[derive(Clone, Debug)]
pub struct Config {
    /// 服务器地址：`https://im.example.com`、`wss://im.example.com` 都行（测试里用 `http://127.0.0.1:端口`）。
    pub server: String,
    /// 这台电脑的名字（“我的电脑”里显示，1–64 个字符）。
    pub device_name: String,
}

/// 要交给 HHH 存进系统凭据库的东西（约 200 字节）：这台电脑的私钥 + 服务器发的登录凭证。
/// 账号钥匙、会话钥匙每次连上后从服务器取回再解，不用存。
#[derive(Clone, Serialize, Deserialize)]
pub struct Credentials {
    /// 这台电脑的私钥。
    pub device: DeviceSecret,
    /// 服务器发的登录凭证（第一次用 Cindy 凭证登录后才有）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<Bytes>,
}

impl Credentials {
    /// 新电脑：生成一对电脑钥匙。
    pub fn generate() -> Self {
        Self {
            device: DeviceSecret::generate(),
            session: None,
        }
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Credentials({}, 登录凭证：{})",
            self.device.id(),
            if self.session.is_some() { "有" } else { "无" }
        )
    }
}

/// 新电脑发起批准请求的结果（契约 S2、v3）。
#[derive(Debug)]
pub struct JoinStart {
    /// 要显示的 4 个词。
    pub code: JoinCode,
    /// 这个账号已登录的电脑（名字、在不在线、时间）；旧服务器不给为 `None`。
    pub devices: Option<Vec<DeviceInfo>>,
    /// 按服务器的钟，此刻是几点（毫秒）：写“N 天前在线”用。
    pub now_ms: i64,
}

/// 一条解开的消息。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// 会话。
    pub conv: ConvId,
    /// 消息编号（发送的电脑取的，撤回、回复都用它）。
    pub id: MsgId,
    /// 服务器日志序号（同一会话里按它排序）。
    pub log: u64,
    /// 服务器收到的时间（毫秒）。
    pub ts_ms: i64,
    /// 发送账号。
    pub sender: Uid,
    /// 发送账号当时的身份指纹。
    pub sender_eldest: Fixed<32>,
    /// 发送的电脑。
    pub device: DeviceId,
    /// 发送时发送方的本机时间（毫秒；被撤回的消息为 0）。
    pub ctime_ms: i64,
    /// 内容；被撤回的消息服务器上已删掉密文，为空。
    pub content: Option<Content>,
}

impl Message {
    /// 这条是否已被撤回（服务器上的内容已删）。
    pub fn recalled(&self) -> bool {
        self.content.is_none()
    }
}

/// 会话里的一条系统提示（来自会话签名链，按日志序号和消息排在一起）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    /// 会话。
    pub conv: ConvId,
    /// 服务器日志序号。
    pub log: u64,
    /// 签名时签名人的本机时间（毫秒）。
    pub ctime_ms: i64,
    /// 谁做的。
    pub author: Uid,
    /// 做了什么。
    pub change: ConvNotice,
}

/// 系统提示的内容。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConvNotice {
    /// 建了会话（私聊或群）。
    Created {
        /// 类型。
        kind: ConvKind,
        /// 成员（含建的人）。
        members: Vec<Uid>,
        /// 私聊的来源（通过好友链接添加、身份已核对；或在某个群里认识）。
        via: Option<Via>,
    },
    /// 邀请了成员。
    Added {
        /// 新成员。
        members: Vec<Uid>,
    },
    /// 凭群邀请链接加入。
    JoinedByInvite,
    /// 移出了成员。
    Removed {
        /// 被移出的人。
        uid: Uid,
        /// 原因。
        reason: RemoveReason,
    },
    /// 退群。
    Left,
    /// 换了钥匙（不用给用户看）。
    Rotated,
    /// 私聊对方重置了账号，之后的消息用新钥匙加密（契约 S16）。
    MemberReset {
        /// 重置的人。
        uid: Uid,
    },
    /// 改了群名、群头像或简介。
    ProfileChanged,
    /// 发了群邀请链接。
    InviteCreated {
        /// 邀请编号。
        invite: InviteId,
    },
    /// 作废了群邀请链接。
    InviteRevoked {
        /// 邀请编号。
        invite: InviteId,
    },
}

impl Notice {
    /// 由验过的一环得到系统提示。
    pub(crate) fn from_link(conv: &ConvId, link: &ConvLink, log: u64) -> Option<Self> {
        let body = link.parse().ok()?;
        let change = match body.change {
            ConvChange::Create {
                kind, members, via, ..
            } => ConvNotice::Created {
                kind,
                members: members.into_iter().map(|m| m.uid).collect(),
                via,
            },
            ConvChange::Add { members } => ConvNotice::Added {
                members: members.into_iter().map(|m| m.uid).collect(),
            },
            ConvChange::JoinByInvite { .. } => ConvNotice::JoinedByInvite,
            ConvChange::Remove { uid, reason } => ConvNotice::Removed { uid, reason },
            ConvChange::Leave => ConvNotice::Left,
            ConvChange::Rotate { .. } => ConvNotice::Rotated,
            ConvChange::MemberReset { member, .. } => ConvNotice::MemberReset { uid: member.uid },
            ConvChange::SetProfile { .. } => ConvNotice::ProfileChanged,
            ConvChange::CreateInvite { invite, .. } => ConvNotice::InviteCreated { invite },
            ConvChange::RevokeInvite { invite } => ConvNotice::InviteRevoked { invite },
        };
        Some(Self {
            conv: conv.clone(),
            log,
            ctime_ms: body.ctime_ms,
            author: body.author,
            change,
        })
    }
}

/// 账号的变化（自己的账号：契约 S4 的提醒；聊过的人：重置）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountNotice {
    /// 账号开通（或重置后的新一轮开始）。
    Started {
        /// 是不是重置（第 2 轮及以后）。
        reset: bool,
    },
    /// 新增了电脑。
    DeviceAdded {
        /// 电脑。
        device: DeviceId,
        /// 电脑名。
        name: String,
    },
    /// 移除了电脑。
    DeviceRemoved {
        /// 电脑。
        device: DeviceId,
        /// 电脑名。
        name: String,
    },
    /// 账号钥匙换了代（不用给用户看）。
    KeyRotated,
    /// 换了恢复密钥。
    RecoveryReplaced,
}

/// 推给上层的更新。
#[derive(Clone, Debug)]
pub enum Update {
    /// 阅读事实变了；上层只读补查，不作为新消息或本人查看。
    ReadingChanged { conv: ConvId },
    /// 好友申请变化；重新查询当前账号的列表。
    FriendRequestsChanged,
    /// 连上了服务器。
    Connected {
        /// 这台电脑的状态。
        status: DeviceStatus,
    },
    /// 断开了，正在重连（已收到的消息照常能看，发送会失败）。
    Disconnected,
    /// 这台电脑刚变成可用（开通、被批准、用恢复密钥加入、重置后）。
    Activated,
    /// 处理到了哪个日志序号：上层随事件把它存成同步位置，下次从这里接着补。
    Position(u64),
    /// 一条消息。
    Message(Message),
    /// 一条消息解不开或验不过（服务器给的东西不对）：上层显示一条提示，不当成正常消息。
    MessageRejected {
        /// 会话。
        conv: ConvId,
        /// 消息编号。
        id: MsgId,
        /// 日志序号。
        log: u64,
        /// 服务器收到的时间（毫秒）。
        ts_ms: i64,
        /// 信封上写的发送账号（没验过，只用来把提示放在对的人名下）。
        sender: Uid,
        /// 原因（不含内容）。
        reason: String,
    },
    /// 会话里的系统提示（也是“这个会话变了”的信号：新会话第一次出现时就是它的建会话提示）。
    Conv(Notice),
    /// 会话签名链验不过（服务器私自加成员等）：拒绝并提醒用户（契约 §5）。
    ConvRejected {
        /// 会话。
        conv: ConvId,
        /// 日志序号。
        log: u64,
        /// 原因。
        reason: String,
    },
    /// 账号变化。
    Account {
        /// 哪个账号（自己或聊过的人）。
        uid: Uid,
        /// 日志序号。
        log: u64,
        /// 变化。
        notice: AccountNotice,
    },
    /// 旧电脑：有新电脑请求加入。
    JoinRequested(JoinRequestInfo),
    /// 补读后的全部有效请求，与增量事件按同一状态锁的顺序交付。
    JoinRequests(Vec<JoinRequestInfo>),
    /// 服务器已接受本机批准，只有实际完成批准的设备收到。
    JoinApproved {
        /// 批准请求。
        request: RequestId,
    },
    /// 旧电脑：刚输入的 4 个词和新电脑上的不一致，可以再输（契约 S21）。
    JoinRetry {
        /// 批准请求。
        request: RequestId,
        /// 第几次尝试。
        attempt: u32,
    },
    /// 新电脑：旧电脑输入的 4 个词不一致，已自动开始下一次尝试。
    JoinWrongCode {
        /// 批准请求。
        request: RequestId,
        /// 第几次尝试（新的这次）。
        attempt: u32,
    },
    /// 批准请求结束（两边都收到）。
    JoinClosed {
        /// 批准请求。
        request: RequestId,
        /// 原因。
        reason: JoinCloseReason,
    },
    /// 登录凭证变了：上层把 [`crate::Client::credentials`] 重新交给 HHH 存。
    CredentialsChanged,
    /// 这台电脑被移出了账号（或退出了登录），客户端已停止。
    DeviceRemoved,
    /// 登录凭证失效，客户端已停止，需要重新登录。
    LoggedOut,
}

/// 翻历史的一项。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HistoryItem {
    /// 消息。
    Message(Message),
    /// 解不开或验不过的消息。
    Rejected {
        /// 消息编号。
        id: MsgId,
        /// 日志序号。
        log: u64,
        /// 服务器收到的时间（毫秒）。
        ts_ms: i64,
        /// 信封上写的发送账号（没验过，只用来把提示放在对的人名下）。
        sender: Uid,
        /// 原因。
        reason: String,
    },
    /// 系统提示。
    Notice(Notice),
}

impl HistoryItem {
    /// 日志序号。
    pub fn log(&self) -> u64 {
        match self {
            Self::Message(m) => m.log,
            Self::Rejected { log, .. } => *log,
            Self::Notice(n) => n.log,
        }
    }
}

/// 一页历史（从新到旧）。
#[derive(Clone, Debug, Default)]
pub struct HistoryPage {
    /// 消息与系统提示，按日志序号从新到旧。
    pub items: Vec<HistoryItem>,
    /// 是否还有更早的。
    pub more: bool,
}

/// 一个会话的现状（按验过的签名链）。
#[derive(Clone, Debug)]
pub struct ConvInfo {
    /// 会话。
    pub conv: ConvId,
    /// 类型。
    pub kind: ConvKind,
    /// 群主（建的人）。
    pub owner: Uid,
    /// 现在的成员与身份指纹。
    pub members: Vec<MemberRef>,
    /// 私聊的来源。
    pub via: Option<Via>,
    /// 我现在是不是成员。
    pub member: bool,
}
