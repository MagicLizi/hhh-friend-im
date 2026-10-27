//! 读取与动作（protocol-v1 §8、§10）：会话、成员、名字、会话发现、翻历史、发消息、撤回。
//!
//! - 翻历史只能从新往旧（服务器按日志序号往前翻），HHH 读消息也一直是这样读；游标是日志序号（`translate::cursor`）。
//!   一页里除了消息还有系统提示，合起来不超过宿主要的条数，多出来的留给下一页。
//! - 发消息一条一条发（第一阶段线上验收的教训：并发发送会挤满客户端的推送队列）。消息编号由账号与 `operationId`
//!   算出来：同一次发送重试还是同一条，服务器按编号去重。附件大、60 秒内发不完时先回“不确定”，发完的结果在
//!   `messages/lookupSend` 里取。

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use friend_im_client::core::ids::{ConvId, MsgId, Uid};
use friend_im_client::core::limits::HISTORY_PAGE_MAX;
use friend_im_client::core::message::{Content, Part};
use friend_im_client::core::wire::ConvActivity;
use friend_im_client::{ClientError, HistoryItem};
use hhh_im_protocol::method::{
    ActivityItem, ConversationsGetParams, ConversationsListParams, MembersParams,
    MessagesListParams, MessagesLookupSendParams, MessagesRecallParams, MessagesSendParams, Page,
    PeopleGetParams, PeopleGetResult, RecentActivityParams, RecentActivityResult,
};
use hhh_im_protocol::rpc::{ErrorKind, RpcError};
use hhh_im_protocol::types::{Person, PersonKind, SendOutcome, SendTarget};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use super::session::Live;
use super::translate::{self, Piece};
use super::{Server, errors, push};

/// 记住多少次发送的结果（同一个 `operationId` 再来时回同一个结果）。
const SENDS_MAX: usize = 1000;

/// 会话发现时一个会话至多翻几页历史（一页 [`HISTORY_PAGE_MAX`] 条，平时一页就到头）。
const ACTIVITY_PAGES: usize = 3;

type SendResult = Result<Value, RpcError>;

/// 发过和正在发的消息：操作编号 → 结果。
#[derive(Default)]
pub(crate) struct Sends {
    slots: Mutex<VecDeque<(String, watch::Receiver<Option<SendResult>>)>>,
    /// 一条发完再发下一条（个人资料也排在这里）。
    pub(crate) gate: tokio::sync::Mutex<()>,
}

impl Sends {
    fn find(&self, operation: &str) -> Option<watch::Receiver<Option<SendResult>>> {
        self.slots
            .lock()
            .expect("发送记录锁中毒")
            .iter()
            .find(|(id, _)| id == operation)
            .map(|(_, rx)| rx.clone())
    }

    /// 这次发送的结果槽；第一次见到这个编号时另外给出写结果的那一头（由调用方去发）。
    fn slot(
        &self,
        operation: &str,
    ) -> (
        watch::Receiver<Option<SendResult>>,
        Option<watch::Sender<Option<SendResult>>>,
    ) {
        let mut slots = self.slots.lock().expect("发送记录锁中毒");
        if let Some(at) = slots.iter().position(|(id, _)| id == operation) {
            // 确定没发出去的（结果是错误）可以用同一个编号再发一次：宿主重试沿用操作编号。
            if !matches!(&*slots[at].1.borrow(), Some(Err(_))) {
                return (slots[at].1.clone(), None);
            }
            slots.remove(at);
        }
        let (tx, rx) = watch::channel(None);
        slots.push_back((operation.to_owned(), rx.clone()));
        if slots.len() > SENDS_MAX {
            slots.pop_front();
        }
        (rx, Some(tx))
    }
}

pub(crate) fn params<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, RpcError> {
    serde_json::from_value(value).map_err(errors::invalid_params)
}

fn to_value(value: impl serde::Serialize) -> Value {
    serde_json::to_value(value).expect("结果总能写成 JSON")
}

fn conv_id(text: &str) -> Result<ConvId, RpcError> {
    ConvId::parse(text).map_err(|_| errors::of(ErrorKind::NotFound, "没有这个会话。"))
}

fn msg_id(text: &str) -> Result<MsgId, RpcError> {
    MsgId::parse(text).map_err(|_| errors::of(ErrorKind::NotFound, "没有这条消息。"))
}

/// 按偏移翻页的游标：`o<偏移>`。
fn offset_of(cursor: Option<&str>) -> Result<usize, RpcError> {
    match cursor {
        None => Ok(0),
        Some(text) => text
            .strip_prefix('o')
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| errors::of(ErrorKind::InvalidRequest, "翻页游标不对。")),
    }
}

/// 一页的切法：从 `offset` 起取 `limit` 个，还有就给下一页的游标。
fn slice<T>(all: Vec<T>, offset: usize, limit: u16) -> Page<T> {
    let limit = usize::from(limit.max(1));
    let total = all.len();
    let items: Vec<T> = all.into_iter().skip(offset).take(limit).collect();
    let next = (offset + items.len() < total).then(|| format!("o{}", offset + items.len()));
    Page { items, next }
}

/// 消息编号：由账号与操作编号算出来（同一次发送重试还是同一个编号）。
pub(crate) fn send_id(me: &Uid, operation: &str) -> MsgId {
    let digest = Sha256::new()
        .chain_update(b"friend-im/send/v1\0")
        .chain_update(me.as_str())
        .chain_update(b"\0")
        .chain_update(operation)
        .finalize();
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&digest[..16]);
    MsgId::from_raw(raw)
}

fn mime_of(name: &str, image: bool, head: &[u8]) -> String {
    if image && let Ok(kind) = imagesize::image_type(head) {
        let known = match kind {
            imagesize::ImageType::Png => Some("image/png"),
            imagesize::ImageType::Jpeg => Some("image/jpeg"),
            imagesize::ImageType::Gif => Some("image/gif"),
            imagesize::ImageType::Webp => Some("image/webp"),
            imagesize::ImageType::Bmp => Some("image/bmp"),
            _ => None,
        };
        if let Some(mime) = known {
            return mime.into();
        }
    }
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "txt" | "md" | "log" => "text/plain",
        "zip" => "application/zip",
        "mp4" => "video/mp4",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        _ => "application/octet-stream",
    }
    .into()
}

impl Server {
    /// `conversations/list`：自己现在所在的会话，按最近有动静的排。
    pub(crate) async fn conversations_list(
        &self,
        params: ConversationsListParams,
    ) -> Result<Value, RpcError> {
        let live = self.live().await?;
        let offset = offset_of(params.cursor.as_deref())?;
        let summaries = live.client.convs().await.map_err(|e| errors::client(&e))?;
        // 重置过账号后退出的群不再列（契约 S7）。
        let left = live
            .client
            .groups_left_by_reset()
            .await
            .map_err(|e| errors::client(&e))?;
        let ids: Vec<ConvId> = summaries
            .into_iter()
            .filter(|s| s.member && !left.contains(&s.conv))
            .map(|s| s.conv)
            .collect();
        let page = slice(ids, offset, params.limit.min(100));
        let mut items = Vec::with_capacity(page.items.len());
        for conv in &page.items {
            match live.conversation(conv).await {
                Ok(conversation) => items.push(conversation),
                Err(error) => tracing::info!(%conv, %error, "会话资料取不到，这次列表里先不放"),
            }
        }
        Ok(to_value(Page {
            items,
            next: page.next,
        }))
    }

    /// `conversations/get`。
    pub(crate) async fn conversations_get(
        &self,
        params: ConversationsGetParams,
    ) -> Result<Value, RpcError> {
        let live = self.live().await?;
        let conv = conv_id(&params.conversation_id)?;
        live.conversation(&conv)
            .await
            .map(to_value)
            .map_err(|e| errors::client(&e))
    }

    /// `conversations/members`：会话现在的成员。
    pub(crate) async fn conversations_members(
        &self,
        params: MembersParams,
    ) -> Result<Value, RpcError> {
        let live = self.live().await?;
        let conv = conv_id(&params.conversation_id)?;
        let offset = offset_of(params.cursor.as_deref())?;
        let info = live
            .client
            .conv_info(&conv)
            .await
            .map_err(|e| errors::client(&e))?;
        let page = slice(
            info.members.into_iter().map(|m| m.uid).collect(),
            offset,
            params.limit,
        );
        let names = live.names(page.items.iter().cloned()).await;
        let items: Vec<Person> = page
            .items
            .iter()
            .map(|u| Person {
                id: u.to_string(),
                id_type: None,
                kind: PersonKind::User,
                name: names.get(u).cloned(),
                avatar: live.avatar_of(u),
            })
            .collect();
        Ok(to_value(Page {
            items,
            next: page.next,
        }))
    }

    /// `people/get`：账号的名字。编号格式不对、服务器上没有的放进 `missing`。
    pub(crate) async fn people_get(&self, params: PeopleGetParams) -> Result<Value, RpcError> {
        let live = self.live().await?;
        let mut missing = Vec::new();
        let mut uids = Vec::new();
        for id in params.ids.iter().take(100) {
            match Uid::parse(id) {
                Ok(uid) => uids.push(uid),
                Err(_) => missing.push(id.clone()),
            }
        }
        let profiles = live
            .client
            .profiles(&uids)
            .await
            .map_err(|e| errors::client(&e))?;
        let found: Vec<Person> = profiles
            .iter()
            .map(|p| Person {
                id: p.uid.to_string(),
                id_type: None,
                kind: PersonKind::User,
                name: Some(p.name.clone()),
                avatar: live.avatar_of(&p.uid),
            })
            .collect();
        missing.extend(
            uids.iter()
                .filter(|u| !profiles.iter().any(|p| &p.uid == *u))
                .map(ToString::to_string),
        );
        Ok(to_value(PeopleGetResult { found, missing }))
    }

    /// `conversations/recentActivity`：服务器一次给全（至多 1000 个会话），只有编号与时间。服务器解不开内容，个人资料这类
    /// 不给人看的也算进去，所以再翻一下这段历史，只报有人发了消息的（[`Seen`]）；私聊只有别人发过时才带对方编号。
    pub(crate) async fn conversations_recent_activity(
        &self,
        params: RecentActivityParams,
    ) -> Result<Value, RpcError> {
        let live = self.live().await?;
        let activity = live
            .client
            .activity(params.since_ms)
            .await
            .map_err(|e| errors::client(&e))?;
        let mut items = Vec::with_capacity(activity.len());
        for item in activity {
            let Ok(conversation) = live.conversation(&item.conv).await else {
                continue;
            };
            let seen = match seen_since(&live, &item, params.since_ms).await {
                Ok(Some(seen)) => seen,
                Ok(None) => {
                    tracing::debug!(conv = %item.conv, "这段时间只有不给人看的（个人资料、撤回、换钥匙），不算有新消息");
                    continue;
                }
                Err(error @ (ClientError::Disconnected | ClientError::Timeout)) => {
                    return Err(errors::client(&error));
                }
                Err(error) => {
                    tracing::info!(conv = %item.conv, %error, "这段历史翻不了，按服务器给的算");
                    Seen::reported(&item)
                }
            };
            items.push(ActivityItem {
                first_page: None,
                conversation: None,
                conversation_id: item.conv.to_string(),
                kind: conversation.kind,
                first_ms: seen.first_ms,
                latest_ms: seen.latest_ms,
                peer_id: conversation.peer.filter(|_| seen.others),
            });
        }
        items.sort_by_key(|item| std::cmp::Reverse(item.latest_ms));
        Ok(to_value(RecentActivityResult {
            items,
            complete: true,
        }))
    }

    /// `messages/list`：从新往旧翻一页，页里按从旧到新排。
    pub(crate) async fn messages_list(
        &self,
        params: MessagesListParams,
    ) -> Result<Value, RpcError> {
        let live = self.live().await?;
        let conv = conv_id(&params.conversation_id)?;
        if params.thread_id.is_some() {
            return Ok(to_value(Page::<()> {
                items: Vec::new(),
                next: None,
            }));
        }
        if !params.newest_first {
            return Err(errors::of(
                ErrorKind::Unsupported,
                "Cindy IM 只能从新往旧翻历史。",
            ));
        }
        let before = match params.cursor.as_deref() {
            None => None,
            Some(text) => Some(
                translate::parse_cursor(text)
                    .ok_or_else(|| errors::of(ErrorKind::InvalidRequest, "翻页游标不对。"))?,
            ),
        };
        let limit = usize::from(params.limit.max(1)).min(translate_page_max());
        let page = live
            .client
            .history_in(
                &conv,
                before,
                limit as u32,
                params.after_ms,
                params.before_ms,
            )
            .await
            .map_err(|e| errors::client(&e))?;
        Ok(to_value(
            history_page(&live, &conv, page.items, page.more, limit).await,
        ))
    }

    /// `messages/send`：同一个操作编号只发一次；60 秒内没发完先回“不确定”。
    pub(crate) async fn messages_send(
        self: &Arc<Self>,
        params: MessagesSendParams,
    ) -> Result<Value, RpcError> {
        let (mut rx, tx) = self.sends.slot(&params.operation_id);
        if let Some(tx) = tx {
            let server = self.clone();
            tokio::spawn(async move {
                let result = server.send_now(params).await;
                let _ = tx.send(Some(result));
            });
        }
        self.wait_send(&mut rx).await
    }

    /// `messages/lookupSend`：这次发送的结果（还在发就再等一会儿）。
    pub(crate) async fn messages_lookup_send(
        &self,
        params: MessagesLookupSendParams,
    ) -> Result<Value, RpcError> {
        let Some(mut rx) = self.sends.find(&params.operation_id) else {
            return Err(errors::of(
                ErrorKind::NotFound,
                "没有这次发送的记录（插件重启过）。",
            ));
        };
        self.wait_send(&mut rx).await
    }

    async fn wait_send(
        &self,
        rx: &mut watch::Receiver<Option<SendResult>>,
    ) -> Result<Value, RpcError> {
        match tokio::time::timeout(self.options.send_wait, rx.wait_for(Option::is_some)).await {
            Ok(Ok(result)) => result.clone().expect("等到的结果一定有值"),
            Ok(Err(_)) => Ok(to_value(SendOutcome::Unknown {
                reason: "发送中途插件出了问题，不知道发出去没有。".into(),
            })),
            Err(_) => Ok(to_value(SendOutcome::Unknown {
                reason: "附件还在上传，发完后在发送记录里能看到结果。".into(),
            })),
        }
    }

    /// 真的发：附件先加密上传，再一条一条发。没连上服务器时不知道服务器收没收到，回“不确定”（不自己重发）。
    async fn send_now(&self, params: MessagesSendParams) -> SendResult {
        let live = self.live().await?;
        let (conv, reply_to) = match &params.target {
            SendTarget::Conversation { conversation_id } => (conv_id(conversation_id)?, None),
            SendTarget::Reply {
                conversation_id,
                message_id,
                ..
            } => (conv_id(conversation_id)?, Some(msg_id(message_id)?)),
        };
        let pieces = translate::pieces(&params.content)
            .map_err(|m| errors::of(ErrorKind::InvalidRequest, m))?;
        if pieces.is_empty() {
            return Err(errors::of(ErrorKind::InvalidRequest, "消息是空的。"));
        }
        let mut parts = Vec::with_capacity(pieces.len());
        let mut used = Vec::new();
        for piece in pieces {
            match piece {
                Piece::Part(part) => parts.push(part),
                Piece::Attachment { key, image } => {
                    parts.push(self.upload_attachment(&live, &conv, &key, image).await?);
                    used.push(key);
                }
            }
        }
        let content = Content::Post {
            parts: parts.clone(),
            reply_to: reply_to.clone(),
        };
        let id = send_id(&live.me, &params.operation_id);
        let sent = {
            let _turn = self.sends.gate.lock().await;
            // 没连着服务器：一定没发出去，回可以重试的错误（契约 S19），宿主记成“没有发出去”、能重试；
            // 发出去之后才断的才说不确定。
            if !live.client.connected() {
                tracing::info!(%conv, "发送时没连着服务器，没有发出去");
                return Err(errors::client(&ClientError::Disconnected));
            }
            live.client.send(&conv, &id, content).await
        };
        let (_, ts_ms) = match sent {
            Ok(sent) => sent,
            Err(error @ (ClientError::Disconnected | ClientError::Timeout)) => {
                tracing::info!(%conv, %error, "发送时没连上服务器，不知道发出去没有");
                return Ok(to_value(SendOutcome::Unknown {
                    reason: "没连上 Cindy IM 服务器，不知道发出去没有。".into(),
                }));
            }
            Err(error) => {
                tracing::info!(%conv, %error, "发送被拒");
                return Err(errors::client(&error));
            }
        };
        for key in used {
            self.uploads.done(&key).await;
        }
        let mut uids = vec![live.me.clone()];
        uids.extend(parts.iter().filter_map(|p| match p {
            Part::Mention { uid: Some(uid), .. } => Some(uid.clone()),
            _ => None,
        }));
        let names = live.names(uids).await;
        let message = translate::posted(
            conv.as_str(),
            &id,
            &live.me,
            ts_ms,
            &parts,
            reply_to.as_ref(),
            &names,
        );
        live.remember(&message.id, &live.me, ts_ms);
        Ok(to_value(SendOutcome::Accepted {
            message: Box::new(message),
        }))
    }

    /// 暂存的附件：读宽高（图片），加密上传到这个会话，换成消息正文里的一段。
    async fn upload_attachment(
        &self,
        live: &Live,
        conv: &ConvId,
        key: &str,
        image: bool,
    ) -> Result<Part, RpcError> {
        let attachment = self
            .uploads
            .attachment(key)
            .await
            .ok_or_else(|| errors::of(ErrorKind::NotFound, "附件已经过期，要重新上传。"))?;
        let path = attachment.path.clone();
        let read_head = move || {
            use std::io::Read as _;
            let mut head = vec![0u8; 64 * 1024];
            let n = std::fs::File::open(&path)
                .and_then(|mut f| f.read(&mut head))
                .unwrap_or(0);
            head.truncate(n);
            let size = imagesize::size(&path).ok();
            (head, size)
        };
        #[cfg(not(target_os = "wasi"))]
        let (head, size) = tokio::task::spawn_blocking(read_head)
            .await
            .unwrap_or_default();
        // WASI 构建没有后台线程：就地读（只读文件头）。
        #[cfg(target_os = "wasi")]
        let (head, size) = read_head();
        let image = image || attachment.image;
        let mime = mime_of(&attachment.name, image, &head);
        let file = std::fs::File::open(&attachment.path).map_err(|error| {
            tracing::error!(%error, "打不开暂存的附件");
            errors::of(ErrorKind::NotFound, "附件已经过期，要重新上传。")
        })?;
        let uploaded = live
            .client
            .upload(conv, file, attachment.bytes, &attachment.name, &mime)
            .await
            .map_err(|error| {
                tracing::info!(%conv, %error, "附件上传没成");
                errors::client(&error)
            })?;
        Ok(if image {
            Part::Image {
                file: uploaded,
                width: size.map(|s| s.width as u32),
                height: size.map(|s| s.height as u32),
            }
        } else {
            Part::File { file: uploaded }
        })
    }

    /// `messages/recall`：撤回自己的一条（服务器上的密文随之删除）。
    pub(crate) async fn messages_recall(
        &self,
        params: MessagesRecallParams,
    ) -> Result<Value, RpcError> {
        let live = self.live().await?;
        let conv = conv_id(&params.conversation_id)?;
        let target = msg_id(&params.message_id)?;
        let _turn = self.sends.gate.lock().await;
        live.client
            .recall(&conv, &MsgId::random(), &target)
            .await
            .map_err(|error| {
                tracing::info!(%conv, %error, "撤回没成");
                errors::client(&error)
            })?;
        Ok(serde_json::json!({}))
    }
}

fn translate_page_max() -> usize {
    super::declare::PAGE_MAX as usize
}

/// 一个会话在一段时间里有人发的消息（[`translate::activity_of`]）：最早、最新一条的时间，其中有没有别人发的。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Seen {
    first_ms: i64,
    latest_ms: i64,
    others: bool,
}

impl Seen {
    /// 服务器报的原样（看不了历史时用）：当作别人发的，宁可多报一次也不漏掉真消息。
    fn reported(item: &ConvActivity) -> Self {
        Self {
            first_ms: item.first_ms,
            latest_ms: item.latest_ms,
            others: true,
        }
    }

    /// 把翻到的一页记进来。
    fn add(seen: Option<Self>, items: &[HistoryItem], me: &Uid) -> Option<Self> {
        items
            .iter()
            .filter_map(|item| translate::activity_of(item, me))
            .fold(seen, |seen, (at, sender)| {
                let others = sender != me;
                Some(match seen {
                    None => Self {
                        first_ms: at,
                        latest_ms: at,
                        others,
                    },
                    Some(s) => Self {
                        first_ms: s.first_ms.min(at),
                        latest_ms: s.latest_ms.max(at),
                        others: s.others || others,
                    },
                })
            })
    }
}

/// 服务器说这个会话 `since_ms` 起有动静：从新往旧翻这段历史，看其中有没有人发的消息（与翻历史同一套“给不给人看”）。
/// 翻满 [`ACTIVITY_PAGES`] 页还没到头时，最早一条按服务器给的算（宁可多算未读）；一条给人看的都没翻到，就按服务器给的报。
async fn seen_since(
    live: &Live,
    item: &ConvActivity,
    since_ms: i64,
) -> Result<Option<Seen>, ClientError> {
    let mut seen = None;
    let mut before = None;
    for _ in 0..ACTIVITY_PAGES {
        let page = live
            .client
            .history_in(&item.conv, before, HISTORY_PAGE_MAX, Some(since_ms), None)
            .await?;
        seen = Seen::add(seen, &page.items, &live.me);
        before = page.items.iter().map(HistoryItem::log).min();
        if !page.more || before.is_none() {
            return Ok(seen);
        }
    }
    Ok(Some(match seen {
        Some(seen) => Seen {
            first_ms: seen.first_ms.min(item.first_ms),
            ..seen
        },
        None => Seen::reported(item),
    }))
}

/// 一页历史（客户端库给的，从新到旧）→ 协议的一页（从旧到新）。消息与系统提示合起来不超过 `limit` 条：
/// 多出来的（更早的）留给下一页，游标停在留下的最早一条。撤回动作本身、不用给人看的提示不占条数。
pub(crate) async fn history_page(
    live: &Live,
    conv: &ConvId,
    items: Vec<HistoryItem>,
    more: bool,
    limit: usize,
) -> Page<hhh_im_protocol::types::Message> {
    let mut uids = Vec::new();
    for item in &items {
        match item {
            HistoryItem::Message(m) => uids.extend(push::mentioned(m)),
            HistoryItem::Rejected { sender, .. } => uids.push(sender.clone()),
            HistoryItem::Notice(n) => uids.extend(translate::notice_people(n)),
        }
    }
    let names = live.names(uids).await;
    let mut kept = Vec::new();
    let mut truncated = false;
    let mut oldest = None;
    for item in &items {
        // 翻到的个人资料照记（新电脑、重启后从历史里重新认识别人的头像）。
        if let HistoryItem::Message(m) = item
            && let Some(Content::Profile { avatar, photo }) = &m.content
        {
            let key = super::profile::profile_key(avatar.as_deref(), photo.as_ref());
            push::profile_seen(live, &m.sender, m.log, key).await;
        }
        let wire = match item {
            HistoryItem::Message(m) => translate::message(m, &names),
            HistoryItem::Rejected {
                id, ts_ms, sender, ..
            } => Some(translate::unreadable(
                conv.as_str(),
                id,
                sender,
                *ts_ms,
                &names,
            )),
            HistoryItem::Notice(n) => translate::notice(n, &names, &live.me),
        };
        if let Some(wire) = wire {
            if kept.len() == limit {
                truncated = true;
                break;
            }
            if let HistoryItem::Message(m) = item {
                live.remember(&wire.id, &m.sender, m.ts_ms);
            }
            kept.push(wire);
        }
        oldest = Some(item.log());
    }
    let next = (truncated || more)
        .then(|| oldest.map(translate::cursor))
        .flatten();
    kept.reverse();
    Page { items: kept, next }
}

#[cfg(test)]
mod tests {
    use super::*;
    use friend_im_client::core::bytes::Fixed;
    use friend_im_client::core::ids::{DeviceId, InviteId};
    use friend_im_client::{ConvNotice, Message, Notice};

    fn uid(n: u8) -> Uid {
        Uid::from_raw([n; 16])
    }

    fn message(log: u64, ts_ms: i64, sender: u8, content: Option<Content>) -> HistoryItem {
        HistoryItem::Message(Message {
            conv: ConvId::from_raw([1; 16]),
            id: MsgId::from_raw([log as u8; 16]),
            log,
            ts_ms,
            sender: uid(sender),
            sender_eldest: Fixed([0; 32]),
            device: DeviceId::from_raw([sender; 16]),
            ctime_ms: ts_ms,
            content,
        })
    }

    fn post(log: u64, ts_ms: i64, sender: u8) -> HistoryItem {
        let parts = vec![Part::Text {
            text: "在吗".into(),
        }];
        message(
            log,
            ts_ms,
            sender,
            Some(Content::Post {
                parts,
                reply_to: None,
            }),
        )
    }

    fn notice(log: u64, ctime_ms: i64, author: u8, change: ConvNotice) -> HistoryItem {
        HistoryItem::Notice(Notice {
            conv: ConvId::from_raw([1; 16]),
            log,
            ctime_ms,
            author: uid(author),
            change,
        })
    }

    #[test]
    fn what_nobody_sees_is_not_someone_sending_a_message() {
        // 自己的电脑发的头像资料、撤回、换钥匙，以及被撤回只剩“已撤回”的那条：删掉的会话不该因为它们回来。
        let me = uid(1);
        let profile = Content::Profile {
            avatar: None,
            photo: None,
        };
        let recall = Content::Recall {
            target: MsgId::from_raw([9; 16]),
        };
        let items = [
            message(14, 140, 1, Some(profile.clone())),
            message(13, 130, 2, Some(profile)),
            message(12, 120, 2, Some(recall)),
            message(11, 110, 2, None),
            notice(10, 100, 2, ConvNotice::Rotated),
        ];
        assert_eq!(Seen::add(None, &items, &me), None);
    }

    #[test]
    fn messages_unreadable_ones_and_shown_notices_count_with_who_sent_them() {
        let me = uid(1);
        // 只有自己发的：算有消息，但不是别人发的（私聊不带对方编号）。
        let mine = [post(5, 500, 1)];
        assert_eq!(
            Seen::add(None, &mine, &me),
            Some(Seen {
                first_ms: 500,
                latest_ms: 500,
                others: false
            })
        );
        // 对方的一条、解不开的一条、对方签的“你重置了账号”：时间取最早与最新，有别人发的。
        let theirs = [
            post(8, 800, 2),
            HistoryItem::Rejected {
                id: MsgId::from_raw([7; 16]),
                log: 7,
                ts_ms: 700,
                sender: uid(2),
                reason: "解不开".into(),
            },
            notice(6, 600, 2, ConvNotice::MemberReset { uid: me.clone() }),
        ];
        let seen = Seen::add(Seen::add(None, &mine, &me), &theirs, &me);
        assert_eq!(
            seen,
            Some(Seen {
                first_ms: 500,
                latest_ms: 800,
                others: true
            })
        );
        // 群邀请链接的发出不给人看，不算。
        let invite = notice(
            9,
            900,
            2,
            ConvNotice::InviteCreated {
                invite: InviteId::from_raw([4; 16]),
            },
        );
        assert_eq!(Seen::add(seen, &[invite], &me), seen);
    }

    #[test]
    fn send_ids_are_stable_per_account_and_operation() {
        let me = Uid::from_raw([1; 16]);
        assert_eq!(send_id(&me, "op-1"), send_id(&me, "op-1"));
        assert_ne!(send_id(&me, "op-1"), send_id(&me, "op-2"));
        assert_ne!(
            send_id(&me, "op-1"),
            send_id(&Uid::from_raw([2; 16]), "op-1")
        );
    }

    #[test]
    fn offset_pages_and_cursors() {
        let page = slice((0..5).collect::<Vec<_>>(), 0, 2);
        assert_eq!((page.items, page.next.as_deref()), (vec![0, 1], Some("o2")));
        let page = slice(
            (0..5).collect::<Vec<_>>(),
            offset_of(Some("o4")).unwrap(),
            2,
        );
        assert_eq!((page.items, page.next), (vec![4], None));
        assert!(offset_of(Some("x")).is_err());
    }

    #[test]
    fn mime_types_from_content_or_name() {
        let png = [
            0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, b'I', b'H', b'D', b'R', 0,
            0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0,
        ];
        assert_eq!(mime_of("x.bin", true, &png), "image/png");
        assert_eq!(mime_of("报告.PDF", false, &[]), "application/pdf");
        assert_eq!(mime_of("无后缀", false, &[]), "application/octet-stream");
    }
}
