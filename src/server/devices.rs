//! 设备之间同步，接到插件上（契约 friend-im v10，方案 plan-v10 §4–§9）。
//!
//! 一个任务独占对账引擎，所有事情排队进来：发消息、撤回和刚发出来的消息在前（[`Devices::urgent`]），其余收到的帧、在线变化在后，所以补历史时
//! 收发新消息不受影响。引擎要的“宿主存储”是 [`HostStore`]：读走 `store/*`（provider-protocol v53），写走 `events/push`，
//! 宿主回了才算写好。插件自己不存聊天记录，进程重启后索引从宿主重建。
//!
//! 文件不进引擎：要一段时向在线、有权的设备一个一个问，帧本身端到端加密，内容摘要随消息签名、由宿主在收完后核对。

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use friend_im_client::ClientError;
use friend_im_client::core::bytes::{Bytes, Fixed};
use friend_im_client::core::file::FileRef;
use friend_im_client::core::ids::{ConvId, DeviceId, FileId, MsgId};
use friend_im_client::core::message::Content;
use friend_im_client::core::reading::ReadingEnvelope;
use friend_im_client::core::sync::{self as keys, Key, next_at};
use friend_im_client::peers::{ClientAuthority, Opened, RAW_FORMAT};
use friend_im_client::sync::{Applied, Engine, PeerFrame, Store, StoredItem, StoredRecord, SyncError, Write};
use hhh_im_protocol::method::EventsPushParams;
use hhh_im_protocol::rpc::code;
use hhh_im_protocol::store_read::{
    StoreConversationsParams, StoreConversationsResult, StoreIndexParams, StoreIndexResult, StoreMessagesParams, StoreMessagesResult,
    StoreResourceParams, StoreResourceResult,
};
use hhh_im_protocol::types::{Event, Message as Wire, Raw};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::{mpsc, oneshot};
use tokio::task::AbortHandle;

use super::session::Live;
use super::{Server, push, translate};

/// 每隔多久和在线设备把共享的会话都对一遍，索引也从宿主重建一次（用户可能清过本机记录）。
const TICK: Duration = Duration::from_secs(600);
/// 问一台设备要一段文件至多等多久。
const FILE_WAIT: Duration = Duration::from_secs(15);
/// 一帧至多带多少文件字节。
const FILE_FRAME_BYTES: u64 = 256 * 1024;
/// 都说没有时再问几轮：发送方的宿主可能还没把文件存好。
const FILE_ROUNDS: usize = 3;
/// 两轮之间等多久。
const FILE_ROUND_GAP: Duration = Duration::from_millis(500);
/// 读宿主被限流或库还没打开时最多重试几次。
const STORE_RETRIES: u32 = 7;

/// 文件请求的回答。
enum FileAnswer {
    Chunk { data: Vec<u8>, total: u64 },
    Missing,
}

/// 排给对账任务的事。
enum Command {
    Connected,
    Disconnected,
    Presence { device: DeviceId, online: bool },
    Frame { from: DeviceId, frame: PeerFrame },
    Changed { conv: ConvId },
    Send { conv: ConvId, id: MsgId, content: Content, reply: oneshot::Sender<Result<i64, ClientError>> },
    Recall { conv: ConvId, target: MsgId, reply: oneshot::Sender<Result<(), ClientError>> },
    Reading { conv: ConvId, envelope: ReadingEnvelope },
    Announce { conv: ConvId },
    Sharing { conv: ConvId, reply: oneshot::Sender<Vec<DeviceId>> },
}

/// 对账任务的入口。
pub(crate) struct Devices {
    urgent: mpsc::UnboundedSender<Command>,
    commands: mpsc::UnboundedSender<Command>,
    files: Mutex<HashMap<u64, oneshot::Sender<FileAnswer>>>,
    next: AtomicU64,
}

/// [`Devices`] 的另一头，开任务时交给它。
pub(crate) struct Inbox {
    urgent: mpsc::UnboundedReceiver<Command>,
    commands: mpsc::UnboundedReceiver<Command>,
}

fn gone() -> ClientError {
    ClientError::state("Cindy IM 已经下线")
}

impl Devices {
    pub(crate) fn new() -> (Self, Inbox) {
        let (urgent, urgent_rx) = mpsc::unbounded_channel();
        let (commands, commands_rx) = mpsc::unbounded_channel();
        (
            Self { urgent, commands, files: Mutex::new(HashMap::new()), next: AtomicU64::new(1) },
            Inbox { urgent: urgent_rx, commands: commands_rx },
        )
    }

    fn post(&self, command: Command) {
        // 任务停了（下线了）：没什么要做的了。
        let _ = self.commands.send(command);
    }

    pub(crate) fn connected(&self) {
        self.post(Command::Connected);
    }

    pub(crate) fn disconnected(&self) {
        self.post(Command::Disconnected);
    }

    pub(crate) fn presence(&self, device: DeviceId, online: bool) {
        self.post(Command::Presence { device, online });
    }

    pub(crate) fn frame(&self, from: DeviceId, frame: PeerFrame) {
        let queue = if frame.is_live() { &self.urgent } else { &self.commands };
        let _ = queue.send(Command::Frame { from, frame });
    }

    /// 会话的成员变了：和新成员对一遍。
    pub(crate) fn changed(&self, conv: ConvId) {
        self.post(Command::Changed { conv });
    }

    /// 把个人资料交给在线的会话成员。
    pub(crate) fn announce(&self, conv: ConvId) {
        self.post(Command::Announce { conv });
    }

    /// 把本设备新的已读记录交给在线的设备。
    pub(crate) fn reading(&self, conv: ConvId, envelope: ReadingEnvelope) {
        self.post(Command::Reading { conv, envelope });
    }

    /// 发一条消息：写进宿主、投给在线设备，返回排序时间。
    pub(crate) async fn send(&self, conv: &ConvId, id: &MsgId, content: Content) -> Result<i64, ClientError> {
        let (reply, answer) = oneshot::channel();
        self.urgent.send(Command::Send { conv: conv.clone(), id: id.clone(), content, reply }).map_err(|_| gone())?;
        answer.await.map_err(|_| gone())?
    }

    /// 撤回自己的一条。
    pub(crate) async fn recall(&self, conv: &ConvId, target: &MsgId) -> Result<(), ClientError> {
        let (reply, answer) = oneshot::channel();
        self.urgent.send(Command::Recall { conv: conv.clone(), target: target.clone(), reply }).map_err(|_| gone())?;
        answer.await.map_err(|_| gone())?
    }

    async fn sharing(&self, conv: &ConvId) -> Vec<DeviceId> {
        let (reply, answer) = oneshot::channel();
        if self.urgent.send(Command::Sharing { conv: conv.clone(), reply }).is_err() {
            return Vec::new();
        }
        answer.await.unwrap_or_default()
    }

    /// 文件的回答到了。
    pub(crate) fn file_answer(&self, frame: PeerFrame) {
        let (req, answer) = match frame {
            PeerFrame::FileChunk { req, data, total } => (req, FileAnswer::Chunk { data: data.0, total }),
            PeerFrame::FileMissing { req } => (req, FileAnswer::Missing),
            _ => return,
        };
        if let Some(waiting) = self.files.lock().expect("文件等待表锁中毒").remove(&req) {
            let _ = waiting.send(answer);
        }
    }

    async fn ask_file(&self, live: &Live, peer: &DeviceId, conv: &ConvId, key: &str, offset: u64, length: u64) -> Option<FileAnswer> {
        let req = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.files.lock().expect("文件等待表锁中毒").insert(req, tx);
        let frame = PeerFrame::FileWant { req, conv: conv.clone(), key: key.to_owned(), offset, length };
        let sent = live.client.send_frame(peer, Some(conv), &frame).await;
        let answer = match sent {
            Ok(true) => tokio::time::timeout(FILE_WAIT, rx).await.ok().and_then(Result::ok),
            _ => None,
        };
        self.files.lock().expect("文件等待表锁中毒").remove(&req);
        answer
    }

    /// 向在线、有权的设备要一段文件，自己的设备优先。谁都没有时报“暂时读不到”，之后可以重试。
    async fn fetch_part(&self, live: &Live, conv: &ConvId, key: &str, offset: u64, length: u64) -> Result<(Vec<u8>, u64), ClientError> {
        for round in 0..FILE_ROUNDS {
            if round > 0 {
                tokio::time::sleep(FILE_ROUND_GAP).await;
            }
            for peer in self.sharing(conv).await {
                if let Some(FileAnswer::Chunk { data, total }) = self.ask_file(live, &peer, conv, key, offset, length).await {
                    return Ok((data, total));
                }
            }
        }
        Err(ClientError::Transfer("现在没有在线的设备有这个文件，等有设备上线后再试。".into()))
    }

    /// 读文件的一段：至多 `length` 字节，读到文件尾就少给。
    pub(crate) async fn fetch(&self, live: &Live, conv: &ConvId, key: &str, offset: u64, length: u64) -> Result<Vec<u8>, ClientError> {
        let mut out = Vec::new();
        while (out.len() as u64) < length {
            let at = offset + out.len() as u64;
            let part = (length - out.len() as u64).min(FILE_FRAME_BYTES);
            let (data, total) = self.fetch_part(live, conv, key, at, part).await?;
            let finished = data.is_empty() || at + data.len() as u64 >= total;
            out.extend(data);
            if finished {
                break;
            }
        }
        Ok(out)
    }
}

/// 开始对账任务。
pub(crate) fn start(server: Arc<Server>, live: Arc<Live>, inbox: Inbox) -> AbortHandle {
    tokio::spawn(run(server, live, inbox)).abort_handle()
}

/// 宿主存储：读走 `store/*`，写走 `events/push`。
pub(crate) struct HostStore {
    server: Arc<Server>,
    live: Arc<Live>,
}

impl HostStore {
    pub(crate) fn new(server: Arc<Server>, live: Arc<Live>) -> Self {
        Self { server, live }
    }

    /// 问宿主一次。被限流、库还没打开时退避重试；缺 `items`（旧宿主回了空对象）算不支持。
    async fn ask<T: DeserializeOwned>(&self, method: &str, params: impl Serialize) -> Result<T, String> {
        let params = serde_json::to_value(params).map_err(|error| error.to_string())?;
        let mut delay = Duration::from_millis(100);
        for attempt in 0..STORE_RETRIES {
            match self.server.peer.request(method, &params).await {
                Ok(value) => return serde_json::from_value(value).map_err(|_| format!("这个 HHH 太旧了，{method} 回的看不懂")),
                Err(error) if matches!(error.code, code::LIMIT_EXCEEDED | code::DISCONNECTED) && attempt + 1 < STORE_RETRIES => {
                    tracing::debug!(method, code = error.code, "读宿主要再等等");
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                }
                Err(error) => return Err(format!("{method} 没成：{}", error.code)),
            }
        }
        Err(format!("{method} 一直没成"))
    }

    fn digest_of(text: &str) -> Option<Fixed<16>> {
        if text.len() != 32 {
            return None;
        }
        let mut out = [0u8; 16];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
        }
        Some(Fixed(out))
    }

    /// 按编号取消息。放不下时宿主分页，这里取到头。
    pub(crate) async fn messages(&self, conv: &ConvId, ids: &[MsgId]) -> Result<Vec<Wire>, String> {
        let mut out = Vec::with_capacity(ids.len());
        for chunk in ids.chunks(hhh_im_protocol::budget::STORE_MESSAGE_IDS_MAX) {
            let list: Vec<String> = chunk.iter().map(ToString::to_string).collect();
            let mut cursor = None;
            loop {
                let params = StoreMessagesParams { conversation_id: conv.to_string(), ids: list.clone(), cursor, limit: None };
                let page: StoreMessagesResult = self.ask("store/messages", params).await?;
                out.extend(page.items);
                cursor = page.next;
                if cursor.is_none() {
                    break;
                }
            }
        }
        Ok(out)
    }

    /// 一批要写的翻成协议的消息；解不开的（不该发生，刚验过）跳过并记日志。
    async fn wire_of(&self, conv: &ConvId, write: Write) -> Option<Wire> {
        let (key, raw, tomb) = match write {
            Write::Full { key, raw } => (key, raw, false),
            Write::Tombstone { key, raw } => (key, raw, true),
        };
        let opened = match self.live.client.open_record(conv, &raw).await {
            Ok(opened) => opened,
            Err(error) => {
                tracing::warn!(%conv, id = %key.id, %error, "刚验过的原件解不开，不写进宿主");
                return None;
            }
        };
        let mut wire = match opened {
            Opened::Message(message) if !tomb => {
                let names = self.live.names(push::mentioned(&message)).await;
                translate::message(&message, &names)?
            }
            Opened::Tombstone { sender, .. } if tomb => {
                let names = self.live.names([sender.clone()]).await;
                translate::recalled(conv.as_str(), &key.id, &sender, key.at, &names)
            }
            _ => return None,
        };
        wire.read_position = Some(keys::read_position(&key));
        wire.raw = Some(Raw { format: RAW_FORMAT.into(), data: raw });
        Some(wire)
    }
}

impl Store for HostStore {
    async fn conversations(&mut self) -> Result<Vec<ConvId>, String> {
        let mut convs = BTreeSet::new();
        let mut cursor = None;
        loop {
            let page: StoreConversationsResult = self.ask("store/conversations", StoreConversationsParams { cursor, limit: None }).await?;
            convs.extend(page.items.iter().filter_map(|item| ConvId::parse(&item.conversation_id).ok()));
            cursor = page.next;
            if cursor.is_none() {
                break;
            }
        }
        // 新设备的宿主是空的：服务器的会话列表补上，它才知道要向别人要什么。
        match self.live.client.convs().await {
            Ok(summaries) => convs.extend(summaries.into_iter().map(|summary| summary.conv)),
            Err(error) => tracing::debug!(%error, "这会儿取不到会话列表，只看宿主里有的"),
        }
        Ok(convs.into_iter().collect())
    }

    async fn index(&mut self, conv: &ConvId) -> Result<Vec<StoredItem>, String> {
        let mut items = Vec::new();
        let mut cursor = None;
        loop {
            let params = StoreIndexParams { conversation_id: conv.to_string(), cursor, limit: None };
            let page: StoreIndexResult = self.ask("store/index", params).await?;
            for item in page.items {
                // 系统提示（`n-…`）与没有原件的旧消息不进对账集合。
                let (Ok(id), Some(raw)) = (MsgId::parse(&item.id), item.raw_digest.as_deref().and_then(Self::digest_of)) else {
                    continue;
                };
                items.push(StoredItem { id, at: item.created_at_ms, tomb: item.deleted, raw: (!item.deleted).then_some(raw) });
            }
            cursor = page.next;
            if cursor.is_none() {
                break;
            }
        }
        Ok(items)
    }

    async fn records(&mut self, conv: &ConvId, ids: &[MsgId]) -> Result<Vec<StoredRecord>, String> {
        let messages = self.messages(conv, ids).await?;
        Ok(messages
            .into_iter()
            .filter_map(|message| {
                let raw = message.raw.filter(|raw| raw.format == RAW_FORMAT)?;
                Some(StoredRecord { id: MsgId::parse(&message.id).ok()?, raw: raw.data })
            })
            .collect())
    }

    async fn write(&mut self, conv: &ConvId, writes: Vec<Write>) -> Result<(), String> {
        let mut messages = Vec::with_capacity(writes.len());
        for write in writes {
            messages.extend(self.wire_of(conv, write).await);
        }
        let mut events = Vec::new();
        let mut left = false;
        if !self.live.knows_conversation(conv) {
            match self.live.conversation(conv).await {
                Ok(conversation) => events.push(Event::Conversation { conversation }),
                Err(error) => tracing::info!(%conv, %error, "会话资料取不到，先不推会话"),
            }
            left = self.live.client.conv_info(conv).await.is_ok_and(|info| !info.member);
        }
        events.push(Event::Messages { conversation_id: conv.to_string(), messages });
        if left {
            // 离开前的记录照样同步到自己的设备，但会话不回到列表里。
            events.push(Event::ConversationRemoved { conversation_id: conv.to_string() });
        }
        let params = EventsPushParams { events, sync_state: None };
        self.server.peer.request("events/push", &params).await.map(|_| ()).map_err(|error| format!("宿主没收下：{}", error.code))
    }
}

type Sync = Engine<HostStore, ClientAuthority>;

/// 把引擎攒下的帧发出去。对方不在线就从在线名单里去掉，下次它上线再对。
async fn flush(engine: &mut Sync, live: &Live) {
    for (to, frame) in engine.drain() {
        let conv = match &frame {
            PeerFrame::Sync { conv, .. } | PeerFrame::Want { conv, .. } | PeerFrame::Have { conv, .. } | PeerFrame::Deny { conv } => Some(conv.clone()),
            _ => None,
        };
        match live.client.send_frame(&to, conv.as_ref(), &frame).await {
            Ok(true) => {}
            Ok(false) => engine.peer_offline(&to),
            Err(error) => tracing::debug!(device = %to, %error, "这一帧没发出去，下次对账再来"),
        }
    }
}

/// 个人资料的原件：每个会话封一次，换了头像再封。
#[derive(Default)]
struct Profiles {
    sealed: HashMap<ConvId, (String, String)>,
}

impl Profiles {
    async fn frame(&mut self, server: &Server, live: &Live, conv: &ConvId) -> Option<PeerFrame> {
        if live.read_only {
            return None;
        }
        let photo = server.photo.lock().expect("头像锁中毒").clone()?;
        let raw = match self.sealed.get(conv) {
            Some((sha256, raw)) if *sha256 == photo.sha256 => raw.clone(),
            _ => {
                let content = Content::Profile { avatar: None, photo: Some(photo_ref(&photo)) };
                let at = live.client.now_ms().await;
                match live.client.seal(conv, &MsgId::random(), content, at).await {
                    Ok((raw, _)) => {
                        self.sealed.insert(conv.clone(), (photo.sha256.clone(), raw.clone()));
                        raw
                    }
                    Err(error) => {
                        tracing::debug!(%conv, %error, "这个会话发不了个人资料");
                        return None;
                    }
                }
            }
        };
        Some(PeerFrame::Profile { conv: conv.clone(), raw, photo: Some(Bytes(photo.bytes.as_ref().clone())) })
    }
}

/// 头像写成文件引用：编号和钥匙由内容算出来，同一张头像在每个会话里键都一样。
fn photo_ref(photo: &super::profile::HostPhoto) -> FileRef {
    use sha2::{Digest, Sha256};
    let digest: [u8; 32] = Sha256::digest(photo.bytes.as_slice()).into();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    let name = if photo.mime == "image/jpeg" { "avatar.jpg" } else { "avatar.png" };
    FileRef {
        id: FileId::from_raw(id),
        key: Fixed(digest),
        size: photo.bytes.len() as u64,
        name: name.into(),
        mime: photo.mime.clone(),
        sha256: Some(Fixed(digest)),
    }
}

/// 除了消息之外要交给一台设备的：已读记录、个人资料。
async fn share_extras(server: &Server, live: &Live, profiles: &mut Profiles, peer: &DeviceId, conv: &ConvId) {
    let records = live.client.reading_records(conv).await;
    if !records.is_empty() {
        send_one(live, peer, conv, PeerFrame::Reading { conv: conv.clone(), records }).await;
    }
    if let Some(frame) = profiles.frame(server, live, conv).await {
        send_one(live, peer, conv, frame).await;
    }
}

async fn send_one(live: &Live, peer: &DeviceId, conv: &ConvId, frame: PeerFrame) {
    if let Err(error) = live.client.send_frame(peer, Some(conv), &frame).await {
        tracing::debug!(device = %peer, %error, "这一帧没发出去，下次对账再来");
    }
}

/// 和一台设备对一遍全部共享的会话，再把已读与个人资料交给它。
async fn meet(engine: &mut Sync, server: &Server, live: &Live, profiles: &mut Profiles, peer: &DeviceId) {
    if let Err(error) = engine.peer_online(peer).await {
        tracing::info!(device = %peer, %error, "这次和对方对账没开始，下次再来");
        return;
    }
    let convs = match engine.store_mut().conversations().await {
        Ok(convs) => convs,
        Err(error) => {
            tracing::info!(%error, "读不到会话，已读与个人资料下次再交");
            return;
        }
    };
    for conv in convs {
        if engine.auth_mut().may_share_now(&conv, peer).await {
            share_extras(server, live, profiles, peer, &conv).await;
        }
    }
}

/// 连上了：问服务器现在谁在线，一个一个对。
async fn meet_everyone(engine: &mut Sync, server: &Server, live: &Live, profiles: &mut Profiles) {
    let peers = match live.client.peers().await {
        Ok(peers) => peers,
        Err(error) => {
            tracing::info!(%error, "问在线设备没成");
            return;
        }
    };
    for peer in peers {
        meet(engine, server, live, profiles, &peer.device).await;
    }
}

async fn on_send(engine: &mut Sync, live: &Live, conv: &ConvId, id: &MsgId, content: Content) -> Result<i64, ClientError> {
    let seen = engine.seen_max(conv).await.map_err(stored)?;
    let at = next_at(live.client.now_ms().await, seen);
    let (raw, at) = live.client.seal(conv, id, content, at).await?;
    let Applied { rejected, .. } = engine.local(conv, raw).await.map_err(stored)?;
    if rejected > 0 {
        return Err(ClientError::state("这条消息没有通过本机核对"));
    }
    Ok(at)
}

async fn on_recall(engine: &mut Sync, live: &Live, conv: &ConvId, target: &MsgId) -> Result<(), ClientError> {
    let Key { at: target_at, .. } = engine.key_of(conv, target).await.map_err(stored)?.ok_or_else(|| ClientError::state("这条消息不在本机，撤回不了"))?;
    let seen = engine.seen_max(conv).await.map_err(stored)?;
    let at = next_at(live.client.now_ms().await, seen);
    let content = Content::Recall { target: target.clone(), target_at };
    let (raw, _) = live.client.seal(conv, &MsgId::random(), content, at).await?;
    let applied = engine.local(conv, raw).await.map_err(stored)?;
    if applied.rejected > 0 {
        return Err(ClientError::state("只能撤回自己的消息"));
    }
    Ok(())
}

fn stored(error: SyncError) -> ClientError {
    ClientError::state(format!("本机没有保存成功：{}", error.0))
}

/// 收到别的设备要文件：有权才给，宿主里没有就说没有，不替它下载。
#[allow(clippy::too_many_arguments)]
async fn serve_file(server: Arc<Server>, live: Arc<Live>, from: DeviceId, req: u64, conv: ConvId, key: String, offset: u64, length: u64) {
    let length = length.clamp(1, FILE_FRAME_BYTES);
    let reply = if !live.client.may_share(&conv, &from).await {
        tracing::info!(device = %from, %conv, "对方无权拿这个会话的文件");
        PeerFrame::FileMissing { req }
    } else if let Some(bytes) = server.avatars.cached(&key) {
        // 刚发出的视频封面只在内存里。
        let total = bytes.len() as u64;
        let start = offset.min(total) as usize;
        let end = (offset + length).min(total) as usize;
        PeerFrame::FileChunk { req, data: Bytes(bytes[start..end].to_vec()), total }
    } else {
        let params = StoreResourceParams { key, offset, length };
        match server.peer.request("store/resource", &params).await.map(serde_json::from_value::<StoreResourceResult>) {
            Ok(Ok(chunk)) => {
                use base64::Engine as _;
                match base64::engine::general_purpose::STANDARD.decode(chunk.data) {
                    Ok(data) => PeerFrame::FileChunk { req, data: Bytes(data), total: chunk.total },
                    Err(_) => PeerFrame::FileMissing { req },
                }
            }
            _ => PeerFrame::FileMissing { req },
        }
    };
    send_one(&live, &from, &conv, reply).await;
}

/// 收到别的设备的已读记录：并进来，变了就告诉宿主。
async fn on_reading(server: &Server, live: &Live, conv: &ConvId, records: Vec<ReadingEnvelope>) {
    match live.client.merge_reading(conv, records).await {
        Ok(true) => server.reading_changed(live, conv).await,
        Ok(false) => {}
        Err(error) => tracing::info!(%conv, %error, "这份已读记录这会儿验不了，下次对账再来"),
    }
}

async fn on_profile(server: &Server, live: &Live, conv: &ConvId, raw: String, photo: Option<Bytes>) {
    let message = match live.client.open_record(conv, &raw).await {
        Ok(Opened::Message(message)) => message,
        Ok(_) => return,
        Err(error) => {
            tracing::info!(%conv, %error, "一份个人资料验不过，丢掉");
            return;
        }
    };
    let Content::Profile { avatar, photo: file } = &message.content else {
        return;
    };
    if let (Some(file), Some(bytes)) = (file, photo) {
        if !super::profile::photo_fits(file, &bytes.0) {
            tracing::warn!(%conv, "个人资料带的头像和它写的对不上，丢掉");
            return;
        }
        server.avatars.remember(&super::profile::photo_key(file), Arc::new(bytes.0));
    }
    let key = super::profile::profile_key(avatar.as_deref(), file.as_ref());
    push::profile_seen(live, &message.sender, message.ctime_ms.max(0) as u64, key).await;
}

async fn handle(engine: &mut Sync, server: &Arc<Server>, live: &Arc<Live>, profiles: &mut Profiles, command: Command) {
    match command {
        Command::Connected => {
            engine.invalidate_all();
            meet_everyone(engine, server, live, profiles).await;
        }
        Command::Disconnected => engine.clear_online(),
        Command::Presence { device, online: true } => meet(engine, server, live, profiles, &device).await,
        Command::Presence { device, online: false } => engine.peer_offline(&device),
        Command::Frame { from, frame } => match frame {
            PeerFrame::Reading { conv, records } => {
                if live.client.may_share(&conv, &from).await {
                    on_reading(server, live, &conv, records).await;
                }
            }
            PeerFrame::Profile { conv, raw, photo } => {
                if live.client.may_share(&conv, &from).await {
                    on_profile(server, live, &conv, raw, photo).await;
                }
            }
            PeerFrame::FileWant { req, conv, key, offset, length } => {
                let task = tokio::spawn(serve_file(server.clone(), live.clone(), from, req, conv, key, offset, length));
                live.hold(task.abort_handle());
            }
            frame => {
                if let Err(error) = engine.on_frame(&from, frame).await {
                    tracing::info!(device = %from, %error, "这一帧没处理完，下次对账再来");
                }
            }
        },
        Command::Changed { conv } => {
            if let Ok(peers) = live.client.peers().await {
                for peer in peers {
                    if engine.auth_mut().may_share_now(&conv, &peer.device).await {
                        engine.peer_seen(&peer.device);
                        if let Err(error) = engine.sync_with(&peer.device, &conv).await {
                            tracing::info!(%conv, %error, "新成员的对账没开始");
                        }
                        share_extras(server, live, profiles, &peer.device, &conv).await;
                    }
                }
            }
        }
        Command::Send { conv, id, content, reply } => {
            let _ = reply.send(on_send(engine, live, &conv, &id, content).await);
        }
        Command::Recall { conv, target, reply } => {
            let _ = reply.send(on_recall(engine, live, &conv, &target).await);
        }
        Command::Reading { conv, envelope } => {
            for peer in engine.sharing(&conv).await {
                send_one(live, &peer, &conv, PeerFrame::Reading { conv: conv.clone(), records: vec![envelope.clone()] }).await;
            }
        }
        Command::Announce { conv } => {
            if let Some(frame) = profiles.frame(server, live, &conv).await {
                for peer in engine.sharing(&conv).await {
                    send_one(live, &peer, &conv, frame.clone()).await;
                }
            }
        }
        Command::Sharing { conv, reply } => {
            // 自己的设备优先。
            let mut mine = Vec::new();
            let mut others = Vec::new();
            for peer in engine.sharing(&conv).await {
                if live.client.owns_device(&peer).await { mine.push(peer) } else { others.push(peer) }
            }
            mine.extend(others);
            let _ = reply.send(mine);
        }
    }
}

async fn run(server: Arc<Server>, live: Arc<Live>, mut inbox: Inbox) {
    let store = HostStore { server: server.clone(), live: live.clone() };
    let mut engine = Engine::new(store, ClientAuthority::new(live.client.clone()));
    let mut profiles = Profiles::default();
    let mut tick = tokio::time::interval(TICK);
    tick.tick().await;
    server.backfill_notices(&live).await;
    meet_everyone(&mut engine, &server, &live, &mut profiles).await;
    flush(&mut engine, &live).await;
    loop {
        tokio::select! {
            biased;
            command = inbox.urgent.recv() => {
                let Some(command) = command else { break };
                handle(&mut engine, &server, &live, &mut profiles, command).await;
            }
            command = inbox.commands.recv() => {
                let Some(command) = command else { break };
                handle(&mut engine, &server, &live, &mut profiles, command).await;
            }
            _ = tick.tick() => {
                engine.invalidate_all();
                if let Err(error) = engine.sync_all().await {
                    tracing::info!(%error, "这轮兜底对账没开始");
                }
            }
        }
        flush(&mut engine, &live).await;
    }
    tracing::info!("设备同步结束");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_are_read_back_exactly() {
        assert_eq!(HostStore::digest_of(&"ab".repeat(16)), Some(Fixed([0xab; 16])));
        assert_eq!(HostStore::digest_of("ab"), None);
        assert_eq!(HostStore::digest_of(&"zz".repeat(16)), None);
    }
}
