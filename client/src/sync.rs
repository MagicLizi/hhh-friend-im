//! 设备之间的同步引擎（契约 friend-im v10，方案 plan-v10 §3–§7）。
//!
//! 引擎不碰网络、不自己存东西：
//! - 消息存在宿主里（插件经 provider-protocol v53 读回），引擎经 [`Store`] 读写；
//! - 谁有权拿哪个会话、一条原件验不验得过，问 [`Authority`]（插件按自己验过的签名链回答）；
//! - 要发给别的设备的帧放进发件箱（[`Engine::drain`]），由调用方经局域网或服务器转交送出。
//!
//! 所以同一份引擎既接真网络，也能在确定性的模拟里跑成千上万种离线、乱序、重启的场景（`tests/sync_sim.rs`）。
//!
//! 规则：
//! - 对账伙伴只限 [`Authority::may_share`] 说可以的设备（同账号，或双方都是会话的当前成员）；不可以的回 `Deny`。
//! - 一条原件先验签、核对成员资格，才写进宿主、并进索引；验不过的丢掉（实现方记日志，不记正文）。
//! - 撤回不单独成元素：被撤回的那条变成墓碑，墓碑里带着撤回原件，补给别人时就交这份。墓碑永远胜过原文；
//!   撤回者不是原发送者的（伪造）：本机有原文就拒绝并把原文回给对方，没有原文先记成墓碑，原文到了再换回。

use std::collections::{HashMap, HashSet};

use friend_im_core::bytes::{Bytes, Fixed};
use friend_im_core::ids::{ConvId, DeviceId, MsgId};
use friend_im_core::reading::ReadingEnvelope;
use friend_im_core::sync::{self, Index, Item, Key, Range, State};
use serde::{Deserialize, Serialize};

/// 一个 `Have` 帧里原件的总字节数上限，超出分成几帧。
pub const HAVE_BYTES_MAX: usize = 512 * 1024;
/// 一个 `Have` 帧里至多几份原件。
pub const HAVE_RECORDS_MAX: usize = 500;
/// 一个 `Want` 帧里至多几个编号。
pub const WANT_MAX: usize = 500;

/// 设备之间的帧。由调用方加密、签名后经局域网或服务器转交（服务器只看到密文）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PeerFrame {
    /// 对账消息（发起或回应）。
    Sync {
        /// 会话。
        conv: ConvId,
        /// 段。
        ranges: Vec<Range>,
    },
    /// 我缺这些，请给我。
    Want {
        /// 会话。
        conv: ConvId,
        /// 编号。
        ids: Vec<MsgId>,
    },
    /// 原件（宿主里存的原样字符串：消息原件或墓碑）。
    Have {
        /// 会话。
        conv: ConvId,
        /// 原件。
        records: Vec<String>,
    },
    /// 你无权拿这个会话的东西（或我不认识这个会话）。
    Deny {
        /// 会话。
        conv: ConvId,
    },
    /// 各设备的已读记录（设备签名、会话钥匙加密）。不进对账集合，每台设备取最新的一份。
    Reading {
        /// 会话。
        conv: ConvId,
        /// 记录。
        records: Vec<ReadingEnvelope>,
    },
    /// 发送人的个人资料：不进对账集合，直接交给在线的会话成员，头像字节随帧带着。
    Profile {
        /// 会话。
        conv: ConvId,
        /// 个人资料消息的原件。
        raw: String,
        /// 头像字节。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        photo: Option<Bytes>,
    },
    /// 我要这个文件的这一段。
    FileWant {
        /// 请求编号（回复原样带回）。
        req: u64,
        /// 会话。
        conv: ConvId,
        /// 资源键。
        key: String,
        /// 从第几个字节。
        offset: u64,
        /// 要多少字节。
        length: u64,
    },
    /// 文件的一段。
    FileChunk {
        /// 请求编号。
        req: u64,
        /// 这一段。
        data: Bytes,
        /// 文件总字节数。
        total: u64,
    },
    /// 我这里没有这个文件。
    FileMissing {
        /// 请求编号。
        req: u64,
    },
}

/// 宿主里一条消息的索引信息（v53 `store/index` 给的）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredItem {
    /// 编号。
    pub id: MsgId,
    /// 排序时间。
    pub at: i64,
    /// 是不是墓碑（宿主里标了撤回）。
    pub tomb: bool,
    /// 原件摘要（[`sync::raw_digest`]）；没有原件的旧消息为空，不参加对账。
    pub raw: Option<Fixed<16>>,
}

/// 宿主里一条消息的原件。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRecord {
    /// 编号。
    pub id: MsgId,
    /// 原件字符串。
    pub raw: String,
}

/// 要写进宿主的一条。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Write {
    /// 一条验过的消息原件：宿主保存原件并显示解开的内容（宿主按编号去重，同一条以最新为准）。
    Full {
        /// 排序键。
        key: Key,
        /// 原件。
        raw: String,
    },
    /// 被撤回的那条：宿主标成撤回，原件换成墓碑。
    Tombstone {
        /// 排序键。
        key: Key,
        /// 墓碑原件（带着撤回原件）。
        raw: String,
    },
}

/// 宿主存储（插件经 v53 读、经 `events/push` 写）。
#[allow(async_fn_in_trait)]
pub trait Store {
    /// 宿主里有哪些会话。
    async fn conversations(&mut self) -> Result<Vec<ConvId>, String>;
    /// 一个会话里全部消息的索引信息。
    async fn index(&mut self, conv: &ConvId) -> Result<Vec<StoredItem>, String>;
    /// 按编号取原件；宿主里没有的不返回。
    async fn records(&mut self, conv: &ConvId, ids: &[MsgId]) -> Result<Vec<StoredRecord>, String>;
    /// 写进宿主（宿主确认才算写好）。
    async fn write(&mut self, conv: &ConvId, writes: Vec<Write>) -> Result<(), String>;
}

/// 验过的一份原件。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// 这条消息自己的排序键（撤回时是撤回消息自己的）。
    pub key: Key,
    /// 发送账号。
    pub sender: String,
    /// 种类。
    pub kind: Kind,
    /// 撤回原件（墓碑里带着的，或撤回消息本身）；普通消息为空。
    pub recall_raw: Option<String>,
}

/// 原件的种类。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// 普通消息。
    Post,
    /// 撤回：撤回的目标（编号与撤回者写的目标时间）。
    Recall {
        /// 目标的排序键。
        target: Key,
    },
}

/// 权限与验签（插件按自己验过的账号与会话签名链回答）。
#[allow(async_fn_in_trait)]
pub trait Authority {
    /// 这台设备能不能和 `peer` 交换这个会话的东西：同账号，或双方都是会话的当前成员。
    async fn may_share(&mut self, conv: &ConvId, peer: &DeviceId) -> bool;
    /// 验一份原件（消息原件或墓碑）。验不过是 `Ok(None)`（实现方记日志，不记正文）；
    /// 这会儿验不了（断网取不到签名链）是 `Err`，这一批先不处理，下一次对账再来。
    async fn verify(&mut self, conv: &ConvId, raw: &str) -> Result<Option<Verified>, SyncError>;
    /// 一份原件的编号（不验）：验不过的记下来，这一轮不再向别人要。
    fn id_of(&self, raw: &str) -> Option<MsgId>;
    /// 由撤回原件生成被撤回那条的墓碑原件。
    fn tombstone(&self, conv: &ConvId, target: &Key, sender: &str, recall_raw: &str) -> String;
}

/// 引擎处理过程中出的错（宿主读写失败）。不影响别的会话；下一次对账会再来。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncError(pub String);

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "设备同步出错：{}", self.0)
    }
}

impl std::error::Error for SyncError {}

impl From<String> for SyncError {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// 一次处理的统计（测试与日志用）。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Applied {
    /// 新写进宿主的条数（原文、墓碑、换回原文都算）。
    pub written: usize,
    /// 验不过或被拒的原件数。
    pub rejected: usize,
}

/// 设备同步引擎。
pub struct Engine<S: Store, A: Authority> {
    store: S,
    auth: A,
    indexes: HashMap<ConvId, Index>,
    online: HashSet<DeviceId>,
    outbox: Vec<(DeviceId, PeerFrame)>,
    /// 这一轮验不过的编号：不再向别人要（比如重置账号后解不开的旧消息）。随 [`Engine::invalidate_all`] 清掉。
    rejected: HashSet<MsgId>,
}

impl<S: Store, A: Authority> Engine<S, A> {
    /// 新引擎。索引在用到时从宿主建（进程重启后也从宿主重建）。
    pub fn new(store: S, auth: A) -> Self {
        Self { store, auth, indexes: HashMap::new(), online: HashSet::new(), outbox: Vec::new(), rejected: HashSet::new() }
    }

    /// 取走要发的帧。
    pub fn drain(&mut self) -> Vec<(DeviceId, PeerFrame)> {
        std::mem::take(&mut self.outbox)
    }

    /// 权限与验签（调用方更新签名链后可能要用）。
    pub fn auth(&self) -> &A {
        &self.auth
    }

    /// 同上，可改。
    pub fn auth_mut(&mut self) -> &mut A {
        &mut self.auth
    }

    /// 宿主存储。
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// 现在在线、可以直接投递的设备。
    pub fn online(&self) -> impl Iterator<Item = &DeviceId> {
        self.online.iter()
    }

    /// 丢掉一个会话的索引，下次用到时从宿主重建（宿主可能被用户清过；调用方定时调）。
    pub fn invalidate(&mut self, conv: &ConvId) {
        self.indexes.remove(conv);
    }

    /// 丢掉全部索引，验不过的记录也再给一次机会。
    pub fn invalidate_all(&mut self) {
        self.indexes.clear();
        self.rejected.clear();
    }

    async fn index(&mut self, conv: &ConvId) -> Result<&mut Index, SyncError> {
        if !self.indexes.contains_key(conv) {
            let stored = self.store.index(conv).await?;
            let items = stored.into_iter().filter_map(|s| {
                let state = match (s.tomb, s.raw) {
                    (true, _) => State::Tombstone,
                    (false, Some(digest)) => State::Full(digest),
                    // 没有原件的旧消息不参加对账。
                    (false, None) => return None,
                };
                Some(Item { key: Key { at: s.at, id: s.id }, state })
            });
            self.indexes.insert(conv.clone(), Index::new(items));
        }
        Ok(self.indexes.get_mut(conv).expect("刚建好"))
    }

    /// 本会话见过的最大排序时间（发送时据此算 [`sync::next_at`]）。
    pub async fn seen_max(&mut self, conv: &ConvId) -> Result<Option<i64>, SyncError> {
        Ok(self.index(conv).await?.items().last().map(|item| item.key.at))
    }

    /// 一条消息的排序键；宿主里没有（或是没有原件的旧消息）为空。
    pub async fn key_of(&mut self, conv: &ConvId, id: &MsgId) -> Result<Option<Key>, SyncError> {
        Ok(self.index(conv).await?.get(id).map(|item| item.key.clone()))
    }

    /// 现在在线、能交换这个会话的设备。
    pub async fn sharing(&mut self, conv: &ConvId) -> Vec<DeviceId> {
        let online: Vec<DeviceId> = self.online.iter().cloned().collect();
        let mut peers = Vec::new();
        for peer in online {
            if self.auth.may_share(conv, &peer).await {
                peers.push(peer);
            }
        }
        peers
    }

    /// 一台设备上线了（服务器推的在线状态，或局域网发现）：和它对一遍共享的会话。
    pub async fn peer_online(&mut self, peer: &DeviceId) -> Result<(), SyncError> {
        self.online.insert(peer.clone());
        self.sync_peer(peer).await
    }

    /// 记下一台在线设备，不发起对账（收到它的帧时）。
    pub fn peer_seen(&mut self, peer: &DeviceId) {
        self.online.insert(peer.clone());
    }

    /// 一台设备下线了。
    pub fn peer_offline(&mut self, peer: &DeviceId) {
        self.online.remove(peer);
    }

    /// 自己和服务器断了：谁在线不知道了，连上后重新问。
    pub fn clear_online(&mut self) {
        self.online.clear();
    }

    /// 和一台设备对一遍所有共享的会话。
    pub async fn sync_peer(&mut self, peer: &DeviceId) -> Result<(), SyncError> {
        for conv in self.store.conversations().await? {
            if self.auth.may_share(&conv, peer).await {
                self.sync_with(peer, &conv).await?;
            }
        }
        Ok(())
    }

    /// 兜底：和每台在线设备把共享的会话都对一遍。
    pub async fn sync_all(&mut self) -> Result<(), SyncError> {
        let peers: Vec<DeviceId> = self.online.iter().cloned().collect();
        for peer in peers {
            self.sync_peer(&peer).await?;
        }
        Ok(())
    }

    /// 和一台设备对一个会话：发第一条对账消息。
    pub async fn sync_with(&mut self, peer: &DeviceId, conv: &ConvId) -> Result<(), SyncError> {
        let ranges = self.index(conv).await?.initiate();
        self.outbox.push((peer.clone(), PeerFrame::Sync { conv: conv.clone(), ranges }));
        Ok(())
    }

    /// 本机刚发出的一条（消息或撤回）：写进宿主、并进索引，再直接投给在线、有权的设备。
    pub async fn local(&mut self, conv: &ConvId, raw: String) -> Result<Applied, SyncError> {
        let mut applied = Applied::default();
        let mut forward = Vec::new();
        self.apply(conv, None, std::slice::from_ref(&raw), &mut applied, &mut forward).await?;
        if applied.written > 0 {
            for peer in self.sharing(conv).await {
                self.outbox.push((peer, PeerFrame::Have { conv: conv.clone(), records: vec![raw.clone()] }));
            }
        }
        Ok(applied)
    }

    /// 收到一帧。
    pub async fn on_frame(&mut self, from: &DeviceId, frame: PeerFrame) -> Result<Applied, SyncError> {
        let mut applied = Applied::default();
        let conv = match &frame {
            PeerFrame::Sync { conv, .. } | PeerFrame::Want { conv, .. } | PeerFrame::Have { conv, .. } => conv.clone(),
            // 别的帧不归对账管，由调用方处理。
            _ => return Ok(applied),
        };
        if !self.auth.may_share(&conv, from).await {
            self.outbox.push((from.clone(), PeerFrame::Deny { conv }));
            return Ok(applied);
        }
        self.online.insert(from.clone());
        match frame {
            PeerFrame::Sync { ranges, .. } => {
                let outcome = match self.index(&conv).await?.respond(&ranges) {
                    Ok(outcome) => outcome,
                    // 对方发来的对账消息不合格式：不回，下一次兜底对账重来。
                    Err(_) => return Ok(applied),
                };
                if !outcome.have.is_empty() {
                    self.send_records(from, &conv, &outcome.have).await?;
                }
                let need: Vec<MsgId> = outcome.need.into_iter().filter(|id| !self.rejected.contains(id)).collect();
                for chunk in need.chunks(WANT_MAX) {
                    self.outbox.push((from.clone(), PeerFrame::Want { conv: conv.clone(), ids: chunk.to_vec() }));
                }
                if !outcome.done {
                    self.outbox.push((from.clone(), PeerFrame::Sync { conv, ranges: outcome.reply }));
                }
            }
            PeerFrame::Want { ids, .. } => {
                let ids: Vec<MsgId> = ids.into_iter().take(WANT_MAX).collect();
                self.send_records(from, &conv, &ids).await?;
            }
            PeerFrame::Have { records, .. } => {
                let records: Vec<String> = records.into_iter().take(HAVE_RECORDS_MAX).collect();
                let mut forward = Vec::new();
                self.apply(&conv, Some(from), &records, &mut applied, &mut forward).await?;
                if !forward.is_empty() {
                    self.send_records(from, &conv, &forward).await?;
                }
            }
            _ => {}
        }
        Ok(applied)
    }

    async fn send_records(&mut self, to: &DeviceId, conv: &ConvId, ids: &[MsgId]) -> Result<(), SyncError> {
        // 只给索引里有的（对账集合里的）；宿主里已经没有的从索引去掉，下次对账对方会再要。
        let known: Vec<MsgId> = {
            let index = self.index(conv).await?;
            ids.iter().filter(|id| index.get(id).is_some()).cloned().collect()
        };
        if known.is_empty() {
            return Ok(());
        }
        let records = self.store.records(conv, &known).await?;
        let found: HashSet<&MsgId> = records.iter().map(|r| &r.id).collect();
        let missing: Vec<MsgId> = known.iter().filter(|id| !found.contains(id)).cloned().collect();
        if !missing.is_empty() {
            let index = self.index(conv).await?;
            for id in &missing {
                index.remove(id);
            }
        }
        let mut batch = Vec::new();
        let mut bytes = 0;
        for record in records {
            if !batch.is_empty() && (bytes + record.raw.len() > HAVE_BYTES_MAX || batch.len() >= HAVE_RECORDS_MAX) {
                self.outbox.push((to.clone(), PeerFrame::Have { conv: conv.clone(), records: std::mem::take(&mut batch) }));
                bytes = 0;
            }
            bytes += record.raw.len();
            batch.push(record.raw);
        }
        if !batch.is_empty() {
            self.outbox.push((to.clone(), PeerFrame::Have { conv: conv.clone(), records: batch }));
        }
        Ok(())
    }

    /// 并进一批原件（逐条处理，后一条看得到前一条的结果）。`forward` 收集要回给发来方的原文编号（拒绝伪造撤回时）。
    async fn apply(&mut self, conv: &ConvId, from: Option<&DeviceId>, records: &[String], applied: &mut Applied, forward: &mut Vec<MsgId>) -> Result<(), SyncError> {
        let mut writes = Vec::new();
        // 这一批里已经决定要写、还没写进宿主的原件：后面的核对先看这里。
        let mut pending: HashMap<MsgId, String> = HashMap::new();
        for raw in records {
            let verified = match self.auth.verify(conv, raw).await {
                Ok(verified) => verified,
                Err(error) => {
                    // 这会儿验不了：这一批没写的下次对账再来，已经决定写的先写掉。
                    self.flush(conv, writes, applied).await?;
                    return Err(error);
                }
            };
            let Some(verified) = verified else {
                applied.rejected += 1;
                if let Some(id) = self.auth.id_of(raw) {
                    self.rejected.insert(id);
                }
                continue;
            };
            match &verified.kind {
                Kind::Post => {
                    let current = self.index(conv).await?.get(&verified.key.id).cloned();
                    let item = Item { key: verified.key.clone(), state: State::Full(sync::raw_digest(raw)) };
                    match current {
                        None => {
                            self.index(conv).await?.merge([item]);
                            writes.push(Write::Full { key: verified.key.clone(), raw: raw.clone() });
                            pending.insert(verified.key.id.clone(), raw.clone());
                        }
                        Some(Item { state: State::Full(_), .. }) => {}
                        Some(Item { key, state: State::Tombstone }) => {
                            // 先到的撤回是不是伪造的：墓碑记下的撤回者要和原文的发送者一致、目标时间要对得上。
                            let tomb = self.claimed(conv, &key.id, &pending).await?;
                            let honest = tomb.is_some_and(|(sender, target)| sender == verified.sender && target == verified.key);
                            if !honest {
                                self.index(conv).await?.replace(item);
                                writes.push(Write::Full { key: verified.key.clone(), raw: raw.clone() });
                                pending.insert(verified.key.id.clone(), raw.clone());
                            }
                        }
                    }
                }
                Kind::Recall { target } => {
                    let Some(recall_raw) = verified.recall_raw.clone() else {
                        applied.rejected += 1;
                        continue;
                    };
                    let current = self.index(conv).await?.get(&target.id).cloned();
                    let tombstone = |engine: &Self| engine.auth.tombstone(conv, target, &verified.sender, &recall_raw);
                    match current {
                        Some(Item { state: State::Tombstone, .. }) => {}
                        None => {
                            let tomb = tombstone(self);
                            self.index(conv).await?.merge([Item { key: target.clone(), state: State::Tombstone }]);
                            writes.push(Write::Tombstone { key: target.clone(), raw: tomb.clone() });
                            pending.insert(target.id.clone(), tomb);
                        }
                        Some(Item { key, state: State::Full(_) }) => {
                            let original = self.original(conv, &key.id, &pending).await?;
                            let honest = original.as_ref().is_some_and(|o| o.sender == verified.sender && o.key == *target);
                            if honest {
                                let tomb = tombstone(self);
                                self.index(conv).await?.merge([Item { key: key.clone(), state: State::Tombstone }]);
                                writes.push(Write::Tombstone { key: key.clone(), raw: tomb.clone() });
                                pending.insert(key.id.clone(), tomb);
                            } else {
                                applied.rejected += 1;
                                // 伪造的撤回：把原文回给发来方，它那边先记的墓碑会换回原文。
                                if from.is_some() {
                                    forward.push(key.id.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
        self.flush(conv, writes, applied).await
    }

    async fn flush(&mut self, conv: &ConvId, writes: Vec<Write>, applied: &mut Applied) -> Result<(), SyncError> {
        if writes.is_empty() {
            return Ok(());
        }
        applied.written += writes.len();
        if let Err(error) = self.store.write(conv, writes).await {
            // 索引已经先改了：写不进宿主时丢掉索引，下次从宿主重建，没写进去的对方还会再给。
            self.invalidate(conv);
            return Err(error.into());
        }
        Ok(())
    }

    /// 墓碑里记下的撤回者与撤回者写的目标排序键。
    async fn claimed(&mut self, conv: &ConvId, id: &MsgId, pending: &HashMap<MsgId, String>) -> Result<Option<(String, Key)>, SyncError> {
        let Some(raw) = self.raw_of(conv, id, pending).await? else {
            return Ok(None);
        };
        Ok(self.auth.verify(conv, &raw).await?.and_then(|v| match v.kind {
            Kind::Recall { target } => Some((v.sender, target)),
            Kind::Post => None,
        }))
    }

    /// 本机存的原文验出来的发送者与排序键。
    async fn original(&mut self, conv: &ConvId, id: &MsgId, pending: &HashMap<MsgId, String>) -> Result<Option<Verified>, SyncError> {
        let Some(raw) = self.raw_of(conv, id, pending).await? else {
            return Ok(None);
        };
        Ok(self.auth.verify(conv, &raw).await?.filter(|v| v.kind == Kind::Post))
    }

    async fn raw_of(&mut self, conv: &ConvId, id: &MsgId, pending: &HashMap<MsgId, String>) -> Result<Option<String>, SyncError> {
        if let Some(raw) = pending.get(id) {
            return Ok(Some(raw.clone()));
        }
        let records = self.store.records(conv, std::slice::from_ref(id)).await?;
        Ok(records.into_iter().next().map(|r| r.raw))
    }
}
