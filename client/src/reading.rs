//! 已读记录：设备签名、会话钥匙加密，设备之间对账时互相交换，服务器不存。
//!
//! 每台设备一份，取版本最大的那份。只在内存里：重启后别的设备的记录从在线伙伴补回，补回前保持未知。
use crate::{Client, ClientError, Message, Result, conn::Conn, state::State};
use friend_im_core::{
    bytes::Fixed,
    ids::{ConvId, DeviceId, MsgId, Uid},
    message::{Content, Sender},
    reading::{ReadingBody, ReadingEnvelope},
    sync::Key,
};
use std::collections::{HashMap, HashSet};

/// 只有已经验过的阅读事实才进名单；没有记录的收件人保持未知。
#[derive(Clone, Debug)]
pub struct MessageReceipt {
    pub message: MsgId,
    pub readers: Vec<Uid>,
    pub unreaders: Vec<Uid>,
    pub complete: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadingMark {
    Applied,
    Unknown,
}

#[derive(Clone)]
struct Verified {
    envelope: ReadingEnvelope,
    // 重置后旧私钥已经丢弃、或拿不到那一代钥匙：版本照记，但不当成阅读事实。
    body: Option<ReadingBody>,
}

/// 一个会话至多记多少份（账号数 × 设备数）。
const RECORDS_MAX: usize = 20_000;

/// 内存里的已读记录：会话 → 设备 → 最新一份。
#[derive(Default)]
pub(crate) struct ReadingBook {
    records: HashMap<ConvId, HashMap<DeviceId, Verified>>,
}

fn key_of(body: &ReadingBody) -> Key {
    Key { at: body.at, id: body.message.clone() }
}

impl State {
    /// 验一份记录：读者当时是成员、设备当时有效、签名对。
    async fn reading_verify(&mut self, conn: &Conn, conv: &ConvId, envelope: ReadingEnvelope) -> Result<Verified> {
        if &envelope.conv != conv {
            return Err(ClientError::verify("阅读记录不是这个会话的"));
        }
        let (start, end) = self.generation_window(conn, conv, envelope.generation).await?;
        let record = self.book.conv(conn, conv).await?;
        if !record.member_during(&envelope.reader, &envelope.reader_eldest, start, end) {
            return Err(ClientError::verify("阅读人当时不是这个身份的成员"));
        }
        let device = self.book.ensure_device_during(conn, &envelope.reader, &envelope.reader_eldest, &envelope.device, start, end).await?;
        envelope.verify(&device)?;
        let me = self.my_ref(conn).await?;
        let body = if envelope.reader == self.uid && envelope.reader_eldest != me.eldest {
            None
        } else {
            match self.optional_conv_seed(conn, conv, envelope.generation).await {
                Ok(Some(seed)) => Some(envelope.open(&seed, &device)?),
                // 不把拿不到旧钥匙误报成未读，也不让旧记录阻断新身份的同步。
                Ok(None) | Err(ClientError::Verify(_)) => None,
                Err(error) => return Err(error),
            }
        };
        Ok(Verified { envelope, body })
    }

    /// 并进别的设备发来的记录，每台设备留版本最大的。有变化返回真。
    pub(crate) async fn reading_merge(&mut self, conn: &Conn, conv: &ConvId, incoming: Vec<ReadingEnvelope>) -> Result<bool> {
        let mut changed = false;
        for envelope in incoming {
            let known = self.readings.records.get(conv).and_then(|records| records.get(&envelope.device)).map(|v| v.envelope.revision);
            if known.is_some_and(|revision| revision >= envelope.revision) {
                continue;
            }
            let verified = match self.reading_verify(conn, conv, envelope).await {
                Ok(verified) => verified,
                Err(error @ (ClientError::Disconnected | ClientError::Timeout)) => return Err(error),
                Err(error) => {
                    tracing::warn!(%conv, %error, "一份阅读记录验不过，丢掉");
                    continue;
                }
            };
            let records = self.readings.records.entry(conv.clone()).or_default();
            if records.len() >= RECORDS_MAX && !records.contains_key(&verified.envelope.device) {
                tracing::warn!(%conv, "阅读记录到上限了，新的不记");
                continue;
            }
            records.insert(verified.envelope.device.clone(), verified);
            changed = true;
        }
        Ok(changed)
    }

    /// 这个会话的全部记录（对账时交给对方）。
    pub(crate) fn reading_records(&self, conv: &ConvId) -> Vec<ReadingEnvelope> {
        self.readings.records.get(conv).map(|records| records.values().map(|v| v.envelope.clone()).collect()).unwrap_or_default()
    }

    /// 本人（当前身份）读到哪里。
    async fn reading_through(&mut self, conn: &Conn, conv: &ConvId) -> Result<Option<Key>> {
        let me = self.my_ref(conn).await?;
        Ok(self
            .readings
            .records
            .get(conv)
            .into_iter()
            .flat_map(|records| records.values())
            .filter(|v| v.envelope.reader == self.uid && v.envelope.reader_eldest == me.eldest)
            .filter_map(|v| v.body.as_ref().map(key_of))
            .max())
    }

    async fn reading_receipts(&mut self, conn: &Conn, conv: &ConvId, messages: &[Message]) -> Result<Vec<MessageReceipt>> {
        self.book.load_conv(conn, conv).await?;
        let mut positions: HashMap<(Uid, Fixed<32>), Key> = HashMap::new();
        let mut unknown = HashSet::new();
        for record in self.readings.records.get(conv).into_iter().flat_map(|r| r.values()) {
            let who = (record.envelope.reader.clone(), record.envelope.reader_eldest);
            match &record.body {
                Some(body) => {
                    let key = key_of(body);
                    positions.entry(who).and_modify(|p| *p = (*p).clone().max(key.clone())).or_insert(key);
                }
                None => {
                    unknown.insert(who);
                }
            }
        }
        let mut result = Vec::new();
        for message in messages {
            if message.sender != self.uid || !matches!(message.content, Content::Post { .. }) {
                continue;
            }
            let at = message.ctime_ms;
            // 回执名单：消息发出时在群里的人。
            let mut recipients: Vec<_> = self.book.convs[conv]
                .stints
                .iter()
                .filter(|s| s.uid != self.uid && s.from_ms <= at && s.until_ms.is_none_or(|until| at < until))
                .map(|s| (s.uid.clone(), s.eldest))
                .collect();
            recipients.sort_by(|a, b| a.0.cmp(&b.0));
            recipients.dedup();
            let key = Key { at, id: message.id.clone() };
            let mut receipt = MessageReceipt { message: message.id.clone(), readers: Vec::new(), unreaders: Vec::new(), complete: true };
            for (uid, eldest) in recipients {
                match positions.get(&(uid.clone(), eldest)) {
                    Some(through) if *through >= key => receipt.readers.push(uid),
                    _ if unknown.contains(&(uid.clone(), eldest)) => receipt.complete = false,
                    Some(_) => receipt.unreaders.push(uid),
                    None => receipt.complete = false,
                }
            }
            result.push(receipt);
        }
        Ok(result)
    }

    /// 写本设备新的一份。已经读到更后面了就不写，返回 `None`。
    async fn reading_mark(&mut self, conn: &Conn, conv: &ConvId, message: &Message) -> Result<Option<ReadingEnvelope>> {
        self.require_active()?;
        if !matches!(message.content, Content::Post { .. }) {
            return Err(ClientError::state("阅读边界不是一条消息"));
        }
        let key = Key { at: message.ctime_ms, id: message.id.clone() };
        if self.reading_through(conn, conv).await?.is_some_and(|through| through >= key) {
            return Ok(None);
        }
        let me = self.my_ref(conn).await?;
        let device = self.creds.device.id();
        let last = self.readings.records.get(conv).and_then(|records| records.get(&device)).map_or(0, |v| v.envelope.revision);
        // 版本用时间：插件重启后内存清空，新写的一份也要比别的设备手里的那份新。
        let revision = (self.now_ms().max(1) as u64).max(last + 1);
        let generation = self.book.conv(conn, conv).await?.state.current_key().generation;
        let seed = self.conv_seed(conn, conv, generation).await?;
        let body = ReadingBody { at: key.at, message: key.id };
        let envelope = ReadingEnvelope::seal(conv, generation, revision, &seed, &Sender { uid: &self.uid, eldest: me.eldest, device: &self.creds.device }, &body)?;
        self.readings.records.entry(conv.clone()).or_default().insert(device, Verified { envelope: envelope.clone(), body: Some(body) });
        Ok(Some(envelope))
    }
}

impl Client {
    /// 本人读到哪里（排序键）；还不知道为空。
    pub async fn reading_through(&self, conv: &ConvId) -> Result<Option<Key>> {
        self.call_any(async |s, c| s.reading_through(c, conv).await).await
    }

    /// 这些消息的阅读回执（只算自己发的）。
    pub async fn reading_receipts(&self, conv: &ConvId, messages: &[Message]) -> Result<Vec<MessageReceipt>> {
        self.call_any(async |s, c| s.reading_receipts(c, conv, messages).await).await
    }

    /// 写本设备的已读位置；返回要交给别的设备的新记录（已经读到更后面了为空）。
    pub async fn mark_read(&self, conv: &ConvId, message: &Message) -> Result<Option<ReadingEnvelope>> {
        self.call_any(async |s, c| s.reading_mark(c, conv, message).await).await
    }

    /// 并进别的设备发来的记录，有变化返回真。
    pub async fn merge_reading(&self, conv: &ConvId, records: Vec<ReadingEnvelope>) -> Result<bool> {
        self.call_any(async |s, c| s.reading_merge(c, conv, records).await).await
    }

    /// 这个会话手里的全部记录。
    pub async fn reading_records(&self, conv: &ConvId) -> Vec<ReadingEnvelope> {
        self.inner.state.lock().await.reading_records(conv)
    }
}
