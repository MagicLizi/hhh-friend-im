//! 阅读查询不写状态；本人明确查看时，才写设备签名的加密边界。
use crate::{Client, ClientError, Message, Result, conn::Conn, state::State};
use friend_im_core::{
    bytes::Fixed,
    ids::{ConvId, DeviceId, MsgId, Uid},
    message::{Content, Sender},
    reading::{ReadingBody, ReadingEnvelope, StoredReading},
    wire::{ErrorCode, Request, Response, WireError},
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

struct Verified {
    record: StoredReading,
    body: ReadingBody,
}
const RECORDS_MAX: usize = 20_000;

fn unsupported() -> ClientError {
    ClientError::Server(WireError {
        code: ErrorCode::Unsupported,
        message: "当前服务器尚未提供阅读扩展，聊天仍可使用".into(),
    })
}

/// 服务端按会话、账号和设备保存 CAS 版本。重置身份保留设备钥匙时，
/// 旧身份的阅读边界不能继承，但同一行的版本必须继续递增。
fn next_revision(records: &[Verified], uid: &Uid, device: &DeviceId) -> Result<u64> {
    records
        .iter()
        .filter(|r| &r.record.envelope.reader == uid && &r.record.envelope.device == device)
        .map(|r| r.record.envelope.revision)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| ClientError::state("阅读版本已到上限"))
}

impl State {
    fn require_reading(&self) -> Result<()> {
        self.require_active()?;
        if !self.reading {
            return Err(unsupported());
        }
        Ok(())
    }

    async fn reading_messages(
        &mut self,
        conn: &Conn,
        conv: &ConvId,
        ids: &[MsgId],
    ) -> Result<Vec<Message>> {
        self.require_reading()?;
        if ids.len() > 100 {
            return Err(ClientError::state("一次最多核对 100 条消息"));
        }
        let Response::ReadingMessages { messages } = conn
            .request(Request::ReadingMessages {
                conv: conv.clone(),
                ids: ids.to_vec(),
            })
            .await?
        else {
            return Err(ClientError::protocol("阅读消息回执不正确"));
        };
        let mut seen = HashSet::new();
        if messages.len() > ids.len()
            || messages.iter().any(|m| {
                &m.env.conv != conv || !ids.contains(&m.env.id) || !seen.insert(m.env.id.clone())
            })
        {
            return Err(ClientError::verify("阅读消息范围不一致"));
        }
        let mut result = Vec::with_capacity(messages.len());
        for message in messages {
            result.push(self.open_message(conn, &message).await?);
        }
        Ok(result)
    }

    async fn reading_records(&mut self, conn: &Conn, conv: &ConvId) -> Result<Vec<Verified>> {
        self.require_reading()?;
        self.book.load_conv(conn, conv).await?;
        let mut after = 0;
        let mut records = Vec::new();
        loop {
            let Response::ReadingPage {
                records: page,
                more,
            } = conn
                .request(Request::ReadingGet {
                    conv: conv.clone(),
                    after,
                    limit: 200,
                })
                .await?
            else {
                return Err(ClientError::protocol("阅读分页回执不正确"));
            };
            if page.len() > 200
                || (more && page.is_empty())
                || records.len() + page.len() > RECORDS_MAX
            {
                return Err(ClientError::protocol("阅读分页超过边界"));
            }
            for record in page {
                if record.log <= after
                    || record.log > i64::MAX as u64
                    || &record.envelope.conv != conv
                {
                    return Err(ClientError::verify("阅读分页范围不一致"));
                }
                after = record.log;
                records.push(record);
            }
            if !more {
                break;
            }
        }
        let mut result = Vec::with_capacity(records.len());
        for record in records {
            let envelope = &record.envelope;
            if !self.book.convs[conv].member_at(
                &envelope.reader,
                &envelope.reader_eldest,
                record.log,
            ) {
                return Err(ClientError::verify("阅读人当时不是这个身份的成员"));
            }
            let device = self
                .book
                .ensure_device(
                    conn,
                    &envelope.reader,
                    &envelope.reader_eldest,
                    &envelope.device,
                    record.log,
                )
                .await?;
            let seed = self.conv_seed(conn, conv, envelope.generation).await?;
            let body = envelope.open(&seed, &device)?;
            if body.through >= record.log {
                return Err(ClientError::verify("阅读记录早于它声称读到的消息"));
            }
            result.push(Verified { record, body });
        }
        // 水位必须能对应回同一会话里真实存在、验签通过的确切消息。
        let ids: Vec<_> = result
            .iter()
            .map(|v| v.body.message.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let mut boundaries = HashMap::new();
        for batch in ids.chunks(100) {
            for message in self.reading_messages(conn, conv, batch).await? {
                boundaries.insert(message.id, message.log);
            }
        }
        if result
            .iter()
            .any(|v| boundaries.get(&v.body.message) != Some(&v.body.through))
        {
            return Err(ClientError::verify("阅读水位与确切消息对不上"));
        }
        Ok(result)
    }

    async fn reading_through(&mut self, conn: &Conn, conv: &ConvId) -> Result<Option<u64>> {
        let records = self.reading_records(conn, conv).await?;
        let me = self.my_ref(conn).await?;
        Ok(records
            .iter()
            .filter(|r| {
                r.record.envelope.reader == self.uid && r.record.envelope.reader_eldest == me.eldest
            })
            .map(|r| r.body.through)
            .max())
    }

    async fn reading_receipts(
        &mut self,
        conn: &Conn,
        conv: &ConvId,
        ids: &[MsgId],
    ) -> Result<Vec<MessageReceipt>> {
        let records = self.reading_records(conn, conv).await?;
        let mut positions: HashMap<(Uid, Fixed<32>), u64> = HashMap::new();
        for record in records {
            let key = (
                record.record.envelope.reader,
                record.record.envelope.reader_eldest,
            );
            positions
                .entry(key)
                .and_modify(|p| *p = (*p).max(record.body.through))
                .or_insert(record.body.through);
        }
        let messages = self.reading_messages(conn, conv, ids).await?;
        let mut result = Vec::new();
        for message in messages {
            if message.sender != self.uid || !matches!(message.content, Some(Content::Post { .. }))
            {
                continue;
            }
            let mut recipients: Vec<_> = self.book.convs[conv]
                .stints
                .iter()
                .filter(|s| {
                    s.uid != self.uid
                        && s.from <= message.log
                        && s.until.is_none_or(|until| message.log < until)
                })
                .map(|s| (s.uid.clone(), s.eldest))
                .collect();
            recipients.sort_by(|a, b| a.0.cmp(&b.0));
            recipients.dedup();
            let mut receipt = MessageReceipt {
                message: message.id,
                readers: Vec::new(),
                unreaders: Vec::new(),
                complete: true,
            };
            for (uid, eldest) in recipients {
                match positions.get(&(uid.clone(), eldest)) {
                    Some(through) if *through >= message.log => receipt.readers.push(uid),
                    Some(_) => receipt.unreaders.push(uid),
                    None => receipt.complete = false,
                }
            }
            result.push(receipt);
        }
        Ok(result)
    }

    async fn reading_mark(
        &mut self,
        conn: &Conn,
        conv: &ConvId,
        id: &MsgId,
        position: Option<u64>,
    ) -> Result<ReadingMark> {
        self.require_reading()?;
        let message = self
            .reading_messages(conn, conv, std::slice::from_ref(id))
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| ClientError::state("这条消息不存在"))?;
        if !matches!(message.content, Some(Content::Post { .. }))
            || position.is_some_and(|p| p != message.log)
        {
            return Err(ClientError::state("阅读边界与消息不一致"));
        }
        let records = self.reading_records(conn, conv).await?;
        let me = self.my_ref(conn).await?;
        let own: Vec<_> = records
            .iter()
            .filter(|r| {
                r.record.envelope.reader == self.uid && r.record.envelope.reader_eldest == me.eldest
            })
            .collect();
        if own.iter().any(|r| r.body.through >= message.log) {
            return Ok(ReadingMark::Applied);
        }
        let revision = next_revision(&records, &self.uid, &self.creds.device.id())?;
        let generation = self.book.convs[conv].state.current_key().generation;
        let seed = self.conv_seed(conn, conv, generation).await?;
        let envelope = ReadingEnvelope::seal(
            conv,
            generation,
            revision,
            &seed,
            &Sender {
                uid: &self.uid,
                eldest: me.eldest,
                device: &self.creds.device,
            },
            &ReadingBody {
                through: message.log,
                message: id.clone(),
            },
        )?;
        match conn.request(Request::ReadingSet { envelope }).await {
            Ok(Response::ReadingSaved { .. }) => {}
            Ok(_) | Err(ClientError::Disconnected | ClientError::Timeout) => {
                return Ok(ReadingMark::Unknown);
            }
            Err(error) if error.code() == Some(ErrorCode::Conflict) => {}
            Err(error) => return Err(error),
        }
        // 成功、冲突或响应不确定都不重放写入，只读核对能证明的边界。
        match self.reading_through(conn, conv).await {
            Ok(Some(through)) if through >= message.log => Ok(ReadingMark::Applied),
            _ => Ok(ReadingMark::Unknown),
        }
    }
}

impl Client {
    pub async fn supports_reading(&self) -> bool {
        self.inner.state.lock().await.reading
    }
    pub async fn reading_through(&self, conv: &ConvId) -> Result<Option<u64>> {
        self.call(async |s, c| s.reading_through(c, conv).await)
            .await
    }
    pub async fn reading_receipts(
        &self,
        conv: &ConvId,
        ids: &[MsgId],
    ) -> Result<Vec<MessageReceipt>> {
        self.call(async |s, c| s.reading_receipts(c, conv, ids).await)
            .await
    }
    pub async fn mark_read(
        &self,
        conv: &ConvId,
        id: &MsgId,
        position: Option<u64>,
    ) -> Result<ReadingMark> {
        self.call(async |s, c| s.reading_mark(c, conv, id, position).await)
            .await
    }
    pub async fn reading_messages(&self, conv: &ConvId, ids: &[MsgId]) -> Result<Vec<Message>> {
        self.call(async |s, c| s.reading_messages(c, conv, ids).await)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use friend_im_core::keys::{ConvSeed, DeviceSecret};

    fn record(
        conv: &ConvId,
        uid: &Uid,
        device: &DeviceSecret,
        eldest: u8,
        revision: u64,
    ) -> Verified {
        let body = ReadingBody {
            through: 1,
            message: MsgId::random(),
        };
        let envelope = ReadingEnvelope::seal(
            conv,
            1,
            revision,
            &ConvSeed::generate(),
            &Sender {
                uid,
                eldest: Fixed([eldest; 32]),
                device,
            },
            &body,
        )
        .unwrap();
        Verified {
            record: StoredReading { log: 2, envelope },
            body,
        }
    }

    #[test]
    fn same_device_keeps_its_revision_after_identity_reset() {
        let conv = ConvId::random();
        let me = Uid::random();
        let other = Uid::random();
        let device = DeviceSecret::generate();
        let other_device = DeviceSecret::generate();
        // 本设备仍只有旧身份记录；新身份在另一设备的版本和别人的版本
        // 都不属于本设备的 CAS 行，不能替代或重置旧版本 5。
        let records = vec![
            record(&conv, &me, &device, 1, 5),
            record(&conv, &me, &other_device, 2, 90),
            record(&conv, &other, &device, 2, 70),
        ];
        assert_eq!(next_revision(&records, &me, &device.id()).unwrap(), 6);
        assert_eq!(next_revision(&[], &me, &device.id()).unwrap(), 1);
    }
}
