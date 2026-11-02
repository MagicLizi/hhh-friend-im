//! 平台阅读事实翻成宿主协议；会话读取、同步通知都不产生写回。
use super::{Server, errors, methods::params};
use friend_im_client::{
    Message,
    core::ids::{ConvId, MsgId},
    core::sync::read_position,
    peers::Opened,
};
use hhh_im_protocol::{
    reading::*,
    rpc::{ErrorKind, RpcError},
    types::{Person, PersonKind},
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::session::Live;

fn scope(scope: &ReadScope) -> Result<ConvId, RpcError> {
    if !valid_read_scope(scope) || scope.thread_root.is_some() {
        return Err(errors::of(ErrorKind::Unsupported, "Cindy IM 没有独立话题"));
    }
    ConvId::parse(&scope.conversation_id).map_err(errors::invalid_params)
}
fn ids(ids: &[String]) -> Result<Vec<MsgId>, RpcError> {
    if !valid_read_ids(ids) {
        return Err(errors::of(ErrorKind::InvalidRequest, "阅读消息编号不合法"));
    }
    ids.iter()
        .map(|id| MsgId::parse(id).map_err(errors::invalid_params))
        .collect()
}
fn value<T: serde::Serialize>(value: T) -> Result<Value, RpcError> {
    serde_json::to_value(value).map_err(errors::invalid_params)
}

impl Server {
    /// 按编号从宿主读回消息并解开：已读回执与已读位置都要知道消息的发送人与排序时间。
    async fn stored_messages(
        self: &std::sync::Arc<Self>,
        live: &std::sync::Arc<Live>,
        conv: &ConvId,
        ids: &[MsgId],
    ) -> Result<Vec<Message>, RpcError> {
        let store = super::devices::HostStore::new(self.clone(), live.clone());
        let stored = store
            .messages(conv, ids)
            .await
            .map_err(|reason| errors::of(ErrorKind::Disconnected, reason))?;
        let mut messages = Vec::with_capacity(stored.len());
        for wire in stored {
            let Some(raw) = wire.raw else { continue };
            if let Ok(Opened::Message(message)) = live.client.open_record(conv, &raw.data).await {
                messages.push(message);
            }
        }
        Ok(messages)
    }

    /// 告诉宿主这个会话的已读位置变了。
    pub(crate) async fn reading_changed(&self, live: &Live, conv: &ConvId) {
        if !self
            .reading_events
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return;
        }
        match live.client.reading_through(conv).await {
            Ok(through) => self.peer.notify(
                "reading/changed",
                ReadState {
                    scope: ReadScope {
                        conversation_id: conv.to_string(),
                        thread_root: None,
                    },
                    through: through.as_ref().map(read_position),
                    read_message_ids: Vec::new(),
                },
            ),
            Err(error) => tracing::warn!(%error, "阅读变更未核实，保留原未读"),
        }
    }

    pub(crate) async fn reading_receipts(self: &std::sync::Arc<Self>, input: Value) -> Result<Value, RpcError> {
        let p: ReceiptsParams = params(input)?;
        let conv = scope(&p.scope)?;
        let messages = ids(&p.message_ids)?;
        let live = self.live().await?;
        let stored = self.stored_messages(&live, &conv, &messages).await?;
        let found = live
            .client
            .reading_receipts(&conv, &stored)
            .await
            .map_err(|e| errors::client(&e))?;
        value(ReceiptsResult {
            items: found
                .into_iter()
                .map(|r| MessageReceipt {
                    message_id: r.message.to_string(),
                    read_count: r.complete.then_some(r.readers.len() as u32),
                    total_count: r
                        .complete
                        .then_some((r.readers.len() + r.unreaders.len()) as u32),
                    readers: true,
                    unreaders: true,
                })
                .collect(),
        })
    }

    pub(crate) async fn reading_people(self: &std::sync::Arc<Self>, input: Value) -> Result<Value, RpcError> {
        let p: ReceiptPeopleParams = params(input)?;
        let conv = scope(&p.scope)?;
        let messages = ids(std::slice::from_ref(&p.message_id))?;
        if p.limit == 0 || p.limit as usize > hhh_im_protocol::budget::READ_PEOPLE_MAX {
            return Err(errors::of(
                ErrorKind::InvalidRequest,
                "阅读名单分页数量不合法",
            ));
        }
        let live = self.live().await?;
        let stored = self.stored_messages(&live, &conv, &messages).await?;
        let receipt = live
            .client
            .reading_receipts(&conv, &stored)
            .await
            .map_err(|e| errors::client(&e))?
            .into_iter()
            .next()
            .ok_or_else(|| errors::of(ErrorKind::NotFound, "没有这条本人消息的回执"))?;
        let people = if p.read {
            receipt.readers
        } else {
            receipt.unreaders
        };
        let mut hash = Sha256::new();
        hash.update(p.scope.conversation_id.as_bytes());
        hash.update(p.message_id.as_bytes());
        hash.update([u8::from(p.read)]);
        for uid in &people {
            hash.update(uid.as_str().as_bytes());
        }
        let fingerprint = hash
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let offset = match p.cursor.as_deref() {
            None => 0,
            Some(cursor) => {
                let (version, number) = cursor
                    .split_once(':')
                    .ok_or_else(|| errors::of(ErrorKind::InvalidRequest, "阅读名单游标无效"))?;
                let offset = number.parse::<usize>().map_err(errors::invalid_params)?;
                if version != &fingerprint[..16] || offset == 0 || offset >= people.len() {
                    return Err(errors::of(
                        ErrorKind::InvalidRequest,
                        "阅读名单已更新，请从第一页重试",
                    ));
                }
                offset
            }
        };
        let end = (offset + p.limit as usize).min(people.len());
        let page = &people[offset..end];
        let names = live.names(page.iter().cloned()).await;
        value(ReceiptPeopleResult {
            people: page
                .iter()
                .map(|uid| Person {
                    id: uid.to_string(),
                    id_type: None,
                    kind: PersonKind::User,
                    name: names.get(uid).cloned(),
                    avatar: live.avatar_of(uid),
                })
                .collect(),
            next_cursor: (end < people.len()).then(|| format!("{}:{end}", &fingerprint[..16])),
            complete: receipt.complete && end == people.len(),
        })
    }

    pub(crate) async fn reading_sync(&self, input: Value) -> Result<Value, RpcError> {
        let p: ReadSyncParams = params(input)?;
        let conv = scope(&p.scope)?;
        ids(&p.message_ids)?;
        let live = self.live().await?;
        let through = live
            .client
            .reading_through(&conv)
            .await
            .map_err(|e| errors::client(&e))?
            .map(|key| read_position(&key));
        value(ReadState {
            scope: p.scope,
            through,
            read_message_ids: Vec::new(),
        })
    }

    pub(crate) async fn reading_mark(self: &std::sync::Arc<Self>, input: Value) -> Result<Value, RpcError> {
        let p: MarkReadParams = params(input)?;
        let conv = scope(&p.scope)?;
        let messages = ids(std::slice::from_ref(&p.message_id))?;
        if p.position.as_deref().is_some_and(|position| !valid_read_position(position)) {
            return Err(errors::of(ErrorKind::InvalidRequest, "阅读位置无效"));
        }
        let live = self.live().await?;
        let stored = self.stored_messages(&live, &conv, &messages).await?;
        let Some(message) = stored.into_iter().next() else {
            return Err(errors::of(ErrorKind::NotFound, "这条消息不在本机"));
        };
        let envelope = live
            .client
            .mark_read(&conv, &message)
            .await
            .map_err(|e| errors::client(&e))?;
        if let Some(envelope) = envelope {
            live.devices.reading(conv, envelope);
        }
        value(MarkReadResult::Applied)
    }
}
