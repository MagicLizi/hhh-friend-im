//! 平台阅读事实翻成宿主协议；会话读取、同步通知都不产生写回。
use super::{Server, errors, methods::params};
use friend_im_client::{
    ReadingMark,
    core::ids::{ConvId, MsgId},
};
use hhh_im_protocol::{
    reading::*,
    rpc::{ErrorKind, RpcError},
    types::{Person, PersonKind},
};
use serde_json::Value;
use sha2::{Digest, Sha256};

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
    pub(crate) async fn reading_receipts(&self, input: Value) -> Result<Value, RpcError> {
        let p: ReceiptsParams = params(input)?;
        let conv = scope(&p.scope)?;
        let messages = ids(&p.message_ids)?;
        let live = self.live().await?;
        let found = live
            .client
            .reading_receipts(&conv, &messages)
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

    pub(crate) async fn reading_people(&self, input: Value) -> Result<Value, RpcError> {
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
        let receipt = live
            .client
            .reading_receipts(&conv, &messages)
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
            .map(|p| p.to_string());
        value(ReadState {
            scope: p.scope,
            through,
            read_message_ids: Vec::new(),
        })
    }

    pub(crate) async fn reading_mark(&self, input: Value) -> Result<Value, RpcError> {
        let p: MarkReadParams = params(input)?;
        let conv = scope(&p.scope)?;
        let mut messages = ids(std::slice::from_ref(&p.message_id))?;
        let position = p
            .position
            .as_deref()
            .map(|position| {
                if !valid_read_position(position) {
                    return Err(errors::of(ErrorKind::InvalidRequest, "阅读位置无效"));
                }
                position.parse::<u64>().map_err(errors::invalid_params)
            })
            .transpose()?;
        let live = self.live().await?;
        let result = live
            .client
            .mark_read(&conv, &messages.remove(0), position)
            .await
            .map_err(|e| errors::client(&e))?;
        value(match result {
            ReadingMark::Applied => MarkReadResult::Applied,
            ReadingMark::Unknown => MarkReadResult::Unknown,
        })
    }
}
