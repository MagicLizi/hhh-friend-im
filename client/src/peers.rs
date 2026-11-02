//! 设备对账接到真实世界：消息原件的格式（宿主替插件保存的就是它），和按验过的签名链回答“谁有权、这份真不真”。
//!
//! 原件是一段 JSON 字符串：
//! - 消息：`{"env": 信封}`。信封本身是发送设备签名、会话钥匙加密的密文，不含钥匙。
//! - 墓碑：`{"tombstone": {id, at, sender}, "recall": 撤回消息的原件}`。被撤回那条的密文不留，补给别人时交撤回原件，
//!   对方自己验签再生成墓碑。

use friend_im_core::ids::{ConvId, DeviceId, MsgId, Uid};
use friend_im_core::message::{Content, Envelope};
use friend_im_core::sync::Key;
use serde::{Deserialize, Serialize};

use crate::client::Client;
use crate::error::{ClientError, Result};
use crate::sync::{Authority, Kind, SyncError, Verified};
use crate::types::Message;

/// 原始数据的格式名。
pub const RAW_FORMAT: &str = "cindy-env-v2";

#[derive(Serialize, Deserialize)]
struct Tomb {
    id: MsgId,
    at: i64,
    sender: Uid,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Record {
    Tomb { tombstone: Tomb, recall: String },
    Env { env: Envelope },
}

/// 一封信封的原件。
pub(crate) fn record_of(env: &Envelope) -> Result<String> {
    #[derive(Serialize)]
    struct Env<'a> {
        env: &'a Envelope,
    }
    serde_json::to_string(&Env { env }).map_err(|_| ClientError::protocol("消息原件写不出"))
}

/// 解开的一份原件。
#[derive(Clone, Debug)]
pub enum Opened {
    /// 一条消息（含撤回消息本身）。
    Message(Message),
    /// 墓碑：这条消息被撤回了。
    Tombstone {
        /// 被撤回的消息。
        id: MsgId,
        /// 它的排序时间。
        at: i64,
        /// 撤回的人。
        sender: Uid,
    },
}

/// 时间的合理范围：不早于 2000 年，不晚于现在加一天（宿主也这样核对）。
fn plausible(at: i64, now: i64) -> bool {
    (946_684_800_000..=now.saturating_add(86_400_000)).contains(&at)
}

impl Client {
    /// 解开一份原件。验不过是 [`ClientError::Verify`]。
    pub async fn open_record(&self, conv: &ConvId, raw: &str) -> Result<Opened> {
        let record: Record = serde_json::from_str(raw).map_err(|_| ClientError::verify("原件读不懂"))?;
        match record {
            Record::Env { env } => {
                if env.conv != *conv {
                    return Err(ClientError::verify("原件不是这个会话的"));
                }
                self.open_envelope(env).await.map(Opened::Message)
            }
            Record::Tomb { tombstone, recall } => {
                let Record::Env { env } = serde_json::from_str(&recall).map_err(|_| ClientError::verify("墓碑读不懂"))? else {
                    return Err(ClientError::verify("墓碑里不是撤回原件"));
                };
                if env.conv != *conv || env.sender != tombstone.sender {
                    return Err(ClientError::verify("墓碑对不上"));
                }
                let message = self.open_envelope(env).await?;
                match message.content {
                    Content::Recall { target, target_at } if target == tombstone.id && target_at == tombstone.at => {
                        Ok(Opened::Tombstone { id: target, at: target_at, sender: tombstone.sender })
                    }
                    _ => Err(ClientError::verify("墓碑里的撤回对不上")),
                }
            }
        }
    }
}

/// 按客户端验过的签名链回答。
pub struct ClientAuthority {
    client: Client,
}

impl ClientAuthority {
    /// 新建。
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

impl ClientAuthority {
    /// 这台设备现在能不能和我交换这个会话（不经引擎问）。
    pub async fn may_share_now(&mut self, conv: &ConvId, peer: &DeviceId) -> bool {
        self.client.may_share(conv, peer).await
    }
}

impl Authority for ClientAuthority {
    async fn may_share(&mut self, conv: &ConvId, peer: &DeviceId) -> bool {
        self.client.may_share(conv, peer).await
    }

    async fn verify(&mut self, conv: &ConvId, raw: &str) -> std::result::Result<Option<Verified>, SyncError> {
        let opened = match self.client.open_record(conv, raw).await {
            Ok(opened) => opened,
            Err(error @ (ClientError::Disconnected | ClientError::Timeout)) => return Err(SyncError(error.to_string())),
            Err(error) => {
                tracing::warn!(%conv, %error, "一份原件验不过，丢掉");
                return Ok(None);
            }
        };
        let now = self.client.now_ms().await;
        let verified = match opened {
            Opened::Message(message) => {
                if !plausible(message.ctime_ms, now) {
                    tracing::warn!(%conv, id = %message.id, "原件的时间不合理，丢掉");
                    return Ok(None);
                }
                let key = Key { at: message.ctime_ms, id: message.id };
                let sender = message.sender.to_string();
                match message.content {
                    Content::Post { .. } => Verified { key, sender, kind: Kind::Post, recall_raw: None },
                    Content::Recall { target, target_at } => {
                        Verified { key, sender, kind: Kind::Recall { target: Key { at: target_at, id: target } }, recall_raw: Some(raw.to_owned()) }
                    }
                    // 个人资料不进对账集合。
                    Content::Profile { .. } => return Ok(None),
                }
            }
            Opened::Tombstone { id, at, sender } => {
                let Ok(Record::Tomb { recall, .. }) = serde_json::from_str::<Record>(raw) else {
                    return Ok(None);
                };
                let Ok(Record::Env { env }) = serde_json::from_str::<Record>(&recall) else {
                    return Ok(None);
                };
                Verified { key: Key { at, id: env.id }, sender: sender.to_string(), kind: Kind::Recall { target: Key { at, id: id.clone() } }, recall_raw: Some(recall) }
            }
        };
        Ok(Some(verified))
    }

    fn id_of(&self, raw: &str) -> Option<MsgId> {
        match serde_json::from_str::<Record>(raw).ok()? {
            Record::Env { env } => Some(env.id),
            Record::Tomb { tombstone, .. } => Some(tombstone.id),
        }
    }

    fn tombstone(&self, _conv: &ConvId, target: &Key, sender: &str, recall_raw: &str) -> String {
        #[derive(Serialize)]
        struct Out<'a> {
            tombstone: TombOut<'a>,
            recall: &'a str,
        }
        #[derive(Serialize)]
        struct TombOut<'a> {
            id: &'a MsgId,
            at: i64,
            sender: &'a str,
        }
        serde_json::to_string(&Out { tombstone: TombOut { id: &target.id, at: target.at, sender }, recall: recall_raw }).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_out_of_range_are_refused() {
        let now = 1_700_000_000_000;
        assert!(plausible(now, now));
        assert!(plausible(now + 86_000_000, now), "快一小时的电脑写的时间照收");
        assert!(!plausible(now + 87_000_000, now));
        assert!(!plausible(0, now));
    }
}
