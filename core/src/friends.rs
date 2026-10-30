//! Signed friend requests. Verification messages are sealed to both account keys,
//! so the server can enforce approval without learning their contents.
use crate::{
    bytes::Fixed,
    conv::MemberRef,
    crypto::{self, Sealed},
    error::{CoreError, Result},
    ids::{ConvId, DeviceId, RequestId, Uid},
    keys::{AccountSeed, DevicePublic, DeviceSecret},
};
use serde::{Deserialize, Serialize};

pub const REQUEST_CONTEXT: &str = "friend-im/v1/friend-request";
pub const MESSAGE_MAX_CHARS: usize = 80;
pub const REQUEST_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
pub const REQUEST_COOLDOWN_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FriendSource {
    Group { conv: ConvId },
    Link { token: Fixed<16> },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriendMessageBox {
    pub uid: Uid,
    pub epoch: u32,
    pub generation: u32,
    pub sealed: Sealed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriendRequestBody {
    pub id: RequestId,
    pub from: MemberRef,
    pub to: MemberRef,
    pub source: FriendSource,
    pub messages: Vec<FriendMessageBox>,
}

impl FriendRequestBody {
    pub fn message_context(&self, uid: &Uid, epoch: u32, generation: u32) -> Vec<u8> {
        crypto::frame(&[
            REQUEST_CONTEXT.as_bytes(),
            self.id.as_str().as_bytes(),
            self.from.uid.as_str().as_bytes(),
            &self.from.eldest.0,
            self.to.uid.as_str().as_bytes(),
            &self.to.eldest.0,
            uid.as_str().as_bytes(),
            &epoch.to_be_bytes(),
            &generation.to_be_bytes(),
        ])
    }

    pub fn seal_message(
        &mut self,
        uid: Uid,
        epoch: u32,
        generation: u32,
        public: &[u8; 32],
        message: &str,
    ) -> Result<()> {
        check_message(message)?;
        let sealed = crypto::seal_to(
            public,
            &self.message_context(&uid, epoch, generation),
            message.as_bytes(),
        )?;
        self.messages.push(FriendMessageBox {
            uid,
            epoch,
            generation,
            sealed,
        });
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriendRequestEnvelope {
    pub body: FriendRequestBody,
    pub device: DeviceId,
    pub sig: Fixed<64>,
}

impl FriendRequestEnvelope {
    pub fn sign(body: FriendRequestBody, device: &DeviceSecret) -> Result<Self> {
        let bytes = serde_json::to_vec(&body).map_err(|_| CoreError::format("好友申请编码失败"))?;
        let value = Self {
            body,
            device: device.id(),
            sig: device.sign(REQUEST_CONTEXT, &bytes),
        };
        value.verify(&device.public())?;
        Ok(value)
    }

    pub fn verify(&self, device: &DevicePublic) -> Result<()> {
        let b = &self.body;
        if self.device != device.id()
            || b.from.uid == b.to.uid
            || b.messages.len() != 2
            || b.messages
                .iter()
                .any(|m| m.generation == 0 || m.sealed.ct.len() > 512)
            || b.messages.iter().filter(|m| m.uid == b.from.uid).count() != 1
            || b.messages.iter().filter(|m| m.uid == b.to.uid).count() != 1
        {
            return Err(CoreError::format("好友申请身份或密文无效"));
        }
        device.verify(
            REQUEST_CONTEXT,
            &serde_json::to_vec(b).map_err(|_| CoreError::format("好友申请编码失败"))?,
            &self.sig,
        )
    }

    pub fn open_message(
        &self,
        uid: &Uid,
        seed: &AccountSeed,
        device: &DevicePublic,
    ) -> Result<String> {
        self.verify(device)?;
        let m = self
            .body
            .messages
            .iter()
            .find(|m| &m.uid == uid)
            .ok_or_else(|| CoreError::format("不是申请的参与者"))?;
        let bytes = seed.open(
            &self.body.message_context(uid, m.epoch, m.generation),
            &m.sealed,
        )?;
        let message =
            String::from_utf8(bytes.to_vec()).map_err(|_| CoreError::format("验证消息不是文本"))?;
        check_message(&message)?;
        Ok(message)
    }
}

fn check_message(message: &str) -> Result<()> {
    if message.chars().count() > MESSAGE_MAX_CHARS
        || message.chars().any(|c| c.is_control() && c != '\n')
    {
        return Err(CoreError::format("验证消息最多 80 字，不能包含控制字符"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FriendRequestStatus {
    Pending,
    Accepted,
    Rejected,
    Withdrawn,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFriendRequest {
    pub envelope: FriendRequestEnvelope,
    /// Server log position at submission, used to verify historical device membership.
    pub log: u64,
    pub created_ms: i64,
    pub expires_ms: i64,
    pub updated_ms: i64,
    pub status: FriendRequestStatus,
    pub conversation: Option<ConvId>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verification_message_is_private_signed_and_bound_to_both_identities() {
        let a = AccountSeed::generate();
        let b = AccountSeed::generate();
        let device = DeviceSecret::generate();
        let mut body = FriendRequestBody {
            id: RequestId::random(),
            from: MemberRef {
                uid: Uid::random(),
                eldest: Fixed([1; 32]),
            },
            to: MemberRef {
                uid: Uid::random(),
                eldest: Fixed([2; 32]),
            },
            source: FriendSource::Group {
                conv: ConvId::random(),
            },
            messages: vec![],
        };
        body.seal_message(
            body.from.uid.clone(),
            1,
            1,
            &a.public(1).enc.0,
            "仅双方可读",
        )
        .unwrap();
        body.seal_message(body.to.uid.clone(), 1, 1, &b.public(1).enc.0, "仅双方可读")
            .unwrap();
        let signed = FriendRequestEnvelope::sign(body, &device).unwrap();
        assert_eq!(
            signed
                .open_message(&signed.body.from.uid, &a, &device.public())
                .unwrap(),
            "仅双方可读"
        );
        assert_eq!(
            signed
                .open_message(&signed.body.to.uid, &b, &device.public())
                .unwrap(),
            "仅双方可读"
        );
        assert!(
            !serde_json::to_string(&signed)
                .unwrap()
                .contains("仅双方可读")
        );
        assert!(
            signed
                .open_message(&signed.body.to.uid, &a, &device.public())
                .is_err()
        );
        let mut changed = signed.clone();
        changed.body.id = RequestId::random();
        assert!(changed.verify(&device.public()).is_err());
        changed = signed;
        changed.body.to.uid = Uid::random();
        assert!(changed.verify(&device.public()).is_err());
        assert!(check_message(&"好".repeat(81)).is_err());
    }
}
