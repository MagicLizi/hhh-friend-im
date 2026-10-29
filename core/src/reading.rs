//! 加密的阅读水位，独立于聊天消息。服务器只保存签名信封，看不到消息边界。
use crate::{
    bytes::{Bytes, Fixed},
    crypto::{self, ctx},
    error::{CoreError, Result},
    ids::{ConvId, DeviceId, MsgId, Uid},
    keys::{ConvSeed, DevicePublic},
    message::Sender,
};
use serde::{Deserialize, Serialize};

/// 一份阅读密文的上限；不随聊天历史大小增长。
pub const READING_CT_MAX: usize = 1024;

/// 只有会话成员能解开的确切阅读边界。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadingBody {
    pub through: u64,
    pub message: MsgId,
}

/// 每账号、会话、设备一份。revision 是该设备记录的 CAS 版本，不是阅读位置。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadingEnvelope {
    pub conv: ConvId,
    pub reader: Uid,
    pub reader_eldest: Fixed<32>,
    pub device: DeviceId,
    pub generation: u32,
    pub revision: u64,
    pub ct: Bytes,
    pub sig: Fixed<64>,
}

/// 服务器接受记录的日志序号供验签时核对设备有效区间；不进入旧客户端的事件流。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredReading {
    pub log: u64,
    pub envelope: ReadingEnvelope,
}

impl ReadingEnvelope {
    fn header(&self) -> Vec<u8> {
        crypto::frame(&[
            ctx::READING.as_bytes(),
            self.conv.as_str().as_bytes(),
            self.reader.as_str().as_bytes(),
            &self.reader_eldest.0,
            self.device.as_str().as_bytes(),
            &self.generation.to_be_bytes(),
            &self.revision.to_be_bytes(),
        ])
    }

    pub fn seal(
        conv: &ConvId,
        generation: u32,
        revision: u64,
        seed: &ConvSeed,
        sender: &Sender<'_>,
        body: &ReadingBody,
    ) -> Result<Self> {
        if body.through == 0
            || body.through > i64::MAX as u64
            || generation == 0
            || revision == 0
            || revision > i64::MAX as u64
        {
            return Err(CoreError::format("阅读边界或记录版本无效"));
        }
        let mut value = Self {
            conv: conv.clone(),
            reader: sender.uid.clone(),
            reader_eldest: sender.eldest,
            device: sender.device.id(),
            generation,
            revision,
            ct: Bytes(Vec::new()),
            sig: Fixed([0; 64]),
        };
        let plain = serde_json::to_vec(body).map_err(|_| CoreError::format("阅读边界写不出"))?;
        let head = value.header();
        value.ct = Bytes(crypto::encrypt(&seed.reading_key(), &head, &plain));
        value.sig = sender
            .device
            .sign(ctx::READING, &crypto::frame(&[&head, &value.ct.0]));
        value.verify(&sender.device.public())?;
        Ok(value)
    }

    /// 服务器不解密，也能拒绝冒用账号、设备、记录版本或篡改密文。
    pub fn verify(&self, device: &DevicePublic) -> Result<()> {
        if device.id() != self.device
            || self.generation == 0
            || self.revision == 0
            || self.revision > i64::MAX as u64
            || self.ct.is_empty()
            || self.ct.len() > READING_CT_MAX
        {
            return Err(CoreError::format("阅读信封无效"));
        }
        device.verify(
            ctx::READING,
            &crypto::frame(&[&self.header(), &self.ct.0]),
            &self.sig,
        )
    }

    pub fn open(&self, seed: &ConvSeed, device: &DevicePublic) -> Result<ReadingBody> {
        self.verify(device)?;
        let plain = crypto::decrypt(&seed.reading_key(), &self.header(), &self.ct.0)?;
        let body: ReadingBody =
            serde_json::from_slice(&plain).map_err(|_| CoreError::format("阅读边界读不懂"))?;
        if body.through == 0 || body.through > i64::MAX as u64 {
            return Err(CoreError::format("阅读位置无效"));
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DeviceSecret;

    #[test]
    fn reading_is_encrypted_and_binds_scope_reader_device_and_revision() {
        let conv = ConvId::random();
        let uid = Uid::random();
        let device = DeviceSecret::generate();
        let seed = ConvSeed::generate();
        let sender = Sender {
            uid: &uid,
            eldest: Fixed([7; 32]),
            device: &device,
        };
        let body = ReadingBody {
            through: 42,
            message: MsgId::random(),
        };
        let envelope = ReadingEnvelope::seal(&conv, 1, 1, &seed, &sender, &body).unwrap();
        assert_eq!(envelope.open(&seed, &device.public()).unwrap(), body);
        let wire = serde_json::to_value(&envelope).unwrap();
        assert!(wire.get("through").is_none() && wire.get("message").is_none());
        assert!(
            envelope
                .open(&ConvSeed::generate(), &device.public())
                .is_err()
        );
        assert!(envelope.verify(&DeviceSecret::generate().public()).is_err());
        let mut changed = envelope.clone();
        changed.conv = ConvId::random();
        assert!(changed.verify(&device.public()).is_err());
        changed = envelope.clone();
        changed.revision += 1;
        assert!(changed.verify(&device.public()).is_err());
        changed = envelope.clone();
        changed.reader = Uid::random();
        assert!(changed.verify(&device.public()).is_err());
        changed = envelope;
        changed.ct.0[0] ^= 1;
        assert!(changed.verify(&device.public()).is_err());
    }

    #[test]
    fn reading_rejects_zero_and_out_of_range_boundaries() {
        let uid = Uid::random();
        let device = DeviceSecret::generate();
        let sender = Sender {
            uid: &uid,
            eldest: Fixed([7; 32]),
            device: &device,
        };
        for through in [0, u64::MAX] {
            assert!(
                ReadingEnvelope::seal(
                    &ConvId::random(),
                    1,
                    1,
                    &ConvSeed::generate(),
                    &sender,
                    &ReadingBody {
                        through,
                        message: MsgId::random()
                    }
                )
                .is_err()
            );
        }
    }
}
