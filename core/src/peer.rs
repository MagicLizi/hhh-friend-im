//! 设备之间的帧：用接收设备的收件公钥封装、用发送设备的签名钥匙签名。局域网和服务器转交传的都是它，
//! 服务器与局域网里的中间人都只看到密文。发送设备是否属于这个账号由接收方按自己验过的账号签名链判断。

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::bytes::Fixed;
use crate::crypto::{self, Sealed, ctx};
use crate::error::{CoreError, Result};
use crate::ids::{DeviceId, Uid};
use crate::keys::{DevicePublic, DeviceSecret};

/// 一帧明文的上限：一批原件 512 KiB，再留出格式的余量；封装后走 base64 仍放得进 1 MiB 的连接帧。
pub const PEER_PLAIN_MAX: usize = 640 * 1024;

/// 端到端加密的一帧。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedFrame {
    /// 发送账号。
    pub uid: Uid,
    /// 发送设备。
    pub from: DeviceId,
    /// 接收设备。
    pub to: DeviceId,
    /// 密文。
    pub sealed: Sealed,
    /// 发送设备对以上全部的签名。
    pub sig: Fixed<64>,
}

fn info(uid: &Uid, from: &DeviceId, to: &DeviceId) -> Vec<u8> {
    crypto::frame(&[ctx::PEER_FRAME.as_bytes(), uid.as_str().as_bytes(), from.as_str().as_bytes(), to.as_str().as_bytes()])
}

fn signed(info: &[u8], sealed: &Sealed) -> Vec<u8> {
    crypto::frame(&[info, &sealed.enc.0, &sealed.ct.0])
}

impl SealedFrame {
    /// 封一帧。
    pub fn seal(uid: &Uid, from: &DeviceSecret, to: &DevicePublic, plain: &[u8]) -> Result<Self> {
        if plain.len() > PEER_PLAIN_MAX {
            return Err(CoreError::Limit("这一帧太大".into()));
        }
        let (me, target) = (from.id(), to.id());
        let info = info(uid, &me, &target);
        let sealed = crypto::seal_to(&to.enc.0, &info, plain)?;
        let sig = from.sign(ctx::PEER_FRAME, &signed(&info, &sealed));
        Ok(Self { uid: uid.clone(), from: me, to: target, sealed, sig })
    }

    /// 开一帧。`sender` 是调用方按账号签名链查到的发送设备公钥。
    pub fn open(&self, me: &DeviceSecret, sender: &DevicePublic) -> Result<Zeroizing<Vec<u8>>> {
        if sender.id() != self.from || me.id() != self.to {
            return Err(CoreError::BadSignature);
        }
        let info = info(&self.uid, &self.from, &self.to);
        sender.verify(ctx::PEER_FRAME, &signed(&info, &self.sealed), &self.sig)?;
        me.open(&info, &self.sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_target_can_open_a_frame_and_tampering_is_refused() {
        let uid = Uid::random();
        let (a, b, c) = (DeviceSecret::generate(), DeviceSecret::generate(), DeviceSecret::generate());
        let frame = SealedFrame::seal(&uid, &a, &b.public(), b"hello").unwrap();
        assert_eq!(frame.open(&b, &a.public()).unwrap().as_slice(), b"hello");
        assert!(frame.open(&c, &a.public()).is_err(), "别的设备打不开");
        assert!(frame.open(&b, &c.public()).is_err(), "发送设备对不上");

        let mut forged = frame.clone();
        forged.uid = Uid::random();
        assert!(forged.open(&b, &a.public()).is_err(), "改账号验不过");
        let mut forged = frame.clone();
        forged.sealed.ct.0[0] ^= 1;
        assert!(forged.open(&b, &a.public()).is_err(), "改密文验不过");
        // 冒充别的设备发：拿 c 的钥匙签，声称是 a。
        let mut forged = SealedFrame::seal(&uid, &c, &b.public(), b"x").unwrap();
        forged.from = a.id();
        assert!(forged.open(&b, &a.public()).is_err());
    }

    #[test]
    fn oversized_frames_are_refused() {
        let (a, b) = (DeviceSecret::generate(), DeviceSecret::generate());
        assert!(SealedFrame::seal(&Uid::random(), &a, &b.public(), &vec![0; PEER_PLAIN_MAX + 1]).is_err());
    }
}
