//! 钥匙。
//!
//! | 钥匙 | 是什么 | 存在哪 |
//! |---|---|---|
//! | 电脑钥匙 [`DeviceSecret`] | 每台电脑一对签名钥匙（Ed25519）+ 一对收件钥匙（X25519），本机生成 | 私钥只在本机（插件交给 HHH 存系统凭据库）；公钥在账号签名链里 |
//! | 恢复密钥 [`RecoveryKey`] | 128 位随机数，确定性地派生出一对同样的钥匙，相当于一台“写在纸上的电脑” | 只给用户看一次，哪儿都不存 |
//! | 账号钥匙 [`AccountSeed`]（分代） | 32 字节种子，派生出账号的收件钥匙和“旧钥匙链”用的对称钥匙 | 每一代按每台电脑和恢复密钥各封装一份存服务器 |
//! | 会话钥匙 [`ConvSeed`]（分代） | 32 字节种子，派生出消息钥匙、资料钥匙、旧钥匙链钥匙和承诺值 | 按每个成员的当前账号钥匙各封装一份存服务器 |
//! | 群邀请钥匙 [`InviteSecret`] | 32 字节，只在邀请链接 `#` 后面 | 不发给服务器 |
//!
//! 所有私有材料在丢弃时清零（`ZeroizeOnDrop`），`Debug` 不输出内容。

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::bytes::{Bytes, Fixed};
use crate::crypto::{self, Sealed, ctx};
use crate::error::{CoreError, Result};
use crate::ids::{ConvId, DeviceId, Uid};

/// 一台电脑（或恢复密钥）的公钥：签名公钥 + 收件公钥。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePublic {
    /// Ed25519 签名公钥。
    pub sign: Fixed<32>,
    /// X25519 收件公钥。
    pub enc: Fixed<32>,
}

impl DevicePublic {
    /// 电脑编号（签名公钥的摘要）。
    pub fn id(&self) -> DeviceId {
        DeviceId::from_sign_key(&self.sign.0)
    }

    /// 验这台电脑的签名。
    pub fn verify(&self, label: &str, data: &[u8], signature: &Fixed<64>) -> Result<()> {
        crypto::verify(&self.sign.0, label, data, signature)
    }

    /// 检查签名公钥能用（收件公钥在封装时由 HPKE 检查）。
    pub fn check(&self) -> Result<()> {
        crypto::check_sign_public(&self.sign.0)
    }

    /// 32 + 32 字节的原始形式，用于签名与确认码的上下文。
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.sign.0);
        out[32..].copy_from_slice(&self.enc.0);
        out
    }
}

/// 一台电脑（或恢复密钥）的私钥。
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct DeviceSecret {
    sign: Fixed<32>,
    enc: Fixed<32>,
}

impl fmt::Debug for DeviceSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceSecret({})", self.id())
    }
}

impl DeviceSecret {
    /// 新生成一台电脑的钥匙。
    pub fn generate() -> Self {
        Self {
            sign: Fixed(crypto::random()),
            enc: Fixed(crypto::random()),
        }
    }

    fn from_parts(sign: &[u8; 32], enc: &[u8; 32]) -> Self {
        Self {
            sign: Fixed(*sign),
            enc: Fixed(*enc),
        }
    }

    /// 公钥。
    pub fn public(&self) -> DevicePublic {
        DevicePublic {
            sign: Fixed(crypto::sign_public(&self.sign.0)),
            enc: Fixed(crypto::enc_public(&self.enc.0)),
        }
    }

    /// 电脑编号。
    pub fn id(&self) -> DeviceId {
        DeviceId::from_sign_key(&crypto::sign_public(&self.sign.0))
    }

    /// 签名。
    pub fn sign(&self, label: &str, data: &[u8]) -> Fixed<64> {
        crypto::sign(&self.sign.0, label, data)
    }

    /// 打开封装给这台电脑的东西。
    pub fn open(&self, info: &[u8], sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>> {
        crypto::open_from(&self.enc.0, info, sealed)
    }
}

/// 恢复密钥：128 位随机数。编码见 [`crate::words`]（12 个词，或分组的字母数字）。
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey(pub(crate) [u8; 16]);

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey(…)")
    }
}

impl RecoveryKey {
    /// 新生成一把恢复密钥。
    pub fn generate() -> Self {
        Self(crypto::random())
    }

    /// 由 16 字节构造（解码用）。
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// 确定性派生出的“纸上电脑”钥匙：同一把恢复密钥在任何电脑上都派生出同一对钥匙。
    pub fn device_secret(&self) -> DeviceSecret {
        let sign = crypto::derive::<32>(&self.0, ctx::KDF_RECOVERY_SIGN);
        let enc = crypto::derive::<32>(&self.0, ctx::KDF_RECOVERY_ENC);
        DeviceSecret::from_parts(&sign, &enc)
    }
}

/// 账号钥匙某一代的公开部分，写在账号签名链里，也是打开封装后核对种子的承诺。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountKeyPub {
    /// 第几代，从 1 起。
    pub generation: u32,
    /// 这一代的 X25519 收件公钥：会话钥匙封装给它。
    pub enc: Fixed<32>,
}

/// 账号钥匙某一代的种子。
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct AccountSeed([u8; 32]);

impl fmt::Debug for AccountSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountSeed(…)")
    }
}

impl AccountSeed {
    /// 新生成一代。
    pub fn generate() -> Self {
        Self(crypto::random())
    }

    /// 由 32 字节构造（从封装或凭据里取回）。
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| CoreError::format("账号钥匙种子长度不对"))
    }

    /// 原始 32 字节（交给 HHH 存凭据、封装给电脑时用）。
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn enc_secret(&self) -> Zeroizing<[u8; 32]> {
        crypto::derive::<32>(&self.0, ctx::KDF_ACCOUNT_ENC)
    }

    /// 这一代的公开部分。
    pub fn public(&self, generation: u32) -> AccountKeyPub {
        AccountKeyPub {
            generation,
            enc: Fixed(crypto::enc_public(&self.enc_secret())),
        }
    }

    /// 打开封装给账号钥匙的东西（会话钥匙）。
    pub fn open(&self, info: &[u8], sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>> {
        crypto::open_from(&self.enc_secret(), info, sealed)
    }

    /// 核对种子与签名链里这一代的公钥一致：服务器塞来的假种子在这里被拒。
    pub fn check(&self, expected: &AccountKeyPub) -> Result<()> {
        if self.public(expected.generation).enc == expected.enc {
            Ok(())
        } else {
            Err(CoreError::KeyMismatch(format!("账号钥匙第 {} 代", expected.generation)))
        }
    }

    /// 旧钥匙链：用这一代的钥匙加密上一代的种子。新电脑只要拿到最新一代，就能一路倒推出全部旧代。
    pub fn wrap_previous(&self, uid: &Uid, epoch: u32, generation: u32, previous: &AccountSeed) -> Bytes {
        let key = crypto::derive::<32>(&self.0, ctx::KDF_ACCOUNT_PREV);
        Bytes(crypto::encrypt(&key, &account_prev_aad(uid, epoch, generation), &previous.0))
    }

    /// 解开 [`wrap_previous`](Self::wrap_previous) 得到上一代种子；调用方随后要用签名链核对。
    pub fn unwrap_previous(&self, uid: &Uid, epoch: u32, generation: u32, wrapped: &Bytes) -> Result<AccountSeed> {
        let key = crypto::derive::<32>(&self.0, ctx::KDF_ACCOUNT_PREV);
        let plain = crypto::decrypt(&key, &account_prev_aad(uid, epoch, generation), &wrapped.0)?;
        AccountSeed::from_slice(&plain)
    }
}

fn account_prev_aad(uid: &Uid, epoch: u32, generation: u32) -> Vec<u8> {
    crypto::frame(&[
        ctx::AEAD_ACCOUNT_PREV.as_bytes(),
        uid.as_str().as_bytes(),
        &epoch.to_be_bytes(),
        &generation.to_be_bytes(),
    ])
}

/// 把账号钥匙种子封装给某台电脑时的 `info`：绑定账号、重置轮次、代数、收件电脑。
pub fn account_seed_info(uid: &Uid, epoch: u32, generation: u32, device: &DeviceId) -> Vec<u8> {
    crypto::frame(&[
        ctx::SEAL_ACCOUNT_SEED.as_bytes(),
        uid.as_str().as_bytes(),
        &epoch.to_be_bytes(),
        &generation.to_be_bytes(),
        device.as_str().as_bytes(),
    ])
}

/// 会话钥匙某一代的公开部分，写在会话签名链里。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvKeyPub {
    /// 第几代，从 1 起。
    pub generation: u32,
    /// 对种子的承诺（HKDF 派生，单向）：打开封装后核对，服务器塞不进自己选的种子。
    pub commit: Fixed<32>,
}

/// 会话钥匙某一代的种子。
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ConvSeed([u8; 32]);

impl fmt::Debug for ConvSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConvSeed(…)")
    }
}

impl ConvSeed {
    /// 新生成一代。
    pub fn generate() -> Self {
        Self(crypto::random())
    }

    /// 由 32 字节构造。
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| CoreError::format("会话钥匙种子长度不对"))
    }

    /// 原始 32 字节（封装、邀请链接用）。
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 这一代的公开部分。
    pub fn public(&self, generation: u32) -> ConvKeyPub {
        ConvKeyPub {
            generation,
            commit: Fixed(*crypto::derive::<32>(&self.0, ctx::KDF_CONV_COMMIT)),
        }
    }

    /// 核对种子与签名链里这一代的承诺一致。
    pub fn check(&self, expected: &ConvKeyPub) -> Result<()> {
        if self.public(expected.generation).commit == expected.commit {
            Ok(())
        } else {
            Err(CoreError::KeyMismatch(format!("会话钥匙第 {} 代", expected.generation)))
        }
    }

    /// 消息钥匙。
    pub fn message_key(&self) -> Zeroizing<[u8; 32]> {
        crypto::derive::<32>(&self.0, ctx::KDF_CONV_MSG)
    }

    /// 群资料（群名、头像、简介）钥匙。
    pub fn profile_key(&self) -> Zeroizing<[u8; 32]> {
        crypto::derive::<32>(&self.0, ctx::KDF_CONV_PROFILE)
    }

    /// 阅读状态使用独立派生钥匙，不复用消息或群资料的密钥空间。
    pub fn reading_key(&self) -> Zeroizing<[u8; 32]> {
        crypto::derive::<32>(&self.0, ctx::KDF_CONV_READING)
    }

    /// 旧钥匙链：用这一代加密上一代种子。新成员只拿到当前一代，就能倒推出以前全部的代，看到全部历史。
    pub fn wrap_previous(&self, conv: &ConvId, generation: u32, previous: &ConvSeed) -> Bytes {
        let key = crypto::derive::<32>(&self.0, ctx::KDF_CONV_PREV);
        Bytes(crypto::encrypt(&key, &conv_prev_aad(conv, generation), &previous.0))
    }

    /// 解开 [`wrap_previous`](Self::wrap_previous)；调用方随后要用签名链里上一代的承诺核对。
    pub fn unwrap_previous(&self, conv: &ConvId, generation: u32, wrapped: &Bytes) -> Result<ConvSeed> {
        let key = crypto::derive::<32>(&self.0, ctx::KDF_CONV_PREV);
        let plain = crypto::decrypt(&key, &conv_prev_aad(conv, generation), &wrapped.0)?;
        ConvSeed::from_slice(&plain)
    }
}

fn conv_prev_aad(conv: &ConvId, generation: u32) -> Vec<u8> {
    crypto::frame(&[ctx::AEAD_CONV_PREV.as_bytes(), conv.as_str().as_bytes(), &generation.to_be_bytes()])
}

/// 把会话钥匙种子封装给某个成员的账号钥匙时的 `info`：绑定会话、代数、成员、成员账号钥匙的轮次与代数。
pub fn conv_seed_info(conv: &ConvId, generation: u32, member: &Uid, account_epoch: u32, account_generation: u32) -> Vec<u8> {
    crypto::frame(&[
        ctx::SEAL_CONV_SEED.as_bytes(),
        conv.as_str().as_bytes(),
        &generation.to_be_bytes(),
        member.as_str().as_bytes(),
        &account_epoch.to_be_bytes(),
        &account_generation.to_be_bytes(),
    ])
}

/// 群邀请链接里的钥匙：派生出邀请签名钥匙（证明加入的人确实拿到了链接）和包裹会话种子的对称钥匙。
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct InviteSecret([u8; 32]);

impl fmt::Debug for InviteSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InviteSecret(…)")
    }
}

impl InviteSecret {
    /// 新生成一把。
    pub fn generate() -> Self {
        Self(crypto::random())
    }

    /// 由 32 字节构造（解析链接时用）。
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| CoreError::format("邀请钥匙长度不对"))
    }

    /// 原始 32 字节（写进链接）。
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn sign_seed(&self) -> Zeroizing<[u8; 32]> {
        crypto::derive::<32>(&self.0, ctx::KDF_INVITE_SIGN)
    }

    /// 邀请签名公钥：写进会话签名链，成员用它核对加入的人拿到过链接。
    pub fn public(&self) -> Fixed<32> {
        Fixed(crypto::sign_public(&self.sign_seed()))
    }

    /// 用邀请钥匙签名。
    pub fn sign(&self, label: &str, data: &[u8]) -> Fixed<64> {
        crypto::sign(&self.sign_seed(), label, data)
    }

    /// 把会话种子包起来交给服务器（服务器没有链接里的钥匙，解不开）。
    pub fn wrap_seed(&self, conv: &ConvId, generation: u32, seed: &ConvSeed) -> Bytes {
        let key = crypto::derive::<32>(&self.0, ctx::KDF_INVITE_WRAP);
        Bytes(crypto::encrypt(&key, &invite_aad(conv, generation), seed.as_bytes()))
    }

    /// 解开 [`wrap_seed`](Self::wrap_seed)；调用方随后要用签名链里的承诺核对。
    pub fn unwrap_seed(&self, conv: &ConvId, generation: u32, wrapped: &Bytes) -> Result<ConvSeed> {
        let key = crypto::derive::<32>(&self.0, ctx::KDF_INVITE_WRAP);
        let plain = crypto::decrypt(&key, &invite_aad(conv, generation), &wrapped.0)?;
        ConvSeed::from_slice(&plain)
    }
}

fn invite_aad(conv: &ConvId, generation: u32) -> Vec<u8> {
    crypto::frame(&[ctx::AEAD_INVITE_SEED.as_bytes(), conv.as_str().as_bytes(), &generation.to_be_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_key_derives_the_same_device_every_time() {
        let recovery = RecoveryKey::generate();
        assert_eq!(recovery.device_secret().public(), recovery.device_secret().public());
        assert_ne!(recovery.device_secret().public(), RecoveryKey::generate().device_secret().public());
    }

    #[test]
    fn device_secret_round_trips_through_serde_for_credential_storage() {
        let secret = DeviceSecret::generate();
        let json = serde_json::to_string(&secret).unwrap();
        let back: DeviceSecret = serde_json::from_str(&json).unwrap();
        assert_eq!(back.public(), secret.public());
        assert!(!format!("{secret:?}").contains(&json[10..20]));
    }

    #[test]
    fn account_seed_sealed_to_device_opens_and_checks() {
        let uid = Uid::random();
        let device = DeviceSecret::generate();
        let seed = AccountSeed::generate();
        let info = account_seed_info(&uid, 0, 1, &device.id());
        let sealed = crypto::seal_to(&device.public().enc.0, &info, seed.as_bytes()).unwrap();
        let opened = AccountSeed::from_slice(&device.open(&info, &sealed).unwrap()).unwrap();
        assert!(opened.check(&seed.public(1)).is_ok());
        assert!(AccountSeed::generate().check(&seed.public(1)).is_err());
        assert!(device.open(&account_seed_info(&uid, 0, 2, &device.id()), &sealed).is_err());
    }

    #[test]
    fn previous_chains_walk_back() {
        let uid = Uid::random();
        let (g1, g2) = (AccountSeed::generate(), AccountSeed::generate());
        let wrapped = g2.wrap_previous(&uid, 0, 2, &g1);
        assert_eq!(g2.unwrap_previous(&uid, 0, 2, &wrapped).unwrap(), g1);
        assert!(g1.unwrap_previous(&uid, 0, 2, &wrapped).is_err());

        let conv = ConvId::random();
        let (c1, c2) = (ConvSeed::generate(), ConvSeed::generate());
        let wrapped = c2.wrap_previous(&conv, 2, &c1);
        let back = c2.unwrap_previous(&conv, 2, &wrapped).unwrap();
        assert!(back.check(&c1.public(1)).is_ok());
        assert!(c2.unwrap_previous(&ConvId::random(), 2, &wrapped).is_err());
    }

    #[test]
    fn conv_seed_commit_rejects_substituted_seed() {
        let seed = ConvSeed::generate();
        assert!(seed.check(&seed.public(3)).is_ok());
        assert!(ConvSeed::generate().check(&seed.public(3)).is_err());
    }

    #[test]
    fn invite_secret_wraps_seed_and_signs() {
        let conv = ConvId::random();
        let invite = InviteSecret::generate();
        let seed = ConvSeed::generate();
        let wrapped = invite.wrap_seed(&conv, 1, &seed);
        assert_eq!(invite.unwrap_seed(&conv, 1, &wrapped).unwrap(), seed);
        assert!(InviteSecret::generate().unwrap_seed(&conv, 1, &wrapped).is_err());
        let sig = invite.sign("x", b"y");
        assert!(crypto::verify(&invite.public().0, "x", b"y", &sig).is_ok());
    }
}
