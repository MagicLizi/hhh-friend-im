//! 加密原语。全部是标准构造，不自创：
//!
//! | 用途 | 构造 |
//! |---|---|
//! | 摘要 | SHA-256，前面加用途标签与一个 0 字节（不同用途的摘要不会撞） |
//! | 由种子派生钥匙 | HKDF-SHA256，每种用途一个固定标签 |
//! | 签名 | Ed25519（`verify_strict`，拒绝可塑签名），签的内容前面同样加用途标签 |
//! | 确认码 | HMAC-SHA256 |
//! | 消息、群资料、旧钥匙链 | XChaCha20-Poly1305，每次随机 24 字节随机数 |
//! | 把种子封装给某把收件钥匙 | HPKE（RFC 9180）base 模式：X25519 + HKDF-SHA256 + ChaCha20-Poly1305 |
//!
//! 文件的分段流式加密在 [`crate::file`]。

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::bytes::{Bytes, Fixed};
use crate::error::{CoreError, Result};

/// 用途标签。改任何一个都会让旧数据验不过、解不开，所以只能加不能改。
pub mod ctx {
    pub const UID: &str = "friend-im/v1/uid";
    pub const DEVICE_ID: &str = "friend-im/v1/device-id";
    pub const ACCOUNT_LINK: &str = "friend-im/v1/account-link";
    pub const CONV_LINK: &str = "friend-im/v1/conv-link";
    pub const DEVICE_PROOF: &str = "friend-im/v1/device-proof";
    pub const HELLO: &str = "friend-im/v1/hello";
    pub const MESSAGE: &str = "friend-im/v1/message";
    pub const INVITE_JOIN: &str = "friend-im/v1/invite-join";

    pub const KDF_RECOVERY_SIGN: &str = "friend-im/v1/recovery/sign";
    pub const KDF_RECOVERY_ENC: &str = "friend-im/v1/recovery/enc";
    pub const KDF_ACCOUNT_ENC: &str = "friend-im/v1/account/enc";
    pub const KDF_ACCOUNT_PREV: &str = "friend-im/v1/account/prev";
    pub const KDF_CONV_MSG: &str = "friend-im/v1/conv/msg";
    pub const KDF_CONV_PROFILE: &str = "friend-im/v1/conv/profile";
    pub const KDF_CONV_READING: &str = "friend-im/v1/conv/reading-key";
    pub const READING: &str = "friend-im/v1/reading";
    pub const KDF_CONV_PREV: &str = "friend-im/v1/conv/prev";
    pub const KDF_CONV_COMMIT: &str = "friend-im/v1/conv/commit";
    pub const KDF_INVITE_SIGN: &str = "friend-im/v1/invite/sign";
    pub const KDF_INVITE_WRAP: &str = "friend-im/v1/invite/wrap";
    pub const KDF_PAKE_CONFIRM_A: &str = "friend-im/v1/pake/confirm-new-device";
    pub const KDF_PAKE_CONFIRM_B: &str = "friend-im/v1/pake/confirm-approver";

    pub const SEAL_ACCOUNT_SEED: &str = "friend-im/v1/seal/account-seed";
    pub const SEAL_CONV_SEED: &str = "friend-im/v1/seal/conv-seed";
    pub const AEAD_ACCOUNT_PREV: &str = "friend-im/v1/aead/account-prev";
    pub const AEAD_CONV_PREV: &str = "friend-im/v1/aead/conv-prev";
    pub const AEAD_CONV_PROFILE: &str = "friend-im/v1/aead/conv-profile";
    pub const AEAD_INVITE_SEED: &str = "friend-im/v1/aead/invite-seed";
}

type HpkeKem = hpke::kem::X25519HkdfSha256;
type HpkeKdf = hpke::kdf::HkdfSha256;
type HpkeAead = hpke::aead::ChaCha20Poly1305;

/// 取 N 个字节的系统随机数。
///
/// # Panics
///
/// 操作系统给不出随机数时直接停下：拿不到随机数就生成不了任何钥匙，继续只会更糟。
pub fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("操作系统给不出随机数");
    out
}

fn labeled(label: &str, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(label.len() + 1 + data.len());
    out.extend_from_slice(label.as_bytes());
    out.push(0);
    out.extend_from_slice(data);
    out
}

/// 带用途标签的 SHA-256。
pub fn hash(label: &str, data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update([0u8]);
    hasher.update(data);
    hasher.finalize().into()
}

/// 由种子按用途标签派生 N 字节（HKDF-SHA256，不加盐：种子本身是均匀随机的 32 字节或 16 字节）。
pub fn derive<const N: usize>(seed: &[u8], label: &str) -> Zeroizing<[u8; N]> {
    let mut out = Zeroizing::new([0u8; N]);
    Hkdf::<Sha256>::new(None, seed)
        .expand(label.as_bytes(), out.as_mut())
        .expect("HKDF 输出长度在允许范围内");
    out
}

/// HMAC-SHA256。
pub fn mac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key).expect("HMAC 接受任意长度的钥匙");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// 常量时间比较两个确认码。
pub fn mac_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// 用 Ed25519 私钥种子签名，签的是“用途标签 + 0 + 内容”。
pub fn sign(seed: &[u8; 32], label: &str, data: &[u8]) -> Fixed<64> {
    let key = SigningKey::from_bytes(seed);
    Fixed(key.sign(&labeled(label, data)).to_bytes())
}

/// Ed25519 私钥种子对应的公钥。
pub fn sign_public(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// 验签（严格模式：拒绝弱公钥与可塑签名）。
pub fn verify(public: &[u8; 32], label: &str, data: &[u8], signature: &Fixed<64>) -> Result<()> {
    let key = VerifyingKey::from_bytes(public).map_err(|_| CoreError::BadSignature)?;
    if key.is_weak() {
        return Err(CoreError::BadSignature);
    }
    key.verify_strict(&labeled(label, data), &Signature::from_bytes(&signature.0))
        .map_err(|_| CoreError::BadSignature)
}

/// 检查一把签名公钥能不能用（是曲线上的点、不是弱公钥）。
pub fn check_sign_public(public: &[u8; 32]) -> Result<()> {
    match VerifyingKey::from_bytes(public) {
        Ok(key) if !key.is_weak() => Ok(()),
        _ => Err(CoreError::format("签名公钥不能用")),
    }
}

/// 对称加密：输出“24 字节随机数 + 密文（含 16 字节校验）”。
pub fn encrypt(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    let nonce: [u8; 24] = random();
    let sealed = cipher
        .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad })
        .expect("XChaCha20-Poly1305 加密不会失败");
    let mut out = Vec::with_capacity(24 + sealed.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    out
}

/// 对称解密，[`encrypt`] 的反向。
pub fn decrypt(key: &[u8; 32], aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < 24 + 16 {
        return Err(CoreError::Decrypt);
    }
    let (nonce, sealed) = data.split_at(24);
    let nonce: [u8; 24] = nonce.try_into().map_err(|_| CoreError::Decrypt)?;
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    cipher
        .decrypt(&XNonce::from(nonce), Payload { msg: sealed, aad })
        .map(Zeroizing::new)
        .map_err(|_| CoreError::Decrypt)
}

/// HPKE 封装的结果：封装钥匙 + 密文。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    /// 发送方的临时公钥（RFC 9180 的 `enc`）。
    pub enc: Fixed<32>,
    /// 密文（含 16 字节校验）。
    pub ct: Bytes,
}

/// X25519 收件私钥对应的公钥。
pub fn enc_public(secret: &[u8; 32]) -> [u8; 32] {
    let secret = <HpkeKem as hpke::Kem>::PrivateKey::from_bytes(secret).expect("任意 32 字节都是合法的 X25519 私钥");
    let public = HpkeKem::sk_to_pk(&secret).to_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&public);
    out
}

/// 把一段（通常是 32 字节的种子）封装给一把 X25519 收件公钥；`info` 绑定用途与上下文，开的一方必须给同样的值。
pub fn seal_to(recipient: &[u8; 32], info: &[u8], plaintext: &[u8]) -> Result<Sealed> {
    let public = <HpkeKem as hpke::Kem>::PublicKey::from_bytes(recipient)
        .map_err(|_| CoreError::format("收件公钥不能用"))?;
    let (enc, ct) = hpke::single_shot_seal::<HpkeAead, HpkeKdf, HpkeKem>(&OpModeS::Base, &public, info, plaintext, b"")
        .map_err(|_| CoreError::format("收件公钥不能用"))?;
    let enc = Fixed::from_slice(&enc.to_bytes()).ok_or_else(|| CoreError::format("封装钥匙长度不对"))?;
    Ok(Sealed { enc, ct: Bytes(ct) })
}

/// 用 X25519 收件私钥打开 [`seal_to`] 的结果。
pub fn open_from(secret: &[u8; 32], info: &[u8], sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>> {
    let secret = <HpkeKem as hpke::Kem>::PrivateKey::from_bytes(secret).map_err(|_| CoreError::Decrypt)?;
    let enc = <HpkeKem as hpke::Kem>::EncappedKey::from_bytes(&sealed.enc.0).map_err(|_| CoreError::Decrypt)?;
    hpke::single_shot_open::<HpkeAead, HpkeKdf, HpkeKem>(&OpModeR::Base, &secret, &enc, info, &sealed.ct.0, b"")
        .map(Zeroizing::new)
        .map_err(|_| CoreError::Decrypt)
}

/// 把若干段拼成一段附加数据或 HPKE `info`：每段前面写 4 字节长度，段与段之间不会有歧义。
pub fn frame(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_round_trip_and_tamper_detection() {
        let key = random::<32>();
        let data = encrypt(&key, b"aad", b"hello");
        assert_eq!(decrypt(&key, b"aad", &data).unwrap().as_slice(), b"hello");
        assert_eq!(decrypt(&key, b"other", &data), Err(CoreError::Decrypt));
        let mut tampered = data.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(decrypt(&key, b"aad", &tampered), Err(CoreError::Decrypt));
        assert_eq!(decrypt(&random::<32>(), b"aad", &data), Err(CoreError::Decrypt));
        assert_eq!(decrypt(&key, b"aad", &data[..30]), Err(CoreError::Decrypt));
    }

    #[test]
    fn same_plaintext_encrypts_differently_each_time() {
        let key = random::<32>();
        assert_ne!(encrypt(&key, b"", b"x"), encrypt(&key, b"", b"x"));
    }

    #[test]
    fn hpke_round_trip_binds_info() {
        let secret = random::<32>();
        let public = enc_public(&secret);
        let sealed = seal_to(&public, b"info", b"seed").unwrap();
        assert_eq!(open_from(&secret, b"info", &sealed).unwrap().as_slice(), b"seed");
        assert_eq!(open_from(&secret, b"other", &sealed), Err(CoreError::Decrypt));
        assert_eq!(open_from(&random::<32>(), b"info", &sealed), Err(CoreError::Decrypt));
    }

    #[test]
    fn hpke_rejects_low_order_recipient() {
        assert!(seal_to(&[0u8; 32], b"info", b"seed").is_err());
    }

    #[test]
    fn signatures_bind_label_and_content() {
        let seed = random::<32>();
        let public = sign_public(&seed);
        let sig = sign(&seed, "a", b"data");
        assert!(verify(&public, "a", b"data", &sig).is_ok());
        assert_eq!(verify(&public, "b", b"data", &sig), Err(CoreError::BadSignature));
        assert_eq!(verify(&public, "a", b"datb", &sig), Err(CoreError::BadSignature));
        assert_eq!(verify(&sign_public(&random::<32>()), "a", b"data", &sig), Err(CoreError::BadSignature));
    }

    #[test]
    fn labels_separate_hashes_and_derivations() {
        assert_ne!(hash("a", b"x"), hash("b", b"x"));
        assert_ne!(hash("ab", b"c"), hash("a", b"bc"));
        assert_ne!(*derive::<32>(b"seed", "a"), *derive::<32>(b"seed", "b"));
        assert_eq!(*derive::<32>(b"seed", "a"), *derive::<32>(b"seed", "a"));
    }

    #[test]
    fn frame_has_no_ambiguity() {
        assert_ne!(frame(&[b"ab", b"c"]), frame(&[b"a", b"bc"]));
    }
}
