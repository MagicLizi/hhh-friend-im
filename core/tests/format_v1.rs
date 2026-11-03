//! 格式夹具：锁住第 1 版的线上格式。
//!
//! 插件和服务器都按同一个 core 编译，两边当下总是对得上；这里防的是以后改代码时格式悄悄变了——
//! 用户手里的旧数据就再也验不过、解不开。夹具里有两类东西：
//!
//! - 固定输入算出来的（编号、签名链一环、恢复密钥的两种写法、一帧请求）：每次重算，必须一字不差；
//! - 事先存好的密文（消息、封装的账号钥匙）：加密带随机数，存一份当时的结果，现在的代码必须还解得开。
//!
//! 只有有意改格式（同时把对应的版本号加 1）时才重新生成：
//! `FRIEND_IM_WRITE_FIXTURES=1 cargo test -p friend-im-core --test format_v1`

use friend_im_core::account::{AccountLink, AccountState, DeviceEntry, eldest_body};
use friend_im_core::bytes::{Bytes, Fixed};
use friend_im_core::crypto::{self, Sealed};
use friend_im_core::file;
use friend_im_core::ids::{ConvId, MsgId, Uid};
use friend_im_core::keys::{AccountSeed, ConvSeed, DeviceSecret, RecoveryKey, account_seed_info};
use friend_im_core::message::{Content, Envelope, MESSAGE_VERSION, MessageBody, Part, Sender};
use friend_im_core::wire::{self, ClientFrame, DeviceKind, HelloAuth, Request};
use serde::{Deserialize, Serialize};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/format-v1.json");

#[derive(Serialize, Deserialize)]
struct Fixture {
    uid: Uid,
    device_id: String,
    eldest_link: AccountLink,
    eldest_hash: Fixed<32>,
    recovery_words: String,
    recovery_groups: String,
    hello_frame: String,
    envelope: Envelope,
    message: MessageBody,
    account_seed_box: Sealed,
}

// 固定的输入：钥匙材料都是写死的字节，只用于夹具。
fn device() -> DeviceSecret {
    serde_json::from_value(serde_json::json!({ "sign": friend_im_core::bytes::encode(&[0x11; 32]), "enc": friend_im_core::bytes::encode(&[0x22; 32]) }))
        .expect("电脑私钥的存储格式")
}
fn recovery() -> RecoveryKey {
    RecoveryKey::from_bytes([0x5a; 16])
}
fn account_seed() -> AccountSeed {
    AccountSeed::from_slice(&[0x33; 32]).unwrap()
}
fn conv_seed() -> ConvSeed {
    ConvSeed::from_slice(&[0x44; 32]).unwrap()
}
fn conv() -> ConvId {
    ConvId::from_raw([0x55; 16])
}
fn uid() -> Uid {
    Uid::from_cindy("https://auth.cindy.app", "mem_fixture")
}
const FILE_KEY: [u8; 32] = [0x66; 32];

fn eldest() -> AccountLink {
    let entry = DeviceEntry { keys: device().public(), name: "夹具电脑".into(), kind: DeviceKind::Computer };
    AccountLink::sign(&eldest_body(&uid(), 0, entry, &recovery().device_secret(), account_seed().public(1), 1_700_000_000_000), &device())
}

fn hello() -> String {
    let device = device();
    let nonce = Fixed([0x77; 32]);
    let frame = ClientFrame {
        id: 1,
        req: Request::Hello {
            protocol: wire::PROTOCOL_VERSION,
            auth: HelloAuth::Session { token: Bytes(vec![0x88; 32]) },
            device: device.public(),
            name: "夹具电脑".into(),
            kind: DeviceKind::Computer,
            sig: wire::sign_hello(&device, &nonce),
        },
    };
    serde_json::to_string(&frame).unwrap()
}

fn message() -> MessageBody {
    MessageBody {
        v: MESSAGE_VERSION,
        ctime_ms: 1_700_000_000_123,
        content: Content::Post {
            parts: vec![
                Part::Text { text: "你好，夹具".into() },
                Part::Mention { uid: None, name: None, everyone: true },
            ],
            reply_to: Some(MsgId::from_raw([0x99; 16])),
        },
    }
}

fn generate() -> Fixture {
    let link = eldest();
    let device = device();
    let sender = Sender { uid: &uid(), eldest: link.hash(), device: &device };
    let envelope = Envelope::seal(&conv(), MsgId::from_raw([0xaa; 16]), 1, &conv_seed(), &sender, &message()).unwrap();
    let info = account_seed_info(&uid(), 0, 1, &device.id());
    Fixture {
        uid: uid(),
        device_id: device.id().to_string(),
        eldest_hash: link.hash(),
        eldest_link: link,
        recovery_words: recovery().to_words().to_string(),
        recovery_groups: recovery().to_groups().to_string(),
        hello_frame: hello(),
        envelope,
        message: message(),
        account_seed_box: crypto::seal_to(&device.public().enc.0, &info, account_seed().as_bytes()).unwrap(),
    }
}

#[test]
fn version_1_formats_have_not_drifted() {
    if std::env::var_os("FRIEND_IM_WRITE_FIXTURES").is_some() {
        std::fs::create_dir_all(std::path::Path::new(PATH).parent().unwrap()).unwrap();
        std::fs::write(PATH, serde_json::to_string_pretty(&generate()).unwrap() + "\n").unwrap();
    }
    let text = std::fs::read_to_string(PATH).expect("夹具文件存在（第一次用 FRIEND_IM_WRITE_FIXTURES=1 生成）");
    let fixture: Fixture = serde_json::from_str(&text).expect("夹具读得懂");

    // 固定输入算出来的：一字不差。
    assert_eq!(uid(), fixture.uid, "账号编号的算法变了");
    assert_eq!(device().id().to_string(), fixture.device_id, "电脑编号的算法变了");
    assert_eq!(eldest(), fixture.eldest_link, "签名链一环的原文或签名变了");
    assert_eq!(fixture.eldest_link.hash(), fixture.eldest_hash, "身份指纹的算法变了");
    assert!(AccountState::eldest(&fixture.uid, 0, &fixture.eldest_link, 1).is_ok(), "存好的第一环验不过了");
    assert_eq!(recovery().to_words().as_str(), fixture.recovery_words, "恢复密钥的 12 个词变了");
    assert_eq!(recovery().to_groups().as_str(), fixture.recovery_groups, "恢复密钥的分组写法变了");
    assert_eq!(RecoveryKey::parse(&fixture.recovery_words).unwrap(), recovery());
    assert_eq!(RecoveryKey::parse(&fixture.recovery_groups).unwrap(), recovery());
    assert_eq!(hello(), fixture.hello_frame, "登录帧的格式变了");

    // 事先存好的密文：现在的代码还解得开、验得过。
    assert_eq!(fixture.envelope.open(&conv_seed(), &device().public()).unwrap(), fixture.message, "存好的消息解不开了");
    assert_eq!(fixture.message, message());
    let info = account_seed_info(&uid(), 0, 1, &device().id());
    let opened = device().open(&info, &fixture.account_seed_box).expect("存好的账号钥匙封装打不开了");
    assert_eq!(opened.as_slice(), account_seed().as_bytes());
}

/// 个人资料后加的加密头像文件（`photo`，0.4.0）：不带时与旧版写的一字不差，旧版写的照样读得懂；带了读回不走样。
#[test]
fn a_profile_photo_keeps_older_profiles() {
    let old = r#"{"type":"profile","avatar":"https://cdn.cindy.app/a.png"}"#;
    let plain = Content::Profile { avatar: Some("https://cdn.cindy.app/a.png".into()), photo: None };
    assert_eq!(serde_json::to_string(&plain).unwrap(), old, "不带头像文件的个人资料变了");
    assert_eq!(serde_json::from_str::<Content>(old).unwrap(), plain, "旧版的个人资料读不懂了");
    let photo = file::FileRef {
        id: friend_im_core::ids::FileId::from_raw([0xbb; 16]),
        key: Fixed(FILE_KEY),
        size: 2_048,
        name: "avatar.png".into(),
        mime: "image/png".into(),
        sha256: None,
    };
    let with_photo = Content::Profile { avatar: None, photo: Some(photo) };
    let text = serde_json::to_string(&with_photo).unwrap();
    assert!(!text.contains("\"avatar\""), "新版不写 Cindy 头像地址");
    assert_eq!(serde_json::from_str::<Content>(&text).unwrap(), with_photo);
}
