//! 消息：先签名、再加密。
//!
//! - 发送的电脑用自己的签名钥匙签“消息头 + 正文”，签名放进密文里：群里别的成员拿着会话钥匙也仿冒不了别人的消息。
//! - 用当前一代会话钥匙的消息钥匙加密（XChaCha20-Poly1305），附加数据就是消息头
//!   （会话、消息编号、代数、发送账号与电脑、撤回目标），改动任何一项都解不开。
//! - 消息编号由发送的电脑随机生成并签进密文：服务器重放旧密文只会被当成同一条。
//!
//! 撤回本身也是一条消息（[`Content::Recall`]），撤回目标同时写在明文的消息头里：
//! 服务器据此把同一个人发的原消息密文删掉，接收方解开后核对两处一致、且撤回的人就是原消息的发送者。

use serde::{Deserialize, Serialize};

use crate::bytes::{Bytes, Fixed};
use crate::crypto::{self, ctx};
use crate::error::{CoreError, Result};
use crate::file::FileRef;
use crate::ids::{ConvId, DeviceId, MsgId, Uid};
use crate::keys::{ConvSeed, DevicePublic, DeviceSecret};

/// 消息格式版本。
pub const MESSAGE_VERSION: u32 = 1;
/// 一条消息密文的上限（与服务器上限一致）：文字上限对齐 HHH 协议单块 64 KiB，再留出签名和格式的余量。
pub const ENVELOPE_CT_MAX: usize = 80 * 1024;
/// 一条消息里正文段数的上限。
pub const PARTS_MAX: usize = 256;
/// 个人资料里头像地址的上限（字节）。
pub const AVATAR_URL_MAX: usize = 1024;

/// 正文的一段，对应 HHH 协议的消息块（文字、提及、资源）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Part {
    /// 文字。
    Text {
        /// 原文。
        text: String,
    },
    /// @某人或 @所有人。
    Mention {
        /// 被 @ 的账号；@所有人时为空。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        uid: Option<Uid>,
        /// 发送时显示的名字。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// 是否 @所有人。
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        everyone: bool,
    },
    /// 图片。
    Image {
        /// 加密文件。
        file: FileRef,
        /// 宽（像素）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        width: Option<u32>,
        /// 高（像素）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        height: Option<u32>,
    },
    /// 文件。
    File {
        /// 加密文件。
        file: FileRef,
        /// 视频信息（发送方取的封面、时长与宽高，契约 friend/video-preview v3）；不是视频或没取到时没有。
        /// 旧版不认识这个字段，读到的还是一个文件。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        video: Option<VideoInfo>,
    },
}

/// 视频封面文件的上限（与宿主交来的视频封面同一上限，契约 hhh-im client v46）。
pub const COVER_MAX: u64 = 256 * 1024;

/// 视频文件附带的视频信息：封面是同一会话里另一个加密文件（服务器只看到多了一个文件），时长与宽高明文写在加了密的正文里。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoInfo {
    /// 封面图（JPEG、PNG 或 WebP，至多 [`COVER_MAX`] 字节）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cover: Option<FileRef>,
    /// 画面宽（像素）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    /// 画面高（像素）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    /// 时长（毫秒）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

impl VideoInfo {
    fn check(&self) -> Result<()> {
        if let Some(cover) = &self.cover {
            cover.check()?;
            if !matches!(cover.mime.as_str(), "image/jpeg" | "image/png" | "image/webp") || cover.size > COVER_MAX {
                return Err(CoreError::format("视频封面不对"));
            }
        }
        Ok(())
    }
}

/// 消息内容。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Content {
    /// 普通消息。
    Post {
        /// 正文。
        parts: Vec<Part>,
        /// 回复哪一条。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reply_to: Option<MsgId>,
    },
    /// 撤回自己的一条消息。
    Recall {
        /// 被撤回的消息。
        target: MsgId,
    },
    /// 发送人的个人资料：和普通消息一样只有会话里的人解得开，服务器看不出它是个人资料。不给人看，收到的一方按发送人
    /// 记最新的一份。头像两种写法：`photo` 是这个会话里的加密头像文件（契约 friend-im v6，头像用 HHH 自己的）；
    /// `avatar` 是旧版发的 Cindy 头像地址（第三阶段，新版只读不写）。都没有就是没有头像（把以前的撤掉）。
    Profile {
        /// 头像地址（https，至多 [`AVATAR_URL_MAX`] 字节）：旧版写的。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        avatar: Option<String>,
        /// 加密头像文件（PNG 或 JPEG，至多 [`PHOTO_MAX`] 字节）：新版写的。旧版不认识这个字段，读到的是“没有头像”。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        photo: Option<FileRef>,
    },
}

/// 个人资料里加密头像文件的上限（与宿主交来的头像同一上限，契约 provider-protocol v35）。
pub const PHOTO_MAX: u64 = 256 * 1024;

impl Content {
    fn check(&self) -> Result<()> {
        if let Self::Profile { avatar: Some(url), .. } = self
            && (!url.starts_with("https://") || url.len() > AVATAR_URL_MAX || url.chars().any(|c| c.is_whitespace() || c.is_control()))
        {
            return Err(CoreError::format("头像地址不对"));
        }
        if let Self::Profile { photo: Some(file), .. } = self {
            file.check()?;
            if !matches!(file.mime.as_str(), "image/png" | "image/jpeg") || file.size > PHOTO_MAX {
                return Err(CoreError::format("头像文件不对"));
            }
        }
        if let Self::Post { parts, .. } = self {
            if parts.is_empty() || parts.len() > PARTS_MAX {
                return Err(CoreError::format("消息正文段数不对"));
            }
            for part in parts {
                match part {
                    Part::Image { file, .. } | Part::File { file, video: None } => file.check()?,
                    Part::File { file, video: Some(video) } => {
                        file.check()?;
                        video.check()?;
                    }
                    Part::Mention { uid: None, everyone: false, .. } => {
                        return Err(CoreError::format("提及缺少对象"));
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

/// 消息正文（签名覆盖它的字节）。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageBody {
    /// 格式版本。
    pub v: u32,
    /// 发送时的本机时间（毫秒）。
    pub ctime_ms: i64,
    /// 内容。
    pub content: Content,
}

/// 消息信封：服务器存、转发的就是它。除 `ct` 以外都是明文的消息头。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// 会话。
    pub conv: ConvId,
    /// 消息编号。
    pub id: MsgId,
    /// 用哪一代会话钥匙加密的。
    pub generation: u32,
    /// 发送账号。
    pub sender: Uid,
    /// 发送账号当时的身份指纹。
    pub sender_eldest: Fixed<32>,
    /// 发送的电脑。
    pub device: DeviceId,
    /// 撤回消息的目标（只有撤回消息有）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recall: Option<MsgId>,
    /// 密文。
    pub ct: Bytes,
}

/// 加密一条消息需要的发送方信息。
pub struct Sender<'a> {
    /// 账号。
    pub uid: &'a Uid,
    /// 身份指纹。
    pub eldest: Fixed<32>,
    /// 这台电脑的私钥。
    pub device: &'a DeviceSecret,
}

fn header(conv: &ConvId, id: &MsgId, generation: u32, sender: &Uid, eldest: &Fixed<32>, device: &DeviceId, recall: Option<&MsgId>) -> Vec<u8> {
    crypto::frame(&[
        ctx::MESSAGE.as_bytes(),
        conv.as_str().as_bytes(),
        id.as_str().as_bytes(),
        &generation.to_be_bytes(),
        sender.as_str().as_bytes(),
        &eldest.0,
        device.as_str().as_bytes(),
        recall.map(MsgId::as_str).unwrap_or("").as_bytes(),
    ])
}

impl Envelope {
    /// 签名并加密一条消息。
    pub fn seal(conv: &ConvId, id: MsgId, generation: u32, seed: &ConvSeed, sender: &Sender<'_>, body: &MessageBody) -> Result<Self> {
        body.content.check()?;
        let recall = match &body.content {
            Content::Recall { target } => Some(target.clone()),
            Content::Post { .. } | Content::Profile { .. } => None,
        };
        let device = sender.device.id();
        let head = header(conv, &id, generation, sender.uid, &sender.eldest, &device, recall.as_ref());
        let body_bytes = serde_json::to_vec(body).map_err(|_| CoreError::format("消息写不出"))?;
        let sig = sender.device.sign(ctx::MESSAGE, &crypto::frame(&[&head, &body_bytes]));
        // 密文里是“64 字节签名 + 正文字节”，不再套一层 base64，文字上限才能对齐协议的 64 KiB。
        let mut inner = Vec::with_capacity(64 + body_bytes.len());
        inner.extend_from_slice(&sig.0);
        inner.extend_from_slice(&body_bytes);
        let ct = crypto::encrypt(&seed.message_key(), &head, &inner);
        if ct.len() > ENVELOPE_CT_MAX {
            return Err(CoreError::Limit("消息太大".into()));
        }
        Ok(Self {
            conv: conv.clone(),
            id,
            generation,
            sender: sender.uid.clone(),
            sender_eldest: sender.eldest,
            device,
            recall,
            ct: Bytes(ct),
        })
    }

    /// 解密并验签。`seed` 是第 `generation` 代会话钥匙，`device` 是发送电脑的公钥（调用方按发送账号的签名链查到、并确认当时有效）。
    pub fn open(&self, seed: &ConvSeed, device: &DevicePublic) -> Result<MessageBody> {
        if self.ct.len() > ENVELOPE_CT_MAX {
            return Err(CoreError::Limit("消息太大".into()));
        }
        if device.id() != self.device {
            return Err(CoreError::BadSignature);
        }
        let head = header(&self.conv, &self.id, self.generation, &self.sender, &self.sender_eldest, &self.device, self.recall.as_ref());
        let inner = crypto::decrypt(&seed.message_key(), &head, &self.ct.0)?;
        if inner.len() < 64 {
            return Err(CoreError::format("消息读不懂"));
        }
        let (sig, body_bytes) = inner.split_at(64);
        let sig = Fixed::<64>::from_slice(sig).ok_or_else(|| CoreError::format("消息读不懂"))?;
        device.verify(ctx::MESSAGE, &crypto::frame(&[&head, body_bytes]), &sig)?;
        let body: MessageBody = serde_json::from_slice(body_bytes).map_err(|_| CoreError::format("消息读不懂"))?;
        if body.v != MESSAGE_VERSION {
            return Err(CoreError::format("消息格式版本不认识"));
        }
        body.content.check()?;
        // 明文消息头里的撤回目标必须和加了密的正文一致。
        let inner_recall = match &body.content {
            Content::Recall { target } => Some(target),
            Content::Post { .. } | Content::Profile { .. } => None,
        };
        if inner_recall != self.recall.as_ref() {
            return Err(CoreError::format("撤回目标前后不一致"));
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::FileId;

    fn text(text: &str) -> MessageBody {
        MessageBody {
            v: MESSAGE_VERSION,
            ctime_ms: 1,
            content: Content::Post {
                parts: vec![Part::Text { text: text.into() }],
                reply_to: None,
            },
        }
    }

    fn sender_parts() -> (Uid, DeviceSecret) {
        (Uid::random(), DeviceSecret::generate())
    }

    #[test]
    fn seal_open_round_trip() {
        let (uid, device) = sender_parts();
        let conv = ConvId::random();
        let seed = ConvSeed::generate();
        let sender = Sender {
            uid: &uid,
            eldest: Fixed([1; 32]),
            device: &device,
        };
        let mut body = text("你好 @所有人");
        if let Content::Post { parts, .. } = &mut body.content {
            parts.push(Part::Mention {
                uid: None,
                name: None,
                everyone: true,
            });
            parts.push(Part::File {
                file: FileRef {
                    id: FileId::random(),
                    key: Fixed([3; 32]),
                    size: 10,
                    name: "a.txt".into(),
                    mime: "text/plain".into(),
                },
                video: None,
            });
        }
        let envelope = Envelope::seal(&conv, MsgId::random(), 1, &seed, &sender, &body).unwrap();
        assert_eq!(envelope.open(&seed, &device.public()).unwrap(), body);
        // 密文里找不到明文。
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(!json.contains("a.txt"));
    }

    #[test]
    fn other_member_cannot_forge_and_header_is_bound() {
        let (uid, device) = sender_parts();
        let conv = ConvId::random();
        let seed = ConvSeed::generate();
        let sender = Sender {
            uid: &uid,
            eldest: Fixed([1; 32]),
            device: &device,
        };
        let envelope = Envelope::seal(&conv, MsgId::random(), 1, &seed, &sender, &text("hi")).unwrap();
        // 同群的另一个成员有会话钥匙，用自己的电脑签、却冒称是 uid 发的。
        let mallory = DeviceSecret::generate();
        let forged_sender = Sender {
            uid: &uid,
            eldest: Fixed([1; 32]),
            device: &mallory,
        };
        let forged = Envelope::seal(&conv, MsgId::random(), 1, &seed, &forged_sender, &text("我是 uid")).unwrap();
        assert!(forged.open(&seed, &device.public()).is_err());
        // 服务器改消息头的任何一项都解不开。
        let mut moved = envelope.clone();
        moved.conv = ConvId::random();
        assert_eq!(moved.open(&seed, &device.public()), Err(CoreError::Decrypt));
        let mut renamed = envelope.clone();
        renamed.id = MsgId::random();
        assert_eq!(renamed.open(&seed, &device.public()), Err(CoreError::Decrypt));
        assert_eq!(envelope.open(&ConvSeed::generate(), &device.public()), Err(CoreError::Decrypt));
    }

    #[test]
    fn recall_target_must_match_header() {
        let (uid, device) = sender_parts();
        let conv = ConvId::random();
        let seed = ConvSeed::generate();
        let sender = Sender {
            uid: &uid,
            eldest: Fixed([1; 32]),
            device: &device,
        };
        let target = MsgId::random();
        let body = MessageBody {
            v: MESSAGE_VERSION,
            ctime_ms: 2,
            content: Content::Recall { target: target.clone() },
        };
        let envelope = Envelope::seal(&conv, MsgId::random(), 1, &seed, &sender, &body).unwrap();
        assert_eq!(envelope.recall, Some(target));
        assert!(envelope.open(&seed, &device.public()).is_ok());
        let mut swapped = envelope.clone();
        swapped.recall = Some(MsgId::random());
        assert!(swapped.open(&seed, &device.public()).is_err());
    }

    #[test]
    fn empty_or_oversized_messages_are_rejected() {
        let (uid, device) = sender_parts();
        let seed = ConvSeed::generate();
        let sender = Sender {
            uid: &uid,
            eldest: Fixed([1; 32]),
            device: &device,
        };
        let empty = MessageBody {
            v: MESSAGE_VERSION,
            ctime_ms: 1,
            content: Content::Post {
                parts: vec![],
                reply_to: None,
            },
        };
        assert!(Envelope::seal(&ConvId::random(), MsgId::random(), 1, &seed, &sender, &empty).is_err());
        let huge = text(&"字".repeat(40 * 1024));
        assert!(matches!(
            Envelope::seal(&ConvId::random(), MsgId::random(), 1, &seed, &sender, &huge),
            Err(CoreError::Limit(_))
        ));
        let max_text = text(&"a".repeat(64 * 1024));
        assert!(Envelope::seal(&ConvId::random(), MsgId::random(), 1, &seed, &sender, &max_text).is_ok());
    }

    // 第三阶段：个人资料和普通消息一样加密、签名；密文里找不到头像地址；头像地址只收 https、不太长；写法固定。
    #[test]
    fn a_profile_is_sealed_like_a_message_and_its_avatar_is_checked() {
        let (uid, device) = sender_parts();
        let conv = ConvId::random();
        let seed = ConvSeed::generate();
        let sender = Sender {
            uid: &uid,
            eldest: Fixed([1; 32]),
            device: &device,
        };
        let url = "https://avatar.example.com/u/abc.png";
        let body = MessageBody { v: MESSAGE_VERSION, ctime_ms: 1, content: Content::Profile { avatar: Some(url.into()), photo: None } };
        let envelope = Envelope::seal(&conv, MsgId::random(), 1, &seed, &sender, &body).unwrap();
        assert_eq!(envelope.open(&seed, &device.public()).unwrap(), body);
        assert!(!serde_json::to_string(&envelope).unwrap().contains("avatar.example.com"), "服务器看不到头像地址");
        assert_eq!(serde_json::to_value(&body.content).unwrap(), serde_json::json!({ "type": "profile", "avatar": url }));
        let cleared = Content::Profile { avatar: None, photo: None };
        assert_eq!(serde_json::to_value(&cleared).unwrap(), serde_json::json!({ "type": "profile" }));
        for bad in ["http://avatar.example.com/a.png".to_owned(), format!("https://a.com/{}", "x".repeat(AVATAR_URL_MAX)), "https://a.com/a b".into()] {
            let body = MessageBody { v: MESSAGE_VERSION, ctime_ms: 1, content: Content::Profile { avatar: Some(bad.clone()), photo: None } };
            assert!(Envelope::seal(&conv, MsgId::random(), 1, &seed, &sender, &body).is_err(), "{bad}");
        }
    }

    fn video_part(cover: Option<FileRef>) -> Part {
        Part::File {
            file: FileRef { id: FileId::random(), key: Fixed([5; 32]), size: 9_000_000, name: "clip.mp4".into(), mime: "video/mp4".into() },
            video: Some(VideoInfo { cover, width: Some(1080), height: Some(1920), duration_ms: Some(3400) }),
        }
    }

    // 契约 friend/video-preview v3：视频文件带封面与视频信息，照样加密签名、密文里找不到封面编号；旧版（只认 file 的写法）
    // 读到的还是一个文件，不会解析失败；封面只收 JPEG / PNG / WebP、不超过 COVER_MAX；旧消息照读。
    #[test]
    fn a_video_file_carries_an_encrypted_cover_and_old_readers_see_a_file() {
        let (uid, device) = sender_parts();
        let conv = ConvId::random();
        let seed = ConvSeed::generate();
        let sender = Sender { uid: &uid, eldest: Fixed([1; 32]), device: &device };
        let cover = FileRef { id: FileId::random(), key: Fixed([6; 32]), size: 40_000, name: "cover.jpg".into(), mime: "image/jpeg".into() };
        let post = |part: Part| MessageBody { v: MESSAGE_VERSION, ctime_ms: 1, content: Content::Post { parts: vec![part], reply_to: None } };
        let body = post(video_part(Some(cover.clone())));
        let envelope = Envelope::seal(&conv, MsgId::random(), 1, &seed, &sender, &body).unwrap();
        assert_eq!(envelope.open(&seed, &device.public()).unwrap(), body);
        assert!(!serde_json::to_string(&envelope).unwrap().contains(cover.id.as_str()), "服务器看不到封面文件");

        // 旧版的正文段只有 file：读新版写的视频不报错，还是一个文件。
        #[derive(Deserialize, Debug)]
        #[serde(tag = "type", rename_all = "snake_case")]
        enum OldPart {
            File { file: FileRef },
        }
        let Content::Post { parts, .. } = &body.content else { unreachable!() };
        let old: OldPart = serde_json::from_value(serde_json::to_value(&parts[0]).unwrap()).unwrap();
        assert!(matches!(&old, OldPart::File { file } if file.name == "clip.mp4"), "{old:?}");
        // 旧消息（没有 video）照读，写回不多出键。
        let plain = serde_json::json!({ "type": "file", "file": serde_json::to_value(&cover).unwrap() });
        let read: Part = serde_json::from_value(plain.clone()).unwrap();
        assert!(matches!(&read, Part::File { video: None, .. }));
        assert_eq!(serde_json::to_value(&read).unwrap(), plain);
        // 只有时长、宽高也行。
        assert!(Envelope::seal(&conv, MsgId::random(), 1, &seed, &sender, &post(video_part(None))).is_ok());

        for bad in [
            FileRef { mime: "image/gif".into(), ..cover.clone() },
            FileRef { size: COVER_MAX + 1, ..cover.clone() },
        ] {
            assert!(Envelope::seal(&conv, MsgId::random(), 1, &seed, &sender, &post(video_part(Some(bad)))).is_err());
        }
    }

    fn photo(mime: &str, size: u64) -> FileRef {
        FileRef { id: crate::ids::FileId::random(), key: Fixed([7; 32]), size, name: "avatar.png".into(), mime: mime.into() }
    }

    // 契约 friend-im v6：个人资料带加密头像文件，照样加密签名、密文里找不到文件钥匙；旧版（只认 avatar 的写法）读到的是
    // “没有头像”，不会解析失败变成解不开的消息；头像只收 PNG / JPEG、不超过 PHOTO_MAX。
    #[test]
    fn a_profile_carries_an_encrypted_photo_and_old_readers_see_no_avatar() {
        let (uid, device) = sender_parts();
        let conv = ConvId::random();
        let seed = ConvSeed::generate();
        let sender = Sender { uid: &uid, eldest: Fixed([1; 32]), device: &device };
        let file = photo("image/png", 40_000);
        let body = MessageBody { v: MESSAGE_VERSION, ctime_ms: 1, content: Content::Profile { avatar: None, photo: Some(file.clone()) } };
        let envelope = Envelope::seal(&conv, MsgId::random(), 1, &seed, &sender, &body).unwrap();
        assert_eq!(envelope.open(&seed, &device.public()).unwrap(), body);
        assert!(!serde_json::to_string(&envelope).unwrap().contains(file.id.as_str()), "服务器看不到头像文件");

        // 旧版的内容类型只有 avatar：读新版写的个人资料不报错，头像为空。
        #[derive(Deserialize, Debug)]
        #[serde(tag = "type", rename_all = "snake_case")]
        enum OldContent {
            Profile {
                #[serde(default)]
                avatar: Option<String>,
            },
        }
        let wire = serde_json::to_value(&body.content).unwrap();
        let old: OldContent = serde_json::from_value(wire).unwrap();
        assert!(matches!(old, OldContent::Profile { avatar: None }), "{old:?}");

        for bad in [photo("image/gif", 10), photo("image/png", PHOTO_MAX + 1)] {
            let body = MessageBody { v: MESSAGE_VERSION, ctime_ms: 1, content: Content::Profile { avatar: None, photo: Some(bad) } };
            assert!(Envelope::seal(&conv, MsgId::random(), 1, &seed, &sender, &body).is_err());
        }
    }
}
