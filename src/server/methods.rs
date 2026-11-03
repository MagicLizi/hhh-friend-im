//! 读取与动作（protocol-v1 §8、§10）：会话、成员、名字、发消息、撤回。消息历史不在这里读：平台是 `history = none`，
//! 消息由设备对账补齐后推给宿主（[`super::devices`]）。
//!
//! - 发消息一条一条发。消息编号由账号与 `operationId` 算出来：同一次发送重试还是同一条，所有设备按编号去重。
//!   本机宿主保存成功就算发出，对方不在线时等对账送达。

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use friend_im_client::core::bytes::Fixed;
use friend_im_client::core::crypto;
use friend_im_client::core::file::FileRef;
use friend_im_client::core::ids::{ConvId, FileId, MsgId, Uid};
use friend_im_client::core::message::{COVER_MAX, Content, Part, VideoInfo};
use friend_im_client::core::sync::{Key, read_position};
use hhh_im_protocol::method::{
    ConversationsGetParams, ConversationsListParams, MembersParams, MessagesLookupSendParams,
    MessagesRecallParams, MessagesSendParams, Page, PeopleGetParams, PeopleGetResult,
};
use hhh_im_protocol::rpc::{ErrorKind, RpcError};
use hhh_im_protocol::types::{OutgoingVideo, Person, PersonKind, SendOutcome, SendTarget};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use super::translate::{self, Piece};
use super::{Server, errors};

/// 记住多少次发送的结果（同一个 `operationId` 再来时回同一个结果）。
const SENDS_MAX: usize = 1000;

type SendResult = Result<Value, RpcError>;

/// 发过和正在发的消息：操作编号 → 结果。
#[derive(Default)]
pub(crate) struct Sends {
    slots: Mutex<VecDeque<(String, watch::Receiver<Option<SendResult>>)>>,
    /// 一条发完再发下一条（个人资料也排在这里）。
    pub(crate) gate: tokio::sync::Mutex<()>,
}

impl Sends {
    fn find(&self, operation: &str) -> Option<watch::Receiver<Option<SendResult>>> {
        self.slots
            .lock()
            .expect("发送记录锁中毒")
            .iter()
            .find(|(id, _)| id == operation)
            .map(|(_, rx)| rx.clone())
    }

    /// 这次发送的结果槽；第一次见到这个编号时另外给出写结果的那一头（由调用方去发）。
    fn slot(
        &self,
        operation: &str,
    ) -> (
        watch::Receiver<Option<SendResult>>,
        Option<watch::Sender<Option<SendResult>>>,
    ) {
        let mut slots = self.slots.lock().expect("发送记录锁中毒");
        if let Some(at) = slots.iter().position(|(id, _)| id == operation) {
            // 确定没发出去的（结果是错误）可以用同一个编号再发一次：宿主重试沿用操作编号。
            if !matches!(&*slots[at].1.borrow(), Some(Err(_))) {
                return (slots[at].1.clone(), None);
            }
            slots.remove(at);
        }
        let (tx, rx) = watch::channel(None);
        slots.push_back((operation.to_owned(), rx.clone()));
        if slots.len() > SENDS_MAX {
            slots.pop_front();
        }
        (rx, Some(tx))
    }
}

pub(crate) fn params<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, RpcError> {
    serde_json::from_value(value).map_err(errors::invalid_params)
}

fn to_value(value: impl serde::Serialize) -> Value {
    serde_json::to_value(value).expect("结果总能写成 JSON")
}

fn conv_id(text: &str) -> Result<ConvId, RpcError> {
    ConvId::parse(text).map_err(|_| errors::of(ErrorKind::NotFound, "没有这个会话。"))
}

fn msg_id(text: &str) -> Result<MsgId, RpcError> {
    MsgId::parse(text).map_err(|_| errors::of(ErrorKind::NotFound, "没有这条消息。"))
}

/// 按偏移翻页的游标：`o<偏移>`。
fn offset_of(cursor: Option<&str>) -> Result<usize, RpcError> {
    match cursor {
        None => Ok(0),
        Some(text) => text
            .strip_prefix('o')
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| errors::of(ErrorKind::InvalidRequest, "翻页游标不对。")),
    }
}

/// 一页的切法：从 `offset` 起取 `limit` 个，还有就给下一页的游标。
fn slice<T>(all: Vec<T>, offset: usize, limit: u16) -> Page<T> {
    let limit = usize::from(limit.max(1));
    let total = all.len();
    let items: Vec<T> = all.into_iter().skip(offset).take(limit).collect();
    let next = (offset + items.len() < total).then(|| format!("o{}", offset + items.len()));
    Page { items, next }
}

/// 消息编号：由账号与操作编号算出来（同一次发送重试还是同一个编号）。
pub(crate) fn send_id(me: &Uid, operation: &str) -> MsgId {
    let digest = Sha256::new()
        .chain_update(b"friend-im/send/v1\0")
        .chain_update(me.as_str())
        .chain_update(b"\0")
        .chain_update(operation)
        .finalize();
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&digest[..16]);
    MsgId::from_raw(raw)
}

/// 读暂存文件的开头（认类型用）与图片宽高；读不了是空的。
fn head_of(path: &std::path::Path) -> (Vec<u8>, Option<imagesize::ImageSize>) {
    use std::io::Read as _;
    let mut head = vec![0u8; 64 * 1024];
    let n = std::fs::File::open(path)
        .and_then(|mut f| f.read(&mut head))
        .unwrap_or(0);
    head.truncate(n);
    (head, imagesize::size(path).ok())
}

#[cfg(not(target_os = "wasi"))]
async fn read_head(path: std::path::PathBuf) -> (Vec<u8>, Option<imagesize::ImageSize>) {
    tokio::task::spawn_blocking(move || head_of(&path))
        .await
        .unwrap_or_default()
}

/// WASI 构建没有后台线程：就地读（只读文件头）。
#[cfg(target_os = "wasi")]
async fn read_head(path: std::path::PathBuf) -> (Vec<u8>, Option<imagesize::ImageSize>) {
    head_of(&path)
}

fn mime_of(name: &str, image: bool, head: &[u8]) -> String {
    if image && let Ok(kind) = imagesize::image_type(head) {
        let known = match kind {
            imagesize::ImageType::Png => Some("image/png"),
            imagesize::ImageType::Jpeg => Some("image/jpeg"),
            imagesize::ImageType::Gif => Some("image/gif"),
            imagesize::ImageType::Webp => Some("image/webp"),
            imagesize::ImageType::Bmp => Some("image/bmp"),
            _ => None,
        };
        if let Some(mime) = known {
            return mime.into();
        }
    }
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "txt" | "md" | "log" => "text/plain",
        "zip" => "application/zip",
        "mp4" => "video/mp4",
        "mp3" | "mp2" => "audio/mpeg",
        "wav" | "wave" => "audio/wav",
        "m4a" | "m4b" => "audio/mp4",
        "aac" => "audio/aac",
        "ogg" | "oga" | "opus" => "audio/ogg",
        "flac" => "audio/flac",
        "amr" => "audio/amr",
        "awb" => "audio/amr-wb",
        "aif" | "aiff" => "audio/aiff",
        "wma" => "audio/x-ms-wma",
        _ => "application/octet-stream",
    }
    .into()
}

impl Server {
    /// `conversations/list`：自己现在所在的会话，按最近有动静的排。
    pub(crate) async fn conversations_list(
        &self,
        params: ConversationsListParams,
    ) -> Result<Value, RpcError> {
        let live = self.live().await?;
        let offset = offset_of(params.cursor.as_deref())?;
        let summaries = live.client.convs().await.map_err(|e| errors::client(&e))?;
        // 重置过账号后退出的群不再列（契约 S7）。
        let left = live
            .client
            .groups_left_by_reset()
            .await
            .map_err(|e| errors::client(&e))?;
        let ids: Vec<ConvId> = summaries
            .into_iter()
            .filter(|s| s.member && !left.contains(&s.conv))
            .map(|s| s.conv)
            .collect();
        let page = slice(ids, offset, params.limit.min(100));
        let mut items = Vec::with_capacity(page.items.len());
        for conv in &page.items {
            match live.conversation(conv).await {
                Ok(conversation) => items.push(conversation),
                Err(error) => tracing::info!(%conv, %error, "会话资料取不到，这次列表里先不放"),
            }
        }
        Ok(to_value(Page {
            items,
            next: page.next,
        }))
    }

    /// `conversations/get`。
    pub(crate) async fn conversations_get(
        &self,
        params: ConversationsGetParams,
    ) -> Result<Value, RpcError> {
        let live = self.live().await?;
        let conv = conv_id(&params.conversation_id)?;
        live.conversation(&conv)
            .await
            .map(to_value)
            .map_err(|e| errors::client(&e))
    }

    /// `conversations/members`：会话现在的成员。
    pub(crate) async fn conversations_members(
        &self,
        params: MembersParams,
    ) -> Result<Value, RpcError> {
        let live = self.live().await?;
        let conv = conv_id(&params.conversation_id)?;
        let offset = offset_of(params.cursor.as_deref())?;
        let info = live
            .client
            .conv_info(&conv)
            .await
            .map_err(|e| errors::client(&e))?;
        let page = slice(
            info.members.into_iter().map(|m| m.uid).collect(),
            offset,
            params.limit,
        );
        let names = live.names(page.items.iter().cloned()).await;
        let items: Vec<Person> = page
            .items
            .iter()
            .map(|u| Person {
                id: u.to_string(),
                id_type: None,
                kind: PersonKind::User,
                name: names.get(u).cloned(),
                avatar: live.avatar_of(u),
            })
            .collect();
        Ok(to_value(Page {
            items,
            next: page.next,
        }))
    }

    /// `people/get`：账号的名字。编号格式不对、服务器上没有的放进 `missing`。
    pub(crate) async fn people_get(&self, params: PeopleGetParams) -> Result<Value, RpcError> {
        let live = self.live().await?;
        let mut missing = Vec::new();
        let mut uids = Vec::new();
        for id in params.ids.iter().take(100) {
            match Uid::parse(id) {
                Ok(uid) => uids.push(uid),
                Err(_) => missing.push(id.clone()),
            }
        }
        let profiles = live
            .client
            .profiles(&uids)
            .await
            .map_err(|e| errors::client(&e))?;
        let found: Vec<Person> = profiles
            .iter()
            .map(|p| Person {
                id: p.uid.to_string(),
                id_type: None,
                kind: PersonKind::User,
                name: Some(p.name.clone()),
                avatar: live.avatar_of(&p.uid),
            })
            .collect();
        missing.extend(
            uids.iter()
                .filter(|u| !profiles.iter().any(|p| &p.uid == *u))
                .map(ToString::to_string),
        );
        Ok(to_value(PeopleGetResult { found, missing }))
    }

    /// `messages/send`：同一个操作编号只发一次；60 秒内没发完先回“不确定”。
    pub(crate) async fn messages_send(
        self: &Arc<Self>,
        params: MessagesSendParams,
    ) -> Result<Value, RpcError> {
        let (mut rx, tx) = self.sends.slot(&params.operation_id);
        if let Some(tx) = tx {
            let server = self.clone();
            tokio::spawn(async move {
                let result = server.send_now(params).await;
                let _ = tx.send(Some(result));
            });
        }
        self.wait_send(&mut rx).await
    }

    /// `messages/lookupSend`：这次发送的结果（还在发就再等一会儿）。
    pub(crate) async fn messages_lookup_send(
        &self,
        params: MessagesLookupSendParams,
    ) -> Result<Value, RpcError> {
        let Some(mut rx) = self.sends.find(&params.operation_id) else {
            return Err(errors::of(
                ErrorKind::NotFound,
                "没有这次发送的记录（插件重启过）。",
            ));
        };
        self.wait_send(&mut rx).await
    }

    async fn wait_send(
        &self,
        rx: &mut watch::Receiver<Option<SendResult>>,
    ) -> Result<Value, RpcError> {
        match tokio::time::timeout(self.options.send_wait, rx.wait_for(Option::is_some)).await {
            Ok(Ok(result)) => result.clone().expect("等到的结果一定有值"),
            Ok(Err(_)) => Ok(to_value(SendOutcome::Unknown {
                reason: "发送中途插件出了问题，不知道发出去没有。".into(),
            })),
            Err(_) => Ok(to_value(SendOutcome::Unknown {
                reason: "附件还在上传，发完后在发送记录里能看到结果。".into(),
            })),
        }
    }

    /// 真的发：附件换成文件引用，再一条一条发。本机宿主没保存成功才算失败（宿主记成“没有发出去”、能重试）。
    async fn send_now(&self, params: MessagesSendParams) -> SendResult {
        let live = self.live().await?;
        let (conv, reply_to) = match &params.target {
            SendTarget::Conversation { conversation_id } => (conv_id(conversation_id)?, None),
            SendTarget::Reply {
                conversation_id,
                message_id,
                ..
            } => (conv_id(conversation_id)?, Some(msg_id(message_id)?)),
        };
        let pieces = translate::pieces(&params.content)
            .map_err(|m| errors::of(ErrorKind::InvalidRequest, m))?;
        if pieces.is_empty() {
            return Err(errors::of(ErrorKind::InvalidRequest, "消息是空的。"));
        }
        let mut parts = Vec::with_capacity(pieces.len());
        let mut used = Vec::new();
        for piece in pieces {
            match piece {
                Piece::Part(part) => parts.push(part),
                Piece::Attachment { key, image, video } => {
                    parts.push(self.attachment_part(&key, image, video.as_ref()).await?);
                    used.push(key);
                    // 封面带没带上，发出去后暂存都不要了。
                    used.extend(video.and_then(|v| v.cover));
                }
            }
        }
        let content = Content::Post {
            parts: parts.clone(),
            reply_to: reply_to.clone(),
        };
        let id = send_id(&live.me, &params.operation_id);
        let sent = {
            let _turn = self.sends.gate.lock().await;
            live.devices.send(&conv, &id, content).await
        };
        let at = sent.map_err(|error| {
            tracing::info!(%conv, %error, "发送没成");
            errors::client(&error)
        })?;
        for key in used {
            self.uploads.done(&key).await;
        }
        let mut uids = vec![live.me.clone()];
        uids.extend(parts.iter().filter_map(|p| match p {
            Part::Mention { uid: Some(uid), .. } => Some(uid.clone()),
            _ => None,
        }));
        let names = live.names(uids).await;
        let mut message = translate::posted(
            conv.as_str(),
            &id,
            &live.me,
            at,
            &parts,
            reply_to.as_ref(),
            &names,
        );
        message.read_position = Some(read_position(&Key { at, id }));
        Ok(to_value(SendOutcome::Accepted {
            message: Box::new(message),
        }))
    }

    /// 暂存的附件：读宽高（图片），换成消息正文里的一段。文件本身不离开这台设备：宿主发送成功后存进文件库，
    /// 别的设备要时从这里取。内容摘要写进文件引用、随消息签名。视频文件带宿主给的视频信息时封面也一样（契约
    /// friend/video-preview v3）；封面有问题这条照常发，只是不带封面。
    async fn attachment_part(
        &self,
        key: &str,
        image: bool,
        video: Option<&OutgoingVideo>,
    ) -> Result<Part, RpcError> {
        let attachment = self
            .uploads
            .attachment(key)
            .await
            .ok_or_else(|| errors::of(ErrorKind::NotFound, "附件已经过期，要重新上传。"))?;
        let (head, size) = read_head(attachment.path.clone()).await;
        let image = image || attachment.image;
        let mime = mime_of(&attachment.name, image, &head);
        let file = file_ref(attachment.bytes, &attachment.name, &mime, attachment.sha256);
        if image {
            return Ok(Part::Image {
                file,
                width: size.map(|s| s.width as u32),
                height: size.map(|s| s.height as u32),
            });
        }
        let video = match video {
            Some(video) => {
                let cover = match &video.cover {
                    Some(cover) => self.cover_ref(cover).await,
                    None => None,
                };
                Some(VideoInfo {
                    cover,
                    width: video.width,
                    height: video.height,
                    duration_ms: video.duration_ms,
                })
                .filter(|v| v != &VideoInfo::default())
            }
            None => None,
        };
        Ok(Part::File { file, video })
    }

    /// 视频封面：要是暂存好的 JPEG、PNG 或 WebP、不超过 [`COVER_MAX`]。宿主不保存发出去的封面，字节留在内存里给别的设备。
    /// 哪一步不行都只记一笔、不带封面（封面只是锦上添花，不让视频发不出去）。
    async fn cover_ref(&self, key: &str) -> Option<FileRef> {
        let Some(attachment) = self.uploads.attachment(key).await else {
            tracing::warn!("视频封面的暂存找不到，这条不带封面");
            return None;
        };
        if attachment.bytes > COVER_MAX {
            tracing::warn!(bytes = attachment.bytes, "视频封面太大，这条不带封面");
            return None;
        }
        let (head, _) = read_head(attachment.path.clone()).await;
        let mime = match imagesize::image_type(&head) {
            Ok(imagesize::ImageType::Jpeg) => "image/jpeg",
            Ok(imagesize::ImageType::Png) => "image/png",
            Ok(imagesize::ImageType::Webp) => "image/webp",
            _ => {
                tracing::warn!("视频封面不是 JPEG、PNG 或 WebP，这条不带封面");
                return None;
            }
        };
        let bytes = match std::fs::read(&attachment.path) {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(%error, "打不开暂存的视频封面，这条不带封面");
                return None;
            }
        };
        let file = file_ref(attachment.bytes, &attachment.name, mime, attachment.sha256);
        self.avatars.remember(&translate::resource_key(&file), Arc::new(bytes));
        Some(file)
    }

    /// `messages/recall`：撤回自己的一条（所有设备上的原文随之换成墓碑）。
    pub(crate) async fn messages_recall(
        &self,
        params: MessagesRecallParams,
    ) -> Result<Value, RpcError> {
        let live = self.live().await?;
        let conv = conv_id(&params.conversation_id)?;
        let target = msg_id(&params.message_id)?;
        let _turn = self.sends.gate.lock().await;
        live.devices
            .recall(&conv, &target)
            .await
            .map_err(|error| {
                tracing::info!(%conv, %error, "撤回没成");
                errors::client(&error)
            })?;
        Ok(serde_json::json!({}))
    }
}

/// 一个新文件的引用：编号和随机值由这台设备取。
fn file_ref(size: u64, name: &str, mime: &str, sha256: [u8; 32]) -> FileRef {
    FileRef {
        id: FileId::random(),
        key: Fixed(crypto::random()),
        size,
        name: name.to_owned(),
        mime: mime.to_owned(),
        sha256: Some(Fixed(sha256)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn send_ids_are_stable_per_account_and_operation() {
        let me = Uid::from_raw([1; 16]);
        assert_eq!(send_id(&me, "op-1"), send_id(&me, "op-1"));
        assert_ne!(send_id(&me, "op-1"), send_id(&me, "op-2"));
        assert_ne!(
            send_id(&me, "op-1"),
            send_id(&Uid::from_raw([2; 16]), "op-1")
        );
    }

    #[test]
    fn offset_pages_and_cursors() {
        let page = slice((0..5).collect::<Vec<_>>(), 0, 2);
        assert_eq!((page.items, page.next.as_deref()), (vec![0, 1], Some("o2")));
        let page = slice(
            (0..5).collect::<Vec<_>>(),
            offset_of(Some("o4")).unwrap(),
            2,
        );
        assert_eq!((page.items, page.next), (vec![4], None));
        assert!(offset_of(Some("x")).is_err());
    }

    #[test]
    fn mime_types_from_content_or_name() {
        let png = [
            0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, b'I', b'H', b'D', b'R', 0,
            0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0,
        ];
        assert_eq!(mime_of("x.bin", true, &png), "image/png");
        assert_eq!(mime_of("报告.PDF", false, &[]), "application/pdf");
        for (name, mime) in [
            ("讨论.M4A", "audio/mp4"),
            ("音乐.FLAC", "audio/flac"),
            ("录音.OPUS", "audio/ogg"),
            ("旧语音.amr", "audio/amr"),
        ] {
            assert_eq!(mime_of(name, false, &[]), mime);
        }
        assert_eq!(mime_of("无后缀", false, &[]), "application/octet-stream");
    }
}
