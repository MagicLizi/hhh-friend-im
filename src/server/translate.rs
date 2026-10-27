//! 客户端库的格式 ↔ 协议的格式（protocol-v1 §7）。这里全是不联网的纯函数，单元测试直接覆盖。
//!
//! 编号的写法：
//! - 会话、账号（人）、消息：客户端库的编号原样（22 个字符的 base64url）。
//! - 系统提示：`n-<日志序号>`（来自会话签名链，一条变化一条提示）；签名链核对不通过的提醒：`r-<日志序号>`。
//! - 资源键：`f1.<文件编号>.<文件钥匙>.<字节数>`（约 80 字节，只在这条消息里有意义）。HHH 读资源时插件凭它向服务器
//!   取密文、在本机解开。文件钥匙在 HHH 本机的库里，和已经解开的消息同一处，服务器上没有。
//! - 翻页游标：`b<日志序号>`，下一页取比它早的。

use std::collections::HashMap;

use friend_im_client::core::bytes::{self, Fixed};
use friend_im_client::core::conv::{ConvKind, RemoveReason, Via};
use friend_im_client::core::file::FileRef;
use friend_im_client::core::ids::{FileId, MsgId, Uid};
use friend_im_client::core::message::{Content, Part};
use friend_im_client::{ConvNotice, HistoryItem, Message, Notice};
use hhh_im_protocol::types::{
    Block, Message as Wire, Outgoing, PersonKind, Resource, ResourceKind, Sender, SenderKind,
};

/// 账号编号 → 名字（只用来显示；没有的写“有人”）。
pub(crate) type Names = HashMap<Uid, String>;

/// 资源键的前缀（格式第 1 版）。
const KEY_PREFIX: &str = "f1";

/// 文件引用 → 资源键。
pub(crate) fn resource_key(file: &FileRef) -> String {
    format!(
        "{KEY_PREFIX}.{}.{}.{}",
        file.id,
        bytes::encode(&file.key.0),
        file.size
    )
}

/// 资源键 → 读文件用的引用（文件名与类型读的时候用不到，留空）。格式不对为 `None`。
pub(crate) fn file_of_key(key: &str) -> Option<FileRef> {
    let mut parts = key.split('.');
    let (Some(KEY_PREFIX), Some(id), Some(secret), Some(size), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return None;
    };
    let secret: [u8; 32] = bytes::decode(secret)?.try_into().ok()?;
    Some(FileRef {
        id: FileId::parse(id).ok()?,
        key: Fixed(secret),
        size: size
            .parse()
            .ok()
            .filter(|s| *s <= friend_im_client::core::limits::FILE_PLAIN_MAX)?,
        name: String::new(),
        mime: String::new(),
    })
}

/// 翻页游标：下一页取日志序号比它小的。
pub(crate) fn cursor(log: u64) -> String {
    format!("b{log}")
}

/// 读回翻页游标；格式不对为 `None`。
pub(crate) fn parse_cursor(text: &str) -> Option<u64> {
    text.strip_prefix('b')?.parse().ok()
}

fn name_of(names: &Names, uid: &Uid) -> String {
    names.get(uid).cloned().unwrap_or_else(|| "有人".to_owned())
}

/// 消息正文的一段 → 协议的内容块。
fn block(part: &Part, names: &Names) -> Block {
    match part {
        Part::Text { text } => Block::Text { text: text.clone() },
        Part::Mention {
            uid,
            name,
            everyone,
        } => Block::Mention {
            user_id: uid.as_ref().map(ToString::to_string),
            id_type: None,
            kind: uid.as_ref().map(|_| PersonKind::User),
            name: name
                .clone()
                .or_else(|| uid.as_ref().and_then(|u| names.get(u).cloned())),
            everyone: *everyone,
        },
        Part::Image {
            file,
            width,
            height,
        } => Block::Resource {
            resource: resource(file, ResourceKind::Image),
            name: Some(file.name.clone()),
            width: *width,
            height: *height,
        },
        Part::File { file } => Block::Resource {
            resource: resource(file, ResourceKind::File),
            name: Some(file.name.clone()),
            width: None,
            height: None,
        },
    }
}

fn resource(file: &FileRef, kind: ResourceKind) -> Resource {
    Resource {
        key: resource_key(file),
        kind,
        mime: (!file.mime.is_empty()).then(|| file.mime.clone()),
        bytes: Some(file.size),
        duration_ms: None,
        cover: None,
    }
}

fn wire(id: String, conv: String, sender: Sender, created_at_ms: i64, content: Vec<Block>) -> Wire {
    Wire {
        id,
        conversation_id: conv,
        sender,
        created_at_ms,
        updated_at_ms: None,
        edited_at_ms: None,
        deleted: false,
        incomplete: false,
        content,
        reply_to: None,
        thread: None,
        reactions: None,
        raw: None,
        edit_draft: None,
        agent_attribution: None,
    }
}

fn user(uid: &Uid, names: &Names) -> Sender {
    Sender {
        id: uid.to_string(),
        id_type: None,
        kind: SenderKind::User,
        name: names.get(uid).cloned(),
    }
}

fn system() -> Sender {
    Sender {
        id: String::new(),
        id_type: None,
        kind: SenderKind::System,
        name: None,
    }
}

/// 一条解开的消息 → 协议的消息。撤回动作本身（`Content::Recall`）与个人资料（`Content::Profile`）不是给人看的消息，
/// 为 `None`：被撤回的那条由 [`recalled`] 另外报，个人资料只记下头像。时间用服务器收到的时间（和按时间读历史同一把尺子）。
pub(crate) fn message(m: &Message, names: &Names) -> Option<Wire> {
    match &m.content {
        None => Some(recalled(m.conv.as_str(), &m.id, &m.sender, m.ts_ms, names)),
        Some(Content::Recall { .. } | Content::Profile { .. }) => None,
        Some(Content::Post { parts, reply_to }) => Some(posted(
            m.conv.as_str(),
            &m.id,
            &m.sender,
            m.ts_ms,
            parts,
            reply_to.as_ref(),
            names,
        )),
    }
}

/// 一条普通消息（收到的，或刚发出去的）。
pub(crate) fn posted(
    conv: &str,
    id: &MsgId,
    sender: &Uid,
    ts_ms: i64,
    parts: &[Part],
    reply_to: Option<&MsgId>,
    names: &Names,
) -> Wire {
    let mut out = wire(
        id.to_string(),
        conv.to_owned(),
        user(sender, names),
        ts_ms,
        parts.iter().map(|p| block(p, names)).collect(),
    );
    out.reply_to = reply_to.map(ToString::to_string);
    out
}

/// 被撤回的一条（撤回推来时）：内容为空、`deleted` 为真，时间与发送人照原来那条。
pub(crate) fn recalled(conv: &str, id: &MsgId, sender: &Uid, ts_ms: i64, names: &Names) -> Wire {
    let mut out = wire(
        id.to_string(),
        conv.to_owned(),
        user(sender, names),
        ts_ms,
        Vec::new(),
    );
    out.deleted = true;
    out
}

/// 解不开或验不过的一条：放在原来的位置，写明为什么看不到，整条标“不完整”。
pub(crate) fn unreadable(conv: &str, id: &MsgId, sender: &Uid, ts_ms: i64, names: &Names) -> Wire {
    let content = vec![Block::Unsupported {
        kind: "friend-im-unreadable".into(),
        label: Some(
            "这条消息解不开：可能是对方重置账号之前发的，或服务器给的内容没通过核对。".into(),
        ),
    }];
    let mut out = wire(
        id.to_string(),
        conv.to_owned(),
        user(sender, names),
        ts_ms,
        content,
    );
    out.incomplete = true;
    out
}

/// 系统提示的文字（契约 S9、S11、S13、S16）。换钥匙、群邀请链接的发出与作废不用给人看，为 `None`。`me` 是这台电脑
/// 登录的账号：重置账号的提示给本人看时说“你重置了账号”，不叫自己去核对自己。
pub(crate) fn notice_text(notice: &Notice, names: &Names, me: &Uid) -> Option<String> {
    let author = name_of(names, &notice.author);
    let list = |uids: &[Uid]| {
        uids.iter()
            .map(|u| name_of(names, u))
            .collect::<Vec<_>>()
            .join("、")
    };
    Some(match &notice.change {
        ConvNotice::Created {
            kind: ConvKind::Group,
            members,
            ..
        } => {
            let others: Vec<Uid> = members
                .iter()
                .filter(|u| **u != notice.author)
                .cloned()
                .collect();
            if others.is_empty() {
                format!("{author} 创建了群")
            } else {
                format!("{author} 创建了群，加入了 {}", list(&others))
            }
        }
        ConvNotice::Created {
            kind: ConvKind::Dm,
            via: Some(Via::FriendLink),
            ..
        } => "通过好友链接添加，身份已核对".to_owned(),
        ConvNotice::Created {
            kind: ConvKind::Dm,
            via: Some(Via::Group { .. }),
            ..
        } => format!("{author} 在群里发起了私聊"),
        ConvNotice::Created {
            kind: ConvKind::Dm,
            via: None,
            ..
        } => format!("{author} 发起了私聊"),
        ConvNotice::Added { members } => format!("{author} 邀请 {} 加入了群", list(members)),
        ConvNotice::JoinedByInvite => format!("{author} 通过群邀请链接加入了群"),
        ConvNotice::Removed {
            uid,
            reason: RemoveReason::Kicked,
        } => format!("{author} 把 {} 移出了群", name_of(names, uid)),
        ConvNotice::Removed {
            uid,
            reason: RemoveReason::Reset,
        } => format!("{} 重置了账号，已退出群", name_of(names, uid)),
        ConvNotice::Left => format!("{author} 退出了群"),
        ConvNotice::MemberReset { uid } if uid == me => {
            "你重置了账号，之后的消息用新钥匙加密".to_owned()
        }
        ConvNotice::MemberReset { uid } => format!(
            "{} 重置了账号，之后的消息用新钥匙加密。想确认是本人，请当面或通过别的渠道问一下",
            name_of(names, uid)
        ),
        ConvNotice::ProfileChanged => format!("{author} 修改了群资料"),
        ConvNotice::Rotated
        | ConvNotice::InviteCreated { .. }
        | ConvNotice::InviteRevoked { .. } => return None,
    })
}

/// 翻到的一项算不算“有人发了消息”（会话发现用，协议 `conversations/recentActivity`）：算的话给它的时间与发的人。
/// 只算翻历史时给人看的新内容——普通消息、解不开的那条、给人看的系统提示；个人资料、撤回、换钥匙这些不给人看的不算，
/// 已经撤回、只剩“已撤回”的那条也不算新消息。
pub(crate) fn activity_of<'a>(item: &'a HistoryItem, me: &Uid) -> Option<(i64, &'a Uid)> {
    match item {
        HistoryItem::Message(m) => {
            matches!(m.content, Some(Content::Post { .. })).then_some((m.ts_ms, &m.sender))
        }
        HistoryItem::Rejected { ts_ms, sender, .. } => Some((*ts_ms, sender)),
        HistoryItem::Notice(n) => {
            notice_text(n, &Names::new(), me).map(|_| (n.ctime_ms, &n.author))
        }
    }
}

/// 系统提示要用到的账号（作者、成员）。
pub(crate) fn notice_people(notice: &Notice) -> Vec<Uid> {
    let mut uids = vec![notice.author.clone()];
    match &notice.change {
        ConvNotice::Created { members, .. } | ConvNotice::Added { members } => {
            uids.extend(members.iter().cloned())
        }
        ConvNotice::Removed { uid, .. } | ConvNotice::MemberReset { uid } => uids.push(uid.clone()),
        _ => {}
    }
    uids
}

/// 一条系统提示 → 协议的系统消息（编号 `n-<日志序号>`，时间是签它的人写的时间）。
pub(crate) fn notice(notice: &Notice, names: &Names, me: &Uid) -> Option<Wire> {
    let text = notice_text(notice, names, me)?;
    Some(wire(
        format!("n-{}", notice.log),
        notice.conv.to_string(),
        system(),
        notice.ctime_ms,
        vec![Block::Text { text }],
    ))
}

/// 会话签名链里一项变化没通过核对：在这个会话里留一条提醒（契约 §5：服务器作恶被识破时提醒用户）。
pub(crate) fn conv_rejected(conv: &str, log: u64, at_ms: i64) -> Wire {
    let text =
        "这个会话有一项变化没通过核对，已拒绝（可能是服务器出了问题或被人改过）。".to_owned();
    wire(
        format!("r-{log}"),
        conv.to_owned(),
        system(),
        at_ms,
        vec![Block::Text { text }],
    )
}

/// 要发的一段（附件已经上传好、换成了文件引用）。
pub(crate) enum Piece {
    /// 文字、提及。
    Part(Part),
    /// 图片或文件：上传的暂存键。
    Attachment { key: String, image: bool },
}

/// HHH 要发的内容 → 要发的几段。提及的编号格式不对时为错误说明。
pub(crate) fn pieces(content: &[Outgoing]) -> Result<Vec<Piece>, String> {
    content
        .iter()
        .map(|o| {
            Ok(match o {
                Outgoing::Sticker { .. } | Outgoing::Rich { .. } => {
                    return Err("Cindy IM 插件尚未声明这种消息的发送能力。".into());
                }
                Outgoing::Text { text } => Piece::Part(Part::Text { text: text.clone() }),
                Outgoing::Mention { user_id, name } => Piece::Part(Part::Mention {
                    uid: Some(
                        Uid::parse(user_id).map_err(|_| format!("提及的人编号不对：{user_id}"))?,
                    ),
                    name: Some(name.clone()),
                    everyone: false,
                }),
                Outgoing::MentionAll => Piece::Part(Part::Mention {
                    uid: None,
                    name: None,
                    everyone: true,
                }),
                Outgoing::Image { key } => Piece::Attachment {
                    key: key.clone(),
                    image: true,
                },
                Outgoing::File { key } => Piece::Attachment {
                    key: key.clone(),
                    image: false,
                },
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use friend_im_client::core::ids::{ConvId, DeviceId};

    fn uid(n: u8) -> Uid {
        Uid::from_raw([n; 16])
    }

    fn file() -> FileRef {
        FileRef {
            id: FileId::from_raw([3; 16]),
            key: Fixed([4; 32]),
            size: 70_000,
            name: "照片.png".into(),
            mime: "image/png".into(),
        }
    }

    fn msg(content: Option<Content>) -> Message {
        Message {
            conv: ConvId::from_raw([1; 16]),
            id: MsgId::from_raw([2; 16]),
            log: 9,
            ts_ms: 1_791_000_000_000,
            sender: uid(5),
            sender_eldest: Fixed([0; 32]),
            device: DeviceId::from_raw([6; 16]),
            ctime_ms: 1_791_000_000_001,
            content,
        }
    }

    #[test]
    fn resource_keys_round_trip_and_reject_garbage() {
        let key = resource_key(&file());
        assert!(key.len() < 100, "{key}");
        let back = file_of_key(&key).unwrap();
        assert_eq!(
            (back.id, back.key, back.size),
            (file().id, file().key, file().size)
        );
        for bad in [
            "",
            "f1",
            "f2.a.b.1",
            &format!("{key}.x"),
            &key.replace("f1.", "f1.x"),
            &key.replace(".70000", ".abc"),
        ] {
            assert!(file_of_key(bad).is_none(), "{bad}");
        }
        assert_eq!(parse_cursor(&cursor(42)), Some(42));
        assert_eq!(parse_cursor("42"), None);
    }

    #[test]
    fn every_kind_of_part_becomes_a_block() {
        let names = Names::from([(uid(5), "小满".to_owned()), (uid(7), "阿哲".to_owned())]);
        let parts = vec![
            Part::Text {
                text: "看这个".into(),
            },
            Part::Mention {
                uid: Some(uid(7)),
                name: None,
                everyone: false,
            },
            Part::Mention {
                uid: None,
                name: None,
                everyone: true,
            },
            Part::Image {
                file: file(),
                width: Some(640),
                height: Some(480),
            },
            Part::File { file: file() },
        ];
        let out = message(
            &msg(Some(Content::Post {
                parts,
                reply_to: Some(MsgId::from_raw([8; 16])),
            })),
            &names,
        )
        .unwrap();
        assert_eq!(out.sender.name.as_deref(), Some("小满"));
        assert_eq!(out.created_at_ms, 1_791_000_000_000, "用服务器时间");
        assert_eq!(out.reply_to, Some(MsgId::from_raw([8; 16]).to_string()));
        let json = serde_json::to_value(&out.content).unwrap();
        assert_eq!(
            json[0],
            serde_json::json!({ "type": "text", "text": "看这个" })
        );
        assert_eq!(json[1]["name"], "阿哲");
        assert_eq!(json[1]["kind"], "user");
        assert_eq!(json[2]["everyone"], true);
        assert_eq!(json[3]["resource"]["kind"], "image");
        assert_eq!(json[3]["width"], 640);
        assert_eq!(json[4]["resource"]["kind"], "file");
        assert_eq!(json[4]["resource"]["bytes"], 70_000);
        assert_eq!(json[4]["name"], "照片.png");
        assert!(file_of_key(json[4]["resource"]["key"].as_str().unwrap()).is_some());
    }

    #[test]
    fn recalls_and_unreadable_messages() {
        let names = Names::new();
        let gone = message(&msg(None), &names).unwrap();
        assert!(gone.deleted && gone.content.is_empty());
        assert!(
            message(
                &msg(Some(Content::Recall {
                    target: MsgId::from_raw([2; 16])
                })),
                &names
            )
            .is_none(),
            "撤回动作本身不显示"
        );
        assert!(
            message(
                &msg(Some(Content::Profile {
                    avatar: Some("https://a.example.com/1.png".into()),
                    photo: None
                })),
                &names
            )
            .is_none(),
            "个人资料不显示"
        );
        let bad = unreadable("c", &MsgId::from_raw([2; 16]), &uid(5), 5, &names);
        assert!(bad.incomplete);
        assert!(matches!(&bad.content[0], Block::Unsupported { .. }));
    }

    #[test]
    fn notices_read_like_the_contract() {
        let names = Names::from([
            (uid(1), "小满".to_owned()),
            (uid(2), "阿哲".to_owned()),
            (uid(3), "米粒".to_owned()),
        ]);
        let notice = |author: u8, change| Notice {
            conv: ConvId::from_raw([9; 16]),
            log: 4,
            ctime_ms: 7,
            author: uid(author),
            change,
        };
        let text = |n: &Notice| notice_text(n, &names, &uid(1));
        assert_eq!(
            text(&notice(
                1,
                ConvNotice::Created {
                    kind: ConvKind::Group,
                    members: vec![uid(1), uid(2), uid(3)],
                    via: None
                }
            ))
            .unwrap(),
            "小满 创建了群，加入了 阿哲、米粒"
        );
        assert_eq!(
            text(&notice(
                2,
                ConvNotice::Created {
                    kind: ConvKind::Dm,
                    members: vec![uid(1), uid(2)],
                    via: Some(Via::FriendLink)
                }
            ))
            .unwrap(),
            "通过好友链接添加，身份已核对"
        );
        assert_eq!(
            text(&notice(
                1,
                ConvNotice::Removed {
                    uid: uid(3),
                    reason: RemoveReason::Kicked
                }
            ))
            .unwrap(),
            "小满 把 米粒 移出了群"
        );
        assert_eq!(
            text(&notice(2, ConvNotice::MemberReset { uid: uid(2) })).unwrap(),
            "阿哲 重置了账号，之后的消息用新钥匙加密。想确认是本人，请当面或通过别的渠道问一下"
        );
        assert_eq!(
            text(&notice(1, ConvNotice::MemberReset { uid: uid(1) })).unwrap(),
            "你重置了账号，之后的消息用新钥匙加密",
            "本人看到的不叫自己去核对自己"
        );
        assert_eq!(text(&notice(9, ConvNotice::Left)).unwrap(), "有人 退出了群");
        assert!(text(&notice(1, ConvNotice::Rotated)).is_none());
        let wire = super::notice(&notice(1, ConvNotice::Left), &names, &uid(1)).unwrap();
        assert_eq!(
            (wire.id.as_str(), wire.sender.kind, wire.created_at_ms),
            ("n-4", SenderKind::System, 7)
        );
        assert!(wire.sender.id.is_empty());
    }

    #[test]
    fn outgoing_content_becomes_parts() {
        let content = vec![
            Outgoing::Text {
                text: "你好".into(),
            },
            Outgoing::Mention {
                user_id: uid(2).to_string(),
                name: "阿哲".into(),
            },
            Outgoing::MentionAll,
            Outgoing::Image { key: "u.1".into() },
            Outgoing::File { key: "u.2".into() },
        ];
        let pieces = pieces(&content).unwrap();
        assert!(
            matches!(&pieces[1], Piece::Part(Part::Mention { uid: Some(u), .. }) if *u == uid(2))
        );
        assert!(matches!(
            &pieces[2],
            Piece::Part(Part::Mention { everyone: true, .. })
        ));
        assert!(matches!(&pieces[3], Piece::Attachment { image: true, .. }));
        assert!(matches!(&pieces[4], Piece::Attachment { image: false, .. }));
        assert!(pieces_err(&[Outgoing::Mention {
            user_id: "不是编号".into(),
            name: "x".into()
        }]));
    }

    fn pieces_err(content: &[Outgoing]) -> bool {
        pieces(content).is_err()
    }
}
