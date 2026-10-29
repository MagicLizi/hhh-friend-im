//! 插件操作（provider-protocol v13 §6.7；契约 S5、S6、S8、S9、S11–S13、S17；文字照原型 friend-im-v2）。
//!
//! - 账号级：我的电脑（移除别的电脑、重新生成恢复密钥）、我的好友链接（换一条）、加好友（也收群邀请链接）、新建群、
//!   关于加密。会话级（只给群）：群成员（群主能移出）、邀请成员（勾选好友或给群邀请链接）、退出群。把会话从列表拿掉
//!   是宿主会话菜单里所有 IM 通用的“从列表移除”（HHH 契约 friend/sidebar-sessions v25），插件不再有自己的“删除会话”。
//! - 提醒上的“查看”：`approve:<请求>` 是批准新电脑（[`super::approvals`]），`devices` 打开我的电脑。
//! - 每项操作是一个流程（[`super::flow`]）：先回流程编号再推第一步；子步骤的“取消”用 `cancelChoice: "back"` 回到上一层，
//!   点遮罩、按 Esc 关掉整个对话框（宿主发 `action/cancel`，这里不再推结果）。

use std::collections::HashMap;
use std::sync::Arc;

use friend_im_client::core::conv::{ConvKind, GroupProfile, Via};
use friend_im_client::core::ids::{ConvId, DeviceId, Uid};
use friend_im_client::core::wire::{DeviceInfo, ErrorCode};
use friend_im_client::{ClientError, FriendLink, InviteLink};
use hhh_im_protocol::method::{ActionsStartParams, ActionsStartResult};
use hhh_im_protocol::rpc::{ErrorKind, RpcError, RpcId};
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::approvals::{APPROVE_PREFIX, civil_date};
use super::flow::{Input, Kind, Ui, compact, link, note, recovery_key, wait_confirm, waiting};
use super::session::Live;
use super::{Server, errors, now_ms};

/// 我的电脑。
pub(crate) const DEVICES: &str = "devices";
/// 我的好友链接。
pub(crate) const LINK: &str = "link";
/// 加好友。
pub(crate) const ADD: &str = "add";
/// 新建群。
pub(crate) const GROUP: &str = "group";
/// 关于加密。
pub(crate) const ABOUT: &str = "about";
/// 群成员。
pub(crate) const MEMBERS: &str = "members";
/// 邀请成员。
pub(crate) const INVITE: &str = "invite";
/// 退出群。
pub(crate) const LEAVE: &str = "leave";

/// 群名至多几个字。
const GROUP_NAME_MAX_CHARS: usize = 64;
/// 列表至多几行（协议上限）。
const ROWS_MAX: usize = hhh_im_protocol::budget::STEP_ROWS_MAX;

/// 用户点了哪一项。
enum Which {
    Devices,
    Link,
    Add,
    Group,
    About,
    Members(ConvId),
    Invite(ConvId),
    Leave(ConvId),
    Approve(String),
}

/// 凭群邀请链接进群的结果。
enum Joined {
    /// 进了。
    Done,
    /// 回到输入框（带不带提示）。
    Back(Option<String>),
}

/// 一个人在列表里的写法：好友（私聊的对方）是怎么认识的。
struct Friend {
    uid: Uid,
    name: String,
    detail: &'static str,
}

/// 客户端库的错误写成给人看的一句话。
fn said(error: &ClientError) -> String {
    errors::client(error)
        .data
        .and_then(|d| d.user_message)
        .unwrap_or_else(|| "出了点问题，稍后再试。".into())
}

/// 身份指纹的前 8 位，分两组（如“3F2A 9C41”）。
pub(crate) fn fingerprint(eldest: &[u8]) -> String {
    let hex: String = eldest.iter().take(4).map(|b| format!("{b:02X}")).collect();
    format!("{} {}", &hex[..4], &hex[4..])
}

/// 一台电脑的说明：加入日期与最近在线（“加入于 2026-10-10 · 在线”/“… · 3 小时前在线”）。新电脑登录时列的电脑也用它。
pub(super) fn device_detail(device: &DeviceInfo, now: i64) -> String {
    let (year, month, day) = civil_date(device.joined_ms);
    let seen = if device.online {
        "在线".to_owned()
    } else {
        let minutes = (now - device.last_seen_ms).max(0) / 60_000;
        match minutes {
            0 => "刚刚在线".to_owned(),
            1..60 => format!("{minutes} 分钟前在线"),
            60..1440 => format!("{} 小时前在线", minutes / 60),
            _ => format!("{} 天前在线", minutes / 1440),
        }
    };
    let kind = matches!(
        device.kind,
        friend_im_client::core::wire::DeviceKind::Mobile
    )
    .then(|| device.kind.label());
    match kind {
        Some(kind) => format!("{kind} · 加入于 {year}-{month:02}-{day:02} · {seen}"),
        None => format!("加入于 {year}-{month:02}-{day:02} · {seen}"),
    }
}

/// 等用户的下一个输入；关掉对话框、被新流程顶掉为 `None`。批准的事件只有批准流程收，这里跳过。
async fn next(rx: &mut mpsc::UnboundedReceiver<Input>) -> Option<Input> {
    loop {
        match rx.recv().await {
            None | Some(Input::Cancel) => return None,
            Some(Input::Join(_)) => {}
            Some(other) => return Some(other),
        }
    }
}

/// 子步骤的确认（危险操作、换链接）：左边的“取消”回到上一层。为真是确认了；`None` 是对话框关了。
async fn confirmed(
    ui: &Ui<'_>,
    rx: &mut mpsc::UnboundedReceiver<Input>,
    step: Value,
) -> Option<bool> {
    let mut step = step;
    step["cancelLabel"] = "取消".into();
    step["cancelChoice"] = "back".into();
    ui.step(compact(step));
    loop {
        match next(rx).await? {
            Input::Choose { choice, .. } if choice == "confirm" => return Some(true),
            Input::Choose { choice, .. } if choice == "back" => return Some(false),
            _ => {}
        }
    }
}

fn person_row(
    id: &str,
    title: &str,
    detail: Option<&str>,
    tag: Option<&str>,
    actions: Vec<Value>,
) -> Value {
    // 没有按钮就不写 `actions`（空数组和没写是一回事，少一个键）。
    let actions = (!actions.is_empty()).then_some(actions);
    compact(
        json!({ "id": id, "title": title, "detail": detail, "tag": tag, "icon": "person", "actions": actions }),
    )
}

impl Server {
    /// `actions/start`：认出是哪一项、核对会话，开一个流程，先回流程编号再推第一步（回 `None`：已经回过了）。
    pub(crate) async fn actions_start(
        self: &Arc<Self>,
        id: &RpcId,
        params: ActionsStartParams,
    ) -> Option<Result<Value, RpcError>> {
        let live = match self.live().await {
            Ok(live) => live,
            Err(error) => return Some(Err(error)),
        };
        let which = match self.which(&live, &params).await {
            Ok(which) => which,
            Err(error) => return Some(Err(error)),
        };
        let title = match &which {
            Which::Approve(request) => live
                .requests
                .lock()
                .expect("批准请求锁中毒")
                .get(request)
                .map(|info| {
                    if matches!(info.kind, friend_im_client::core::wire::DeviceKind::Mobile) {
                        "批准新设备"
                    } else {
                        "批准新电脑"
                    }
                    .to_owned()
                }),
            _ => None,
        };
        let (flow_id, rx) = self.flows.begin(Kind::Action);
        let result = ActionsStartResult {
            flow_id: flow_id.clone(),
            title,
        };
        self.peer.respond(
            id.clone(),
            Ok(serde_json::to_value(result).expect("结果总能写成 JSON")),
        );
        tracing::info!(action = %params.action_id, "开始一项操作");
        let server = self.clone();
        tokio::spawn(async move {
            let ui = Ui {
                peer: &server.peer,
                flow_id: flow_id.clone(),
                kind: Kind::Action,
            };
            server.clone().run_action(live, ui, which, rx).await;
            server.flows.end(&flow_id);
        });
        None
    }

    /// 操作编号 → 哪一项；会话级的要是我在的群。
    async fn which(&self, live: &Live, params: &ActionsStartParams) -> Result<Which, RpcError> {
        let id = params.action_id.as_str();
        if let Some(request) = id.strip_prefix(APPROVE_PREFIX) {
            return Ok(Which::Approve(request.to_owned()));
        }
        let account = match id {
            DEVICES => Some(Which::Devices),
            LINK => Some(Which::Link),
            ADD => Some(Which::Add),
            GROUP => Some(Which::Group),
            ABOUT => Some(Which::About),
            _ => None,
        };
        if let Some(which) = account {
            return Ok(which);
        }
        if ![MEMBERS, INVITE, LEAVE].contains(&id) {
            return Err(errors::of(
                ErrorKind::Unsupported,
                "Cindy IM 没有这项操作。",
            ));
        }
        let text = params
            .conversation_id
            .as_deref()
            .ok_or_else(|| errors::of(ErrorKind::InvalidRequest, "这项操作要在会话里用。"))?;
        let conv =
            ConvId::parse(text).map_err(|_| errors::of(ErrorKind::NotFound, "没有这个会话。"))?;
        let info = live
            .client
            .conv_info(&conv)
            .await
            .map_err(|e| errors::client(&e))?;
        if info.kind != ConvKind::Group {
            return Err(errors::of(
                ErrorKind::InvalidRequest,
                "这项操作只能用在群里。",
            ));
        }
        if !info.member {
            return Err(errors::of(
                ErrorKind::InvalidRequest,
                "你已经不在这个群里了。",
            ));
        }
        Ok(match id {
            MEMBERS => Which::Members(conv),
            INVITE => Which::Invite(conv),
            _ => Which::Leave(conv),
        })
    }

    async fn run_action(
        self: Arc<Self>,
        live: Arc<Live>,
        ui: Ui<'_>,
        which: Which,
        mut rx: mpsc::UnboundedReceiver<Input>,
    ) {
        match which {
            Which::Approve(request) => self.approve(live, ui, &request, rx).await,
            Which::Devices => self.devices(&live, &ui, &mut rx).await,
            Which::Link => self.friend_link(&live, &ui, &mut rx).await,
            Which::Add => self.add(&live, &ui, &mut rx).await,
            Which::Group => self.new_group(&live, &ui, &mut rx).await,
            Which::About => about(&ui, &mut rx).await,
            Which::Members(conv) => self.members(&live, &ui, &mut rx, &conv).await,
            Which::Invite(conv) => self.invite(&live, &ui, &mut rx, &conv).await,
            Which::Leave(conv) => self.leave(&live, &ui, &mut rx, &conv).await,
        }
    }

    /// 我的电脑（S5、S6）：列出电脑，移除别的、重新生成恢复密钥。打开就算看过了电脑增减的提醒。
    async fn devices(&self, live: &Live, ui: &Ui<'_>, rx: &mut mpsc::UnboundedReceiver<Input>) {
        self.devices_seen(live);
        let me: DeviceId = live.client.device_id().clone();
        let mut tip: Option<(String, bool)> = None;
        loop {
            let list = match live.client.devices().await {
                Ok(list) => list,
                Err(error) => {
                    tracing::info!(%error, "我的电脑取不到");
                    ui.fail(Some("没有完成"), &said(&error), Some("再试一次"));
                    return;
                }
            };
            let now = now_ms();
            let rows: Vec<Value> = list
                .iter()
                .take(ROWS_MAX)
                .map(|d| {
                    let mine = d.id == me;
                    let actions = (!mine)
                        .then(|| vec![json!({ "id": "remove", "label": "移除", "danger": true })]);
                    compact(json!({
                        "id": d.id.to_string(), "title": d.name, "detail": device_detail(d, now),
                        "tag": mine.then_some("本机"), "icon": "device", "actions": actions,
                    }))
                })
                .collect();
            ui.step(compact(json!({
                "kind": "list", "caption": "登录着这个账号的设备。移除后，那台设备读不到之后的新消息。", "rows": rows,
                "note": tip.take().map(|(text, warn)| note(&text, warn)),
                "links": [link("regen", "重新生成恢复密钥")],
            })));
            let Some(input) = next(rx).await else {
                self.devices_seen(live);
                return;
            };
            match input {
                Input::Choose {
                    choice,
                    row: Some(row),
                    ..
                } if choice == "remove" => {
                    let Some(device) = list.iter().find(|d| d.id.to_string() == row && d.id != me)
                    else {
                        continue;
                    };
                    let step = json!({
                        "kind": "confirm", "caption": format!("移除「{}」？", device.name), "danger": true, "confirmLabel": "移除",
                        "text": "那台设备会立刻退出 Cindy IM，之后的新消息它读不到。它本机已有的聊天记录不会被远程删除。",
                    });
                    match confirmed(ui, rx, step).await {
                        None => return,
                        Some(false) => continue,
                        Some(true) => {}
                    }
                    ui.step(waiting("正在移除…"));
                    tip = Some(match live.client.remove_device(&device.id).await {
                        Ok(()) => (
                            format!("已移除「{}」。你的其它设备也会收到提醒。", device.name),
                            false,
                        ),
                        Err(error) => {
                            tracing::info!(%error, "移除电脑没成");
                            (
                                format!("没能移除「{}」：{}", device.name, said(&error)),
                                true,
                            )
                        }
                    });
                    // 移除自己做的，不用再提醒这台。
                    self.devices_seen(live);
                }
                Input::Choose { choice, .. } if choice == "regen" => {
                    let step = json!({
                        "kind": "confirm", "caption": "重新生成恢复密钥？", "confirmLabel": "重新生成",
                        "text": "旧的恢复密钥会立即失效。已经登录着的设备不受影响。",
                    });
                    match confirmed(ui, rx, step).await {
                        None => return,
                        Some(false) => continue,
                        Some(true) => {}
                    }
                    ui.step(waiting("正在生成…"));
                    match live.client.replace_recovery().await {
                        Ok(key) => {
                            ui.step(recovery_key(
                                "这是新的恢复密钥，只显示这一次。旧的已经失效。",
                                &key.to_words(),
                            ));
                            if !wait_confirm(rx).await {
                                return;
                            }
                            tip = Some(("新的恢复密钥已生效，旧的已经失效。".into(), false));
                        }
                        Err(error) => {
                            tracing::info!(%error, "重新生成恢复密钥没成");
                            tip = Some((format!("没能重新生成恢复密钥：{}", said(&error)), true));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// 我的好友链接（S8）：复制；换一条后旧的失效。
    async fn friend_link(&self, live: &Live, ui: &Ui<'_>, rx: &mut mpsc::UnboundedReceiver<Input>) {
        let mut rotate = false;
        let mut tip: Option<&str> = None;
        loop {
            let link_text = match live.client.friend_link(rotate).await {
                Ok(link) => link.to_string(),
                Err(error) => {
                    tracing::info!(%error, rotate, "好友链接取不到");
                    ui.fail(Some("没有完成"), &said(&error), Some("再试一次"));
                    return;
                }
            };
            rotate = false;
            ui.step(compact(json!({
                "kind": "showText", "layout": "line", "text": link_text, "copy": true,
                "caption": "把这条链接发给想加你的人。对方在 Cindy IM 里粘贴它就能加你为好友，同时核对是你本人。",
                "note": tip.take().map(|text| note(text, false)),
                "links": [link("renew", "换一条链接")],
            })));
            match next(rx).await {
                None => return,
                Some(Input::Choose { choice, .. }) if choice == "renew" => {
                    let step = json!({
                        "kind": "confirm", "caption": "换一条链接？", "confirmLabel": "换一条",
                        "text": "旧链接会立即失效，还没用它加你的人就加不了了；已经加了你的好友不受影响。",
                    });
                    match confirmed(ui, rx, step).await {
                        None => return,
                        Some(false) => {}
                        Some(true) => {
                            rotate = true;
                            tip = Some("已换成新链接，旧链接失效了。已经加了你的人不受影响。");
                        }
                    }
                }
                Some(_) => {}
            }
        }
    }

    /// 加好友（S9）：粘贴好友链接，按链接核对身份后确认；也收群邀请链接（S12，凭链接进群）。
    async fn add(&self, live: &Live, ui: &Ui<'_>, rx: &mut mpsc::UnboundedReceiver<Input>) {
        let mut warn: Option<String> = None;
        let placeholder = format!("{}/f/…", self.server_url());
        loop {
            ui.step(compact(json!({
                "kind": "input", "caption": "粘贴对方发给你的好友链接或群邀请链接。",
                "fields": [{ "id": "link", "label": "链接", "secret": false, "placeholder": placeholder }],
                "submitLabel": "下一步", "note": warn.take().map(|text| note(&text, true)),
            })));
            let values = match next(rx).await {
                None => return,
                Some(Input::Submit(values)) => values,
                Some(_) => continue,
            };
            let text = values
                .get("link")
                .map(|t| t.trim().to_owned())
                .unwrap_or_default();
            if let Ok(invite) = InviteLink::parse(&text) {
                match self.join_by_link(live, ui, rx, &invite).await {
                    None | Some(Joined::Done) => return,
                    Some(Joined::Back(problem)) => {
                        warn = problem;
                        continue;
                    }
                }
            }
            let Ok(link) = FriendLink::parse(&text) else {
                warn = Some(
                    "这不是好友链接。好友链接以 https:// 开头，由对方在“我的好友链接”里复制给你。"
                        .into(),
                );
                continue;
            };
            ui.step(waiting("正在核对…"));
            let info = match live.client.resolve_friend(&link).await {
                Ok(info) => info,
                Err(error) => {
                    tracing::info!(%error, "按好友链接查人没成");
                    warn = Some(match &error {
                        _ if error.code() == Some(ErrorCode::NotFound) => "这条链接已经失效了（对方换过链接）。请让对方重新发一条。".into(),
                        ClientError::Verify(_) => "链接里的身份和服务器上的对不上，没有添加。请当面或通过别的渠道再要一次链接。".into(),
                        _ => said(&error),
                    });
                    continue;
                }
            };
            if info.uid == live.me {
                warn = Some("这是你自己的好友链接。".into());
                continue;
            }
            let step = json!({
                "kind": "confirm", "caption": format!("加{}为好友？对方不需要再点同意。", info.name), "confirmLabel": "加好友",
                "person": { "name": info.name, "detail": format!("身份指纹 {} · 和链接里的一致", fingerprint(&link.eldest.0)) },
            });
            match confirmed(ui, rx, step).await {
                None => return,
                Some(false) => continue,
                Some(true) => {}
            }
            ui.step(waiting("正在添加…"));
            match live.client.add_friend(&link).await {
                Ok(conversation) => {
                    ui.done_opening(&conversation,
                        Some(&format!("已添加{}", info.name)),
                        Some("私聊已出现在你们两边的会话列表，第一条提示写着“通过好友链接添加，身份已核对”。"),
                    );
                }
                Err(error) if error.code() == Some(ErrorCode::Conflict) => {
                    ui.fail(
                        Some("没有添加"),
                        &format!("你和{}已经是好友了，私聊就在会话列表里。", info.name),
                        None,
                    );
                }
                Err(error) => {
                    tracing::info!(%error, "加好友没成");
                    ui.fail(Some("没有添加"), &said(&error), Some("再试一次"));
                }
            }
            return;
        }
    }

    /// 凭群邀请链接进群：确认 → 加入 → 完成。`None` 是对话框关了。
    async fn join_by_link(
        &self,
        live: &Live,
        ui: &Ui<'_>,
        rx: &mut mpsc::UnboundedReceiver<Input>,
        invite: &InviteLink,
    ) -> Option<Joined> {
        let step = json!({
            "kind": "confirm", "caption": "加入这个群？", "confirmLabel": "加入",
            "text": "群里的人会看到你通过群邀请链接加入了群。加入后能看到群里以前的全部消息。",
        });
        if !confirmed(ui, rx, step).await? {
            return Some(Joined::Back(None));
        }
        ui.step(waiting("正在加入…"));
        match live.client.join_by_invite(invite).await {
            Ok(conv) => {
                let name = live
                    .conversation(&conv)
                    .await
                    .map(|c| c.name)
                    .unwrap_or_else(|_| "群聊".into());
                ui.done_opening(
                    &conv,
                    Some(&format!("已加入群「{name}」")),
                    Some("群已出现在你的会话列表，群里以前的消息在后台补齐。"),
                );
                Some(Joined::Done)
            }
            Err(error) => {
                tracing::info!(%error, "凭群邀请链接进群没成");
                Some(Joined::Back(Some(match &error {
                    ClientError::State(_) => {
                        "这条群邀请链接已经作废或过期了。请让群里的人重新发一条。".into()
                    }
                    _ if error.code() == Some(ErrorCode::NotFound) => {
                        "这条群邀请链接已经作废或过期了。请让群里的人重新发一条。".into()
                    }
                    ClientError::Verify(_) => "链接里的钥匙和群邀请对不上，没有加入。".into(),
                    _ => said(&error),
                })))
            }
        }
    }

    /// 好友：私聊的对方（至多 [`ROWS_MAX`] 个），按名字排。
    async fn friends(&self, live: &Live) -> Result<Vec<Friend>, ClientError> {
        let mut found: Vec<(Uid, &'static str)> = Vec::new();
        for summary in live.client.convs().await? {
            if !summary.member || summary.kind != ConvKind::Dm {
                continue;
            }
            let info = match live.client.conv_info(&summary.conv).await {
                Ok(info) => info,
                Err(error) => {
                    tracing::info!(conv = %summary.conv, %error, "私聊的资料取不到，好友列表里先不放");
                    continue;
                }
            };
            if let Some(peer) = info
                .members
                .iter()
                .map(|m| m.uid.clone())
                .find(|u| *u != live.me)
            {
                let detail = match info.via {
                    Some(Via::Group { .. }) => "好友 · 通过群认识",
                    _ => "好友 · 身份已核对",
                };
                if !found.iter().any(|(u, _)| *u == peer) {
                    found.push((peer, detail));
                }
            }
        }
        let names = live.names(found.iter().map(|(u, _)| u.clone())).await;
        let mut friends: Vec<Friend> = found
            .into_iter()
            .map(|(uid, detail)| Friend {
                name: names.get(&uid).cloned().unwrap_or_else(|| "有人".into()),
                uid,
                detail,
            })
            .collect();
        friends.sort_by(|a, b| a.name.cmp(&b.name));
        friends.truncate(ROWS_MAX);
        Ok(friends)
    }

    /// 新建群（S11）：先填群名，再勾选好友。
    async fn new_group(&self, live: &Live, ui: &Ui<'_>, rx: &mut mpsc::UnboundedReceiver<Input>) {
        let mut warn: Option<&str> = None;
        let name = loop {
            ui.step(compact(json!({
                "kind": "input", "caption": "群名、群头像和群简介只有群成员看得到，服务器看不到。",
                "fields": [{ "id": "name", "label": "群名", "secret": false, "placeholder": "例如：周末徒步" }],
                "submitLabel": "下一步", "note": warn.take().map(|text| note(text, true)),
            })));
            match next(rx).await {
                None => return,
                Some(Input::Submit(values)) => {
                    let name = values
                        .get("name")
                        .map(|n| n.trim().to_owned())
                        .unwrap_or_default();
                    if name.is_empty() {
                        warn = Some("群名不能是空的。");
                    } else if name.chars().count() > GROUP_NAME_MAX_CHARS {
                        warn = Some("群名太长了，至多 64 个字。");
                    } else {
                        break name;
                    }
                }
                Some(_) => {}
            }
        };
        let friends = match self.friends(live).await {
            Ok(friends) => friends,
            Err(error) => {
                tracing::info!(%error, "好友列表取不到");
                ui.fail(Some("没有完成"), &said(&error), Some("再试一次"));
                return;
            }
        };
        let rows: Vec<Value> = friends
            .iter()
            .map(|f| person_row(f.uid.as_str(), &f.name, Some(f.detail), None, vec![]))
            .collect();
        ui.step(compact(json!({
            "kind": "list", "caption": "选要拉进群的好友（之后还能再邀请）。", "rows": rows,
            "select": { "min": 1, "confirmLabel": "创建" }, "empty": "还没有好友。先在“加好友”里加几个人。",
        })));
        let selected = loop {
            match next(rx).await {
                None => return,
                Some(Input::Choose {
                    choice, selected, ..
                }) if choice == "confirm" && !selected.is_empty() => break selected,
                Some(_) => {}
            }
        };
        let chosen: Vec<&Friend> = friends
            .iter()
            .filter(|f| selected.iter().any(|s| s == f.uid.as_str()))
            .collect();
        let uids: Vec<Uid> = chosen.iter().map(|f| f.uid.clone()).collect();
        ui.step(waiting("正在建群…"));
        let profile = GroupProfile {
            name: name.clone(),
            description: String::new(),
            avatar: None,
        };
        match live.client.create_group(&profile, &uids).await {
            Ok(conversation) => {
                let me = live.client.name().await;
                let others = chosen
                    .iter()
                    .map(|f| f.name.as_str())
                    .collect::<Vec<_>>()
                    .join("、");
                ui.done_opening(
                    &conversation,
                    Some(&format!("群「{name}」已创建")),
                    Some(&format!(
                        "群已出现在每个成员的会话列表，第一条提示“{me} 创建了群，加入了 {others}”。"
                    )),
                );
            }
            Err(error) => {
                tracing::info!(%error, "建群没成");
                ui.fail(Some("没有建成"), &said(&error), Some("再试一次"));
            }
        }
    }

    /// 群成员（S13）：群主能移出别人。
    async fn members(
        &self,
        live: &Live,
        ui: &Ui<'_>,
        rx: &mut mpsc::UnboundedReceiver<Input>,
        conv: &ConvId,
    ) {
        let details: HashMap<Uid, &'static str> = self
            .friends(live)
            .await
            .map(|f| f.into_iter().map(|f| (f.uid, f.detail)).collect())
            .unwrap_or_default();
        let mut tip: Option<(String, bool)> = None;
        loop {
            let info = match live.client.conv_info(conv).await {
                Ok(info) if info.member => info,
                Ok(_) => {
                    ui.fail(Some("没有完成"), "你已经不在这个群里了。", None);
                    return;
                }
                Err(error) => {
                    tracing::info!(%conv, %error, "群成员取不到");
                    ui.fail(Some("没有完成"), &said(&error), Some("再试一次"));
                    return;
                }
            };
            let group = live
                .conversation(conv)
                .await
                .map(|c| c.name)
                .unwrap_or_else(|_| "群聊".into());
            let names = live.names(info.members.iter().map(|m| m.uid.clone())).await;
            let name_of = |uid: &Uid| names.get(uid).cloned().unwrap_or_else(|| "有人".into());
            let mine = info.owner == live.me;
            let count = info.members.len();
            let caption = if mine {
                format!("{count} 位成员。你是群主，可以移出成员。")
            } else {
                format!(
                    "{count} 位成员。只有群主{}能移出成员。",
                    name_of(&info.owner)
                )
            };
            let rows: Vec<Value> = info
                .members
                .iter()
                .take(ROWS_MAX)
                .map(|m| {
                    let me = m.uid == live.me;
                    let detail = if me {
                        Some("你自己")
                    } else {
                        details.get(&m.uid).copied()
                    };
                    // 别人那一行都能“发消息”（S10，不用先加好友）；群主还能移出。
                    let mut actions = Vec::new();
                    if !me {
                        actions.push(json!({ "id": "message", "label": "发消息" }));
                    }
                    if mine && !me {
                        actions.push(json!({ "id": "remove", "label": "移出", "danger": true }));
                    }
                    person_row(
                        m.uid.as_str(),
                        &name_of(&m.uid),
                        detail,
                        (m.uid == info.owner).then_some("群主"),
                        actions,
                    )
                })
                .collect();
            ui.step(compact(json!({
                "kind": "list", "caption": caption, "rows": rows, "note": tip.take().map(|(text, warn)| note(&text, warn)),
            })));
            match next(rx).await {
                None => return,
                Some(Input::Choose {
                    choice,
                    row: Some(row),
                    ..
                }) if choice == "message" => {
                    let Some(target) = info
                        .members
                        .iter()
                        .find(|m| m.uid.as_str() == row && m.uid != live.me)
                        .map(|m| m.uid.clone())
                    else {
                        continue;
                    };
                    let who = name_of(&target);
                    ui.step(waiting("正在打开私聊…"));
                    match live.client.open_dm(&target, conv).await {
                        // 新建的私聊随推送进会话列表；已经有的照旧在那里。
                        Ok(_) => ui.done(
                            Some(&format!("和「{who}」私聊")),
                            Some("私聊在你的会话列表里，点开就能聊，不用先加好友。"),
                        ),
                        Err(error) => {
                            tracing::info!(%conv, %error, "和群成员私聊没成");
                            tip = Some((
                                format!("没能打开和「{who}」的私聊：{}", said(&error)),
                                true,
                            ));
                            continue;
                        }
                    }
                    return;
                }
                Some(Input::Choose {
                    choice,
                    row: Some(row),
                    ..
                }) if choice == "remove" && mine => {
                    let Some(target) = info
                        .members
                        .iter()
                        .find(|m| m.uid.as_str() == row && m.uid != live.me)
                        .map(|m| m.uid.clone())
                    else {
                        continue;
                    };
                    let (me, who) = (live.client.name().await, name_of(&target));
                    let step = json!({
                        "kind": "confirm", "caption": format!("把「{who}」移出「{group}」？"), "danger": true, "confirmLabel": "移出",
                        "text": format!("群里所有人会看到“{me} 把 {who} 移出了群”。{who}读不到之后的新消息，在群期间的消息还留在对方的电脑上。"),
                    });
                    match confirmed(ui, rx, step).await {
                        None => return,
                        Some(false) => continue,
                        Some(true) => {}
                    }
                    ui.step(waiting("正在移出…"));
                    tip = Some(match live.client.kick(conv, &target).await {
                        Ok(()) => (format!("已把「{who}」移出群。"), false),
                        Err(error) => {
                            tracing::info!(%conv, %error, "移出成员没成");
                            (format!("没能移出「{who}」：{}", said(&error)), true)
                        }
                    });
                }
                Some(_) => {}
            }
        }
    }

    /// 邀请成员（S12）：勾选不在群里的好友，或改用群邀请链接。
    async fn invite(
        &self,
        live: &Live,
        ui: &Ui<'_>,
        rx: &mut mpsc::UnboundedReceiver<Input>,
        conv: &ConvId,
    ) {
        let mut invite_link: Option<String> = None;
        loop {
            let (info, friends) =
                match (live.client.conv_info(conv).await, self.friends(live).await) {
                    (Ok(info), Ok(friends)) => (info, friends),
                    (Err(error), _) | (_, Err(error)) => {
                        tracing::info!(%conv, %error, "邀请成员要的资料取不到");
                        ui.fail(Some("没有完成"), &said(&error), Some("再试一次"));
                        return;
                    }
                };
            let candidates: Vec<&Friend> = friends
                .iter()
                .filter(|f| !info.members.iter().any(|m| m.uid == f.uid))
                .collect();
            let rows: Vec<Value> = candidates
                .iter()
                .map(|f| person_row(f.uid.as_str(), &f.name, Some(f.detail), None, vec![]))
                .collect();
            ui.step(compact(json!({
                "kind": "list", "caption": "新成员能看到群里以前的全部消息。", "rows": rows,
                "select": { "min": 1, "confirmLabel": "邀请" }, "empty": "好友都已经在群里了。",
                "links": [link("groupLink", "改用群邀请链接")],
            })));
            match next(rx).await {
                None => return,
                Some(Input::Choose {
                    choice, selected, ..
                }) if choice == "confirm" && !selected.is_empty() => {
                    let chosen: Vec<&&Friend> = candidates
                        .iter()
                        .filter(|f| selected.iter().any(|s| s == f.uid.as_str()))
                        .collect();
                    let uids: Vec<Uid> = chosen.iter().map(|f| f.uid.clone()).collect();
                    ui.step(waiting("正在邀请…"));
                    match live.client.invite(conv, &uids).await {
                        Ok(()) => {
                            let me = live.client.name().await;
                            let names = chosen
                                .iter()
                                .map(|f| f.name.as_str())
                                .collect::<Vec<_>>()
                                .join("、");
                            ui.done(
                                Some("已邀请"),
                                Some(&format!("群里所有人都会看到“{me} 邀请 {names} 加入了群”。")),
                            );
                        }
                        Err(error) => {
                            tracing::info!(%conv, %error, "邀请成员没成");
                            ui.fail(Some("没有邀请"), &said(&error), Some("再试一次"));
                        }
                    }
                    return;
                }
                Some(Input::Choose { choice, .. }) if choice == "groupLink" => {
                    let text = match &invite_link {
                        Some(text) => text.clone(),
                        None => {
                            ui.step(waiting("正在生成链接…"));
                            match live.client.create_invite_link(conv).await {
                                Ok(link) => invite_link.insert(link.to_string()).clone(),
                                Err(error) => {
                                    tracing::info!(%conv, %error, "群邀请链接没生成");
                                    ui.fail(Some("没有完成"), &said(&error), Some("再试一次"));
                                    return;
                                }
                            }
                        }
                    };
                    ui.step(json!({
                        "kind": "showText", "layout": "line", "text": text, "copy": true,
                        "caption": "对方在 Cindy IM 的“加好友”里粘贴这条链接就能加入，7 天内有效。链接带着群名，只有拿到链接的人看得到，服务器看不到。",
                        "links": [link("back", "改回勾选好友")],
                    }));
                    loop {
                        match next(rx).await {
                            None => return,
                            Some(Input::Choose { choice, .. }) if choice == "back" => break,
                            Some(_) => {}
                        }
                    }
                }
                Some(_) => {}
            }
        }
    }

    /// 退出群（S13）。
    async fn leave(
        &self,
        live: &Live,
        ui: &Ui<'_>,
        rx: &mut mpsc::UnboundedReceiver<Input>,
        conv: &ConvId,
    ) {
        let group = live
            .conversation(conv)
            .await
            .map(|c| c.name)
            .unwrap_or_else(|_| "群聊".into());
        ui.step(json!({
            "kind": "confirm", "caption": format!("退出「{group}」？"), "danger": true, "confirmLabel": "退出群",
            "text": "退出后读不到群里之后的新消息；以前的消息还在这台电脑上。要回来需要群里的人重新邀请。",
        }));
        loop {
            match next(rx).await {
                None => return,
                Some(Input::Choose { choice, .. }) if choice == "confirm" => break,
                Some(_) => {}
            }
        }
        ui.step(waiting("正在退出…"));
        match live.client.leave(conv).await {
            Ok(()) => ui.done(None, None),
            Err(error) => {
                tracing::info!(%conv, %error, "退群没成");
                ui.fail(Some("没有退出"), &said(&error), Some("再试一次"));
            }
        }
    }
}

/// 关于加密（S17）：服务器看得到什么、看不到什么（第一阶段核对过的实际情况），只有“知道了”。
async fn about(ui: &Ui<'_>, rx: &mut mpsc::UnboundedReceiver<Input>) {
    ui.step(json!({
        "kind": "confirm", "confirmLabel": "知道了", "noCancel": true,
        "sections": [
            { "title": "服务器看不到", "text": "消息、图片、文件和文件名，群名、群头像、群简介，回复的是哪一条，你的头像。只有你们的电脑能解开，运行服务器的人也看不到。" },
            { "title": "服务器看得到", "text": "谁和谁有私聊、每个群有哪些人；每条消息什么时候发的、有多大，撤回了哪一条，文件有多大；你的 Cindy 账号编号和名字；你有几台电脑、电脑的名字、加入和最近在线的时间。邮箱只在登录时经手，不保存。" },
            { "title": "换电脑", "text": "新电脑要由你已登录的电脑批准，或者输入恢复密钥。只登录 Cindy 读不到任何消息。" },
            { "title": "都丢了", "text": "所有电脑和恢复密钥都丢了，以前的消息谁也找不回来。" }
        ],
    }));
    if next(rx).await.is_some() {
        ui.done(None, None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hhh_im_protocol::method::{LoginStep, step_problem};

    #[test]
    fn fingerprints_read_in_two_groups() {
        assert_eq!(fingerprint(&[0x3F, 0x2A, 0x9C, 0x41, 0xFF]), "3F2A 9C41");
    }

    #[test]
    fn device_details_say_when_it_joined_and_was_seen() {
        let day = 86_400_000;
        let joined = 20_736 * day; // 2026-10-10 00:00 UTC
        let device = |online, last_seen_ms| DeviceInfo {
            id: DeviceId::from_raw([1; 16]),
            name: "台式机".into(),
            joined_ms: joined,
            last_seen_ms,
            online,
            kind: friend_im_client::core::wire::DeviceKind::Computer,
        };
        let now = joined + 10 * day;
        assert_eq!(
            device_detail(&device(true, now), now),
            "加入于 2026-10-10 · 在线"
        );
        assert_eq!(
            device_detail(&device(false, now - 30_000), now),
            "加入于 2026-10-10 · 刚刚在线"
        );
        assert_eq!(
            device_detail(&device(false, now - 5 * 60_000), now),
            "加入于 2026-10-10 · 5 分钟前在线"
        );
        assert_eq!(
            device_detail(&device(false, now - 3 * 3_600_000), now),
            "加入于 2026-10-10 · 3 小时前在线"
        );
        assert_eq!(
            device_detail(&device(false, now - 32 * day), now),
            "加入于 2026-10-10 · 32 天前在线"
        );
    }

    // 操作里推的每种步骤照协议、在上限以内（去掉 null 后宿主读得懂）。
    #[test]
    fn action_steps_are_valid_protocol_steps() {
        let rows = vec![person_row(
            "u1",
            "王小明",
            Some("好友 · 身份已核对"),
            Some("群主"),
            vec![json!({ "id": "remove", "label": "移出", "danger": true })],
        )];
        let mut confirm = json!({ "kind": "confirm", "caption": "换一条链接？", "confirmLabel": "换一条", "text": "旧链接会立即失效。" });
        confirm["cancelLabel"] = "取消".into();
        confirm["cancelChoice"] = "back".into();
        for step in [
            compact(
                json!({ "kind": "list", "caption": "选要拉进群的好友（之后还能再邀请）。", "rows": rows,
                "select": { "min": 1, "confirmLabel": "创建" }, "empty": "还没有好友。", "note": null }),
            ),
            compact(
                json!({ "kind": "showText", "layout": "line", "text": "https://im.example.com/f/abc#def", "copy": true,
                "caption": "把这条链接发给想加你的人。", "links": [link("renew", "换一条链接")] }),
            ),
            compact(confirm),
            compact(
                json!({ "kind": "confirm", "caption": "加王小明为好友？", "confirmLabel": "加好友",
                "person": { "name": "王小明", "detail": "身份指纹 3F2A 9C41 · 和链接里的一致" } }),
            ),
        ] {
            let parsed: LoginStep =
                serde_json::from_value(step.clone()).unwrap_or_else(|e| panic!("{e}: {step}"));
            assert_eq!(step_problem(&parsed), None, "{step}");
        }
    }
}
