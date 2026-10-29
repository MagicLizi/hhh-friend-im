//! 用 Cindy 账号登录（provider-protocol v13 §3.1，契约 S1、S2、S3、S7、S18、S20–S23）：宿主在 `login/start` 里给 Cindy 令牌与
//! 账号，插件生成这台电脑的钥匙、用令牌连服务器，然后按账号的情况走：
//!
//! - 账号还没开通（第一台电脑）：开通 → 存凭据 → 出示恢复密钥（不能跳过）→ 完成（“Cindy IM 已开通”）。先存再出示：开通后
//!   这台电脑已在账号里，即使没点完成也不会留下一个没人能进的账号；恢复密钥之后在“我的电脑”里能重新生成。
//! - 开通过、这台是新电脑：出示 4 个词等旧电脑批准，说明里写具体去哪台（服务器随请求交回已登录的电脑，契约 v3）；
//!   一台都不在线时先说清楚、恢复密钥放主按钮。可改用恢复密钥，或都没有了只能重置。批准、加入、重置完成后存凭据、
//!   完成。拒绝、超时、输错 5 次以失败结束（能重试：重新请求）。
//!
//! 令牌只在这一次连服务器时用，不进日志、不存；之后用服务器发的登录凭证（存在凭据里）。

use std::sync::Arc;

use friend_im_client::core::wire::{DeviceInfo, DeviceKind, DeviceStatus, JoinCloseReason};
use friend_im_client::{Client, Config, Credentials, Update, Updates};
use hhh_im_protocol::budget::STEP_PIECE_MAX_CHARS;
use hhh_im_protocol::method::{HostAccount, LoginKind, LoginStartParams, LoginStartResult, login_value};
use hhh_im_protocol::rpc::{ErrorKind, RpcError, RpcId};
use hhh_im_protocol::types::Account;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::actions::device_detail;
use super::flow::{Input, Kind, Ui, compact, link, note, recovery_key, wait_confirm, waiting};
use super::{Server, errors};
use crate::credential::Credential;

/// 声明的登录方式编号。
pub(crate) const HOST_METHOD: &str = "cindy";

/// 出示 4 个词时的老说法：服务器没给已登录电脑的名单（旧服务器，契约 v3 S2g）。
const PLAIN_CAPTION: &str = "这个账号已经在别的电脑上用过。到一台已登录 Cindy IM 的电脑上，在弹出的“批准新电脑”里输入下面 4 个词：";

/// 一台都不在线时至多列几台（契约 v3 S2f），多出来的写一行“还有 N 台”。
const OFFLINE_SHOWN_MAX: usize = 5;

/// 新电脑等批准时怎么说（契约 v3 S2）：按服务器随批准请求交回的已登录电脑名单选。
struct Approval {
    /// 出示 4 个词时的说明：有电脑在线写去哪台（S2a），都不在线写打开哪台（S2c），没有名单照旧（S2g）。
    caption: String,
    /// 一台都不在线：出示 4 个词之前先说清楚、恢复密钥放主按钮的一步（S2b）。
    offline: Option<Value>,
}

impl Approval {
    /// `this_name` 是这台电脑的名字（名单里同名的多写一句）；`now` 按服务器的钟。
    fn of(devices: Option<&[DeviceInfo]>, this_name: &str, this_kind: DeviceKind, now: i64) -> Self {
        let Some(devices) = devices else {
            return Self { caption: if this_kind == DeviceKind::Computer { PLAIN_CAPTION.into() } else { PLAIN_CAPTION.replace("电脑", "设备") }, offline: None };
        };
        let mut online: Vec<&str> = Vec::new();
        for device in devices.iter().filter(|d| d.online) {
            if !online.contains(&device.name.as_str()) {
                online.push(&device.name);
            }
        }
        if !online.is_empty() {
            return Self { caption: online_caption(&online, this_kind), offline: None };
        }
        Self { caption: wait_caption(devices, this_kind), offline: Some(offline_step(devices, this_name, this_kind, now)) }
    }
}

/// 有电脑在线（S2a）：“到「A」或「B」上，在弹出的……”。名字多到一段话放不下时只写放得下的几台，加“等 N 台电脑中的一台”。
fn online_caption(names: &[&str], this_kind: DeviceKind) -> String {
    let tail = if this_kind == DeviceKind::Computer { "上，在弹出的“批准新电脑”里输入下面 4 个词：" } else { "上，在弹出的“批准新设备”里输入下面 4 个词：" };
    let quoted: Vec<String> = names.iter().map(|name| format!("「{name}」")).collect();
    let all = format!("到{}{}", quoted.join("或"), tail);
    if all.chars().count() <= STEP_PIECE_MAX_CHARS {
        return all;
    }
    // 电脑名至多 64 个字，至少一台总放得下。
    let noun = if this_kind == DeviceKind::Computer { "电脑" } else { "设备" };
    (1..quoted.len())
        .rev()
        .map(|shown| format!("到{}等 {} 台{noun}中的一台{}", quoted[..shown].join("、"), names.len(), tail))
        .find(|caption| caption.chars().count() <= STEP_PIECE_MAX_CHARS)
        .unwrap_or(all)
}

/// 都不在线、选了等它上线（S2c）：打开那台的 Friend 会弹出批准。
fn wait_caption(devices: &[DeviceInfo], this_kind: DeviceKind) -> String {
    let phrase = if this_kind == DeviceKind::Computer { "批准新电脑" } else { "批准新设备" };
    match devices {
        [] => PLAIN_CAPTION.into(),
        [only] => format!("打开「{}」上的 Friend，会弹出“{phrase}”，在里面输入下面 4 个词：", only.name),
        _ => format!("打开其中一台的 Friend，会弹出“{phrase}”，在里面输入下面 4 个词："),
    }
}

/// 一台都不在线（S2b、S2b′、S2f）：逐台列名字与“加入于 … · … 在线”，最近在线的在前，至多 5 台；和这台同名的多写一句。
/// 主按钮改用恢复密钥，左边按钮等它上线，下面一行重置。账号里一台都没有（都退出了）时不给“等它上线”。
fn offline_step(devices: &[DeviceInfo], this_name: &str, this_kind: DeviceKind, now: i64) -> Value {
    let lost = link("lost", if this_kind == DeviceKind::Computer { "旧电脑和恢复密钥都没有了" } else { "其它设备和恢复密钥都没有了" });
    if devices.is_empty() {
        return json!({
            "kind": "confirm", "caption": if this_kind == DeviceKind::Computer { "这个账号现在没有已登录的电脑" } else { "这个账号现在没有已登录的设备" }, "text": "输入开通时保存的恢复密钥就能加入。",
            "confirmLabel": "改用恢复密钥", "links": [lost],
        });
    }
    let mut recent: Vec<&DeviceInfo> = devices.iter().collect();
    recent.sort_by_key(|d| std::cmp::Reverse(d.last_seen_ms));
    let this_name = this_name.trim().to_lowercase();
    let mut sections: Vec<Value> = recent
        .iter()
        .take(OFFLINE_SHOWN_MAX)
        .map(|device| {
            let mut text = device_detail(device, now);
            if device.name.trim().to_lowercase() == this_name {
                text.push_str(if this_kind == DeviceKind::Computer { " · 和这台电脑同名" } else { " · 和这台设备同名" });
            }
            json!({ "title": device.name, "text": text })
        })
        .collect();
    let rest = devices.len().saturating_sub(OFFLINE_SHOWN_MAX);
    if rest > 0 {
        sections.push(json!({ "title": format!("还有 {rest} 台"), "text": "更早在线的没有列出" }));
    }
    let whom = if devices.len() == 1 { "打开它的 Friend" } else if this_kind == DeviceKind::Computer { "打开其中一台的 Friend" } else { "打开其中一台设备上的 Friend" };
    let caption = if this_kind == DeviceKind::Computer { "你的其它电脑现在都不在线" } else { "你的其它设备现在都不在线" };
    json!({
        "kind": "confirm", "caption": caption, "sections": sections,
        "text": format!("{whom} 就能批准，也可以输入开通时保存的恢复密钥。"),
        "confirmLabel": "改用恢复密钥", "cancelLabel": "等它上线批准", "cancelChoice": "wait", "links": [lost],
    })
}

/// 这台电脑的名字（“我的电脑”里显示）：系统给的电脑名；拿不到时用“<名字>的电脑”。至多 64 个字。
pub(crate) fn device_kind() -> DeviceKind {
    if cfg!(target_arch = "wasm32") { DeviceKind::Mobile } else { DeviceKind::Computer }
}

pub(crate) fn device_name(account_name: &str) -> String {
    let system = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).ok().filter(|n| !n.trim().is_empty());
    let name = system.unwrap_or_else(|| match device_kind() {
        DeviceKind::Computer => format!("{account_name}的电脑"),
        DeviceKind::Mobile => format!("{account_name}的移动设备"),
        DeviceKind::Unknown => format!("{account_name}的设备"),
    });
    name.chars().take(64).collect()
}

/// 这次登录要用的：令牌、账号、服务器。
struct Start {
    token: String,
    account: HostAccount,
    server: String,
}

impl Server {
    /// `login/start`：只认“用 Cindy 账号登录”；开一个登录流程，先回流程编号再推第一步（回 `None`：已经回过了）。
    pub(crate) fn login_start(self: &Arc<Self>, id: &RpcId, params: LoginStartParams) -> Option<Result<serde_json::Value, RpcError>> {
        if params.method.as_deref().is_some_and(|m| m != HOST_METHOD) {
            return Some(Err(errors::of(ErrorKind::InvalidRequest, "Cindy IM 只能用 Cindy 账号登录。")));
        }
        let token = params.values.get(login_value::HOST_TOKEN).cloned().filter(|t| !t.is_empty());
        let (flow_id, rx) = self.flows.begin(Kind::Login);
        let result = LoginStartResult { flow_id: flow_id.clone() };
        self.peer.respond(id.clone(), Ok(serde_json::to_value(result).expect("结果总能写成 JSON")));
        let (Some(token), Some(account)) = (token, params.host_account) else {
            // 宿主没给令牌（游客，或不是官方签名的 Cindy IM）：这次登录当场失败。
            tracing::warn!("开始登录时宿主没给 Cindy 令牌或账号");
            let ui = Ui { peer: &self.peer, flow_id: flow_id.clone(), kind: Kind::Login };
            ui.fail(Some("没能登录"), "先登录 Cindy：Cindy IM 用 Friend 现在登录的 Cindy 账号登录。", None);
            self.flows.end(&flow_id);
            return None;
        };
        tracing::info!(token_chars = token.len(), "用 Cindy 账号登录 Cindy IM");
        let start = Start { token, account, server: self.server_url() };
        let (server, id) = (self.clone(), flow_id.clone());
        tokio::spawn(async move {
            let ui = Ui { peer: &server.peer, flow_id: id.clone(), kind: Kind::Login };
            server.clone().run_login(&ui, start, rx).await;
            server.flows.end(&id);
        });
        None
    }

    async fn run_login(self: Arc<Self>, ui: &Ui<'_>, start: Start, mut rx: mpsc::UnboundedReceiver<Input>) {
        ui.step(waiting("正在连接 Cindy IM…"));
        let name = device_name(&start.account.name);
        let kind = device_kind();
        let config = Config { server: start.server.clone(), device_name: name.clone() };
        let (client, mut updates) = match Client::connect(config, Credentials::generate(), Some(start.token), None).await {
            Ok(connected) => connected,
            Err(error) => {
                tracing::info!(%error, "用 Cindy 账号连 Cindy IM 服务器没成");
                ui.fail(Some("没能登录"), &format!("连不上 Cindy IM 服务器：{error}"), Some("再试一次"));
                return;
            }
        };
        let avatar = start.account.avatar_url.clone();
        let new_credential = |client_credentials: Credentials| {
            Credential::new(&start.server, client.uid().as_str(), &name, client_credentials).with_avatar(avatar.as_deref())
        };
        let finished = match client.status().await {
            DeviceStatus::Unprovisioned => self.provision(ui, &client, &mut rx, &new_credential).await,
            DeviceStatus::Pending => self.join(ui, &client, &name, kind, &mut updates, &mut rx, &new_credential).await,
            DeviceStatus::Active => {
                // 服务器认得这台电脑的钥匙且已可用（不会发生：钥匙刚生成），照常存凭据上线。
                let credential = new_credential(client.credentials().await);
                match self.save_credential(&credential).await {
                    Ok(()) => Some((credential, None)),
                    Err(reason) => {
                        ui.fail(Some("没能登录"), &reason, Some("再试一次"));
                        None
                    }
                }
            }
        };
        let Some((credential, texts)) = finished else {
            client.close();
            return;
        };
        let account: Account = self.go_live(client, updates, credential, false).await;
        let (title, message) = texts.unzip();
        self.peer.notify(
            "login/finished",
            compact(json!({ "flowId": ui.flow_id, "account": account, "title": title, "message": message })),
        );
        tracing::info!("Cindy IM 登录完成");
    }

    /// 第一台电脑：开通、存凭据、出示恢复密钥。
    async fn provision(
        &self,
        ui: &Ui<'_>,
        client: &Client,
        rx: &mut mpsc::UnboundedReceiver<Input>,
        new_credential: &(dyn Fn(Credentials) -> Credential + Sync),
    ) -> Option<(Credential, Option<(&'static str, &'static str)>)> {
        ui.step(waiting("正在开通…"));
        let key = match client.provision().await {
            Ok(key) => key,
            Err(error) => {
                tracing::info!(%error, "开通没成");
                ui.fail(Some("没能开通"), &format!("开通 Cindy IM 没成：{error}"), Some("再试一次"));
                return None;
            }
        };
        let credential = new_credential(client.credentials().await);
        if let Err(reason) = self.save_credential(&credential).await {
            ui.fail(Some("没能开通"), &reason, Some("再试一次"));
            return None;
        }
        ui.step(recovery_key(
            "Cindy IM 已开通。这是你的恢复密钥：所有电脑都丢了时，只有它能找回聊天记录。它只显示这一次，请抄在纸上，或存进密码管理器。",
            &key.to_words(),
        ));
        // 宿主关掉、断了也往下走：凭据已经存好。
        wait_confirm(rx).await;
        Some((credential, Some(("Cindy IM 已开通", "以后在别的电脑上登录同一个 Cindy 账号，用这台电脑批准，就能看到全部聊天记录。"))))
    }

    /// 新电脑：等旧电脑批准，或改用恢复密钥，或重置。`name` 是这台电脑的名字。
    #[allow(clippy::too_many_arguments)] // 同一登录流程的输入与凭据回调保持原有边界。
    async fn join(
        &self,
        ui: &Ui<'_>,
        client: &Client,
        name: &str,
        kind: DeviceKind,
        updates: &mut Updates,
        rx: &mut mpsc::UnboundedReceiver<Input>,
        new_credential: &(dyn Fn(Credentials) -> Credential + Sync),
    ) -> Option<(Credential, Option<(&'static str, &'static str)>)> {
        enum Mode {
            Approve,
            Recovery,
            Reset,
        }
        let mut mode = Mode::Approve;
        loop {
            match mode {
                Mode::Approve => {
                    // 每次回到这里都重新发起：重新问一次服务器哪台在线（契约 v3 S2d、S2e）。
                    let started = match client.join_start().await {
                        Ok(started) => started,
                        Err(error) => {
                            tracing::info!(%error, "发起批准请求没成");
                            ui.fail(Some("没能请求批准"), &format!("发起批准请求没成：{error}"), Some("再试一次"));
                            return None;
                        }
                    };
                    let code = started.code;
                    let approval = Approval::of(started.devices.as_deref(), name, kind, started.now_ms);
                    tracing::info!(
                        devices = ?started.devices.as_ref().map(Vec::len),
                        online = ?started.devices.as_ref().map(|d| d.iter().filter(|d| d.online).count()),
                        "已请求批准"
                    );
                    let code_step = |warn: Option<&str>| {
                        compact(json!({
                            "kind": "showText", "layout": "code", "text": code.as_str(), "cancelLabel": "取消",
                            "caption": approval.caption,
                            "waiting": "等待批准…（10 分钟内有效）",
                            "note": warn.map(|text| note(text, true)),
                            "links": [link("useKey", "改用恢复密钥"), link("lost", "旧电脑和恢复密钥都没有了")],
                        }))
                    };
                    ui.step(approval.offline.clone().unwrap_or_else(|| code_step(None)));
                    mode = loop {
                        tokio::select! {
                            input = rx.recv() => match input {
                                None | Some(Input::Cancel) => {
                                    let _ = client.join_cancel().await;
                                    return None;
                                }
                                // 都不在线那一步的主按钮（“改用恢复密钥”）与 4 个词下面的链接是同一条路。
                                Some(Input::Choose { choice, .. }) if choice == "useKey" || choice == "confirm" => {
                                    let _ = client.join_cancel().await;
                                    break Mode::Recovery;
                                }
                                // 都不在线那一步的左边按钮：等它上线批准，出示 4 个词（S2c）。
                                Some(Input::Choose { choice, .. }) if choice == "wait" => {
                                    ui.step(code_step(None));
                                }
                                Some(Input::Choose { choice, .. }) if choice == "lost" => {
                                    let _ = client.join_cancel().await;
                                    break Mode::Reset;
                                }
                                Some(_) => {}
                            },
                            update = updates.recv() => match update {
                                None => {
                                    ui.fail(Some("没能登录"), "和 Cindy IM 服务器断开了。", Some("重新请求"));
                                    return None;
                                }
                                Some(Update::JoinWrongCode { .. }) => {
                                    ui.step(code_step(Some("那台电脑输入的和这里的不一致，请在那台电脑上再输一次。")));
                                }
                                Some(Update::JoinClosed { reason, .. }) => match reason {
                                    JoinCloseReason::Approved => {
                                        ui.step(waiting("已批准，正在取回钥匙…"));
                                        if !wait_active(updates).await {
                                            ui.fail(Some("没能登录"), "批准了，但这台电脑没能取回钥匙。", Some("重新请求"));
                                            return None;
                                        }
                                        return self.saved(ui, client, new_credential, ("这台电脑已加入", "会话列表马上出现，历史消息在后台补齐。你的其它电脑也会收到提醒。")).await;
                                    }
                                    JoinCloseReason::Rejected => {
                                        ui.fail(Some("没有批准"), "那台电脑拒绝了这次请求。如果不是你本人在操作，可能有人登录了你的 Cindy 账号，请尽快修改 Cindy 密码。", Some("重新请求"));
                                        return None;
                                    }
                                    JoinCloseReason::Expired => {
                                        ui.fail(Some("没有批准"), "10 分钟内没有电脑批准。可以重新请求，或改用恢复密钥。", Some("重新请求"));
                                        return None;
                                    }
                                    JoinCloseReason::TooManyAttempts => {
                                        ui.fail(Some("请求已作废"), "那台电脑连续 5 次输入的都和这里的不一致，这次请求已作废。可以重新请求，或改用恢复密钥。", Some("重新请求"));
                                        return None;
                                    }
                                    JoinCloseReason::Cancelled => {}
                                },
                                Some(_) => {}
                            },
                        }
                    };
                }
                Mode::Recovery => {
                    let key_step = |warn: Option<&str>| {
                        compact(json!({
                            "kind": "input", "caption": "输入开通时保存的恢复密钥。",
                            "fields": [{ "id": "key", "label": "恢复密钥", "secret": false, "placeholder": "12 个词，用空格隔开" }],
                            "submitLabel": "加入", "note": warn.map(|text| note(text, true)),
                            "links": [link("back", "改用旧电脑批准")],
                        }))
                    };
                    ui.step(key_step(None));
                    mode = loop {
                        match rx.recv().await {
                            None | Some(Input::Cancel) => return None,
                            Some(Input::Choose { choice, .. }) if choice == "back" => break Mode::Approve,
                            Some(Input::Submit(values)) => {
                                let text = values.get("key").map(String::as_str).unwrap_or_default();
                                ui.step(waiting("正在核对恢复密钥…"));
                                match client.join_with_recovery(text).await {
                                    Ok(()) => {
                                        return self.saved(ui, client, new_credential, ("这台电脑已加入", "会话列表马上出现，历史消息在后台补齐。你的其它电脑也会收到提醒。")).await;
                                    }
                                    Err(error) => {
                                        tracing::info!(%error, "用恢复密钥加入没成");
                                        ui.step(key_step(Some("恢复密钥不对，或已经换过。再核对一下。")));
                                    }
                                }
                            }
                            Some(_) => {}
                        }
                    };
                }
                Mode::Reset => {
                    ui.step(json!({
                        "kind": "confirm", "caption": "只能重置账号。重置后：", "danger": true, "confirmLabel": "重置账号",
                        "sections": [
                            { "title": "以前的消息", "text": "全部读不出来，谁也找不回。" },
                            { "title": "群", "text": "你会退出所有群，需要群里的人重新邀请你。" },
                            { "title": "好友", "text": "好友还在。他们和你的私聊里会出现“你重置了账号”的提示。" }
                        ],
                        "links": [link("back", "改用旧电脑批准")],
                    }));
                    match rx.recv().await {
                        Some(Input::Choose { choice, .. }) if choice == "confirm" => {}
                        Some(Input::Choose { choice, .. }) if choice == "back" => {
                            mode = Mode::Approve;
                            continue;
                        }
                        _ => return None,
                    }
                    ui.step(waiting("正在重置账号…"));
                    let key = match client.reset().await {
                        Ok(key) => key,
                        Err(error) => {
                            tracing::info!(%error, "重置没成");
                            ui.fail(Some("没能重置"), &format!("重置账号没成：{error}"), Some("再试一次"));
                            return None;
                        }
                    };
                    let credential = new_credential(client.credentials().await);
                    if let Err(reason) = self.save_credential(&credential).await {
                        ui.fail(Some("没能重置"), &reason, Some("再试一次"));
                        return None;
                    }
                    ui.step(recovery_key("账号已重置。这是新的恢复密钥，只显示这一次，请保存好。", &key.to_words()));
                    wait_confirm(rx).await;
                    return Some((credential, Some(("账号已重置", "可以继续用了。如果还有别的电脑登录着，它们会被移出，需要重新批准。"))));
                }
            }
        }
    }

    /// 这台电脑可用了：存凭据。
    async fn saved(
        &self,
        ui: &Ui<'_>,
        client: &Client,
        new_credential: &(dyn Fn(Credentials) -> Credential + Sync),
        texts: (&'static str, &'static str),
    ) -> Option<(Credential, Option<(&'static str, &'static str)>)> {
        let credential = new_credential(client.credentials().await);
        match self.save_credential(&credential).await {
            Ok(()) => Some((credential, Some(texts))),
            Err(reason) => {
                ui.fail(Some("没能登录"), &reason, Some("再试一次"));
                None
            }
        }
    }
}

/// 等客户端库说这台电脑可用了（批准后取回钥匙）；客户端停了为假。
async fn wait_active(updates: &mut Updates) -> bool {
    while let Some(update) = updates.recv().await {
        if matches!(update, Update::Activated) {
            return true;
        }
    }
    false
}

/// 声明的登录方式。
pub(crate) fn login_methods() -> Vec<hhh_im_protocol::method::LoginMethod> {
    vec![hhh_im_protocol::method::LoginMethod {
        id: HOST_METHOD.into(),
        kind: LoginKind::Host,
        label: "用 Cindy 账号登录".into(),
        note: "用 Friend 现在登录的 Cindy 账号登录 Cindy IM，不用注册，也不要邀请码。".into(),
        placeholder: None,
        default_value: None,
        id_label: None,
        id_placeholder: None,
        secret_label: None,
        secret_placeholder: None,
        secret_help: None,
        callback_path: None,
        callback_help: None,
        create_link: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use hhh_im_protocol::method::{LoginStep, step_problem};

    #[test]
    fn device_names_are_bounded() {
        let name = device_name("李子");
        assert!(!name.is_empty() && name.chars().count() <= 64);
    }

    // 登录里推的步骤照协议、在上限以内。
    #[test]
    fn login_steps_are_valid_protocol_steps() {
        for step in [
            waiting("正在开通…"),
            compact(json!({
                "kind": "showText", "layout": "code", "text": "orbit maple tunnel crisp", "cancelLabel": "取消",
                "caption": "到一台已登录 Cindy IM 的电脑上输入下面 4 个词：", "waiting": "等待批准…（10 分钟内有效）", "note": null,
                "links": [link("useKey", "改用恢复密钥"), link("lost", "旧电脑和恢复密钥都没有了")],
            })),
            compact(json!({
                "kind": "input", "caption": "输入开通时保存的恢复密钥。",
                "fields": [{ "id": "key", "label": "恢复密钥", "secret": false }], "submitLabel": "加入",
                "note": note("恢复密钥不对，或已经换过。再核对一下。", true), "links": [link("back", "改用旧电脑批准")],
            })),
        ] {
            assert_valid(&step);
        }
        assert_eq!(login_methods()[0].kind, LoginKind::Host);
    }

    fn assert_valid(step: &Value) {
        let parsed: LoginStep = serde_json::from_value(step.clone()).unwrap_or_else(|e| panic!("{e}: {step}"));
        assert_eq!(step_problem(&parsed), None, "{step}");
    }

    const DAY: i64 = 86_400_000;
    /// 2026-10-15 00:00（UTC+8）。
    const NOW: i64 = 1_791_993_600_000;

    fn device(name: &str, online: bool, seen_days_ago: i64) -> DeviceInfo {
        DeviceInfo {
            id: friend_im_client::core::ids::DeviceId::random(),
            name: name.into(),
            joined_ms: NOW - 3 * DAY,
            last_seen_ms: NOW - seen_days_ago * DAY,
            online,
            kind: DeviceKind::Computer,
        }
    }

    fn titles(step: &Value) -> Vec<String> {
        step["sections"].as_array().unwrap().iter().map(|s| s["title"].as_str().unwrap().to_owned()).collect()
    }

    // S2g：旧服务器没给名单，照旧出示 4 个词与原来的说明。
    #[test]
    fn without_a_list_the_old_wording_stays() {
        let approval = Approval::of(None, "TEST-B", DeviceKind::Computer, NOW);
        assert_eq!(approval.caption, PLAIN_CAPTION);
        assert!(approval.offline.is_none());
    }

    // S2a：有电脑在线，说明写具体的电脑；几台在线用“或”连起来，同名只写一次，不在线的不写。
    #[test]
    fn online_computers_are_named_in_the_caption() {
        let one = Approval::of(Some(&[device("MAGICLIZI", true, 0), device("旧笔记本", false, 9)]), "TEST-B", DeviceKind::Computer, NOW);
        assert_eq!(one.caption, "到「MAGICLIZI」上，在弹出的“批准新电脑”里输入下面 4 个词：");
        assert!(one.offline.is_none());
        let two = Approval::of(Some(&[device("MAGICLIZI", true, 0), device("LIZI", true, 0), device("LIZI", true, 0)]), "TEST-B", DeviceKind::Computer, NOW);
        assert_eq!(two.caption, "到「MAGICLIZI」或「LIZI」上，在弹出的“批准新电脑”里输入下面 4 个词：");
    }

    #[test]
    fn mobile_devices_use_device_wording_in_approval_steps() {
        let approval = Approval::of(Some(&[device("Lizi iPhone", true, 0)]), "THIS PHONE", DeviceKind::Mobile, NOW);
        assert_eq!(approval.caption, "到「Lizi iPhone」上，在弹出的“批准新设备”里输入下面 4 个词：");
        let offline = Approval::of(Some(&[device("Lizi Mac", false, 1)]), "THIS PHONE", DeviceKind::Mobile, NOW).offline.unwrap();
        assert_eq!(offline["caption"], "你的其它设备现在都不在线");
        assert_eq!(offline["links"][0], json!(link("lost", "其它设备和恢复密钥都没有了")));
    }

    // 名字多到一段话放不下：只写放得下的几台，加“等 N 台”，仍在协议上限以内。
    #[test]
    fn many_long_online_names_stay_within_the_limit() {
        let long: Vec<DeviceInfo> = (0..6).map(|i| device(&format!("{i}{}", "长".repeat(63)), true, 0)).collect();
        let caption = Approval::of(Some(&long), "TEST-B", DeviceKind::Computer, NOW).caption;
        assert!(caption.chars().count() <= STEP_PIECE_MAX_CHARS, "{caption}");
        assert!(caption.contains("等 6 台电脑中的一台上"), "{caption}");
    }

    // S2b、S2b′、S2c：一台都不在线，先说清楚；和这台同名的多写一句；左边按钮等它上线，出示 4 个词时说打开哪台。
    #[test]
    fn all_offline_comes_first_with_the_recovery_key_as_the_main_button() {
        let ghosts = [device("MAGICLIZI", false, 2), device("magiclizi", false, 1)];
        let approval = Approval::of(Some(&ghosts), "MAGICLIZI", DeviceKind::Computer, NOW);
        let step = approval.offline.clone().unwrap();
        assert_valid(&step);
        assert_eq!(step["caption"], "你的其它电脑现在都不在线");
        assert_eq!(step["sections"][0]["title"], "magiclizi", "最近在线的在前");
        assert_eq!(step["sections"][0]["text"], "加入于 2026-10-12 · 1 天前在线 · 和这台电脑同名");
        assert_eq!(step["sections"][1]["text"], "加入于 2026-10-12 · 2 天前在线 · 和这台电脑同名");
        assert_eq!(step["text"], "打开其中一台的 Friend 就能批准，也可以输入开通时保存的恢复密钥。");
        assert_eq!((step["confirmLabel"].as_str(), step["cancelLabel"].as_str(), step["cancelChoice"].as_str()), (Some("改用恢复密钥"), Some("等它上线批准"), Some("wait")));
        assert_eq!(step["links"], json!([link("lost", "旧电脑和恢复密钥都没有了")]));
        assert_eq!(approval.caption, "打开其中一台的 Friend，会弹出“批准新电脑”，在里面输入下面 4 个词：");

        let one = Approval::of(Some(&[device("办公室电脑", false, 0)]), "TEST-B", DeviceKind::Computer, NOW);
        let step = one.offline.unwrap();
        assert_eq!(step["sections"][0]["text"], "加入于 2026-10-12 · 刚刚在线", "不同名不多写");
        assert_eq!(step["text"], "打开它的 Friend 就能批准，也可以输入开通时保存的恢复密钥。");
        assert_eq!(one.caption, "打开「办公室电脑」上的 Friend，会弹出“批准新电脑”，在里面输入下面 4 个词：");
    }

    // S2f：6 台以上只列最近在线的 5 台，加一行“还有 N 台”。
    #[test]
    fn a_long_list_shows_the_five_most_recent() {
        let many: Vec<DeviceInfo> = (0..7).map(|i| device(&format!("电脑{i}"), false, 7 - i)).collect();
        let step = Approval::of(Some(&many), "TEST-B", DeviceKind::Computer, NOW).offline.unwrap();
        assert_valid(&step);
        assert_eq!(titles(&step), ["电脑6", "电脑5", "电脑4", "电脑3", "电脑2", "还有 2 台"]);
        assert_eq!(step["sections"][5]["text"], "更早在线的没有列出");
    }

    // 账号里一台都没有（都退出了）：只能用恢复密钥或重置，不给“等它上线”。
    #[test]
    fn no_computers_left_offers_only_the_recovery_key_and_reset() {
        let step = Approval::of(Some(&[]), "TEST-B", DeviceKind::Computer, NOW).offline.unwrap();
        assert_valid(&step);
        assert_eq!(step["caption"], "这个账号现在没有已登录的电脑");
        assert_eq!(step["confirmLabel"], "改用恢复密钥");
        assert!(step.get("cancelChoice").is_none());
    }
}
