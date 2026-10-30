//! 推送（protocol-v1 §11）：客户端库推来的更新翻成协议的事件，排进一条队列，由一个任务一批一批推给宿主。
//!
//! - 同一时间只有一批在途：宿主写进本地库、回复了才算送到，才推下一批；出错或 30 秒没回复就隔一会儿原样重推
//!   （宿主按编号去重）。一批至多 500 个事件。
//! - 同步位置（客户端库处理到的日志序号）只随“把队列推空”的那一批带上：宿主存下的位置之前的事件一定都已经存好，
//!   插件重启后从这里接着补，不会跳过没推出去的。
//! - 新会话先推会话本身再推它的消息；自己退群或被移出时推“会话没有了”（宿主只记下，不删本地记录）。
//! - 连接状态（连上、断开重连）当场发 `status` 通知，不排队。
//! - 第三阶段：个人资料不当成消息，记下发送人的头像、推 `people`（[`super::profile`]）；新电脑批准与自己账号的电脑增减交给
//!   [`super::approvals`]（`session/notice` 的待处理行）。

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use friend_im_client::core::ids::{ConvId, MsgId, Uid};
use friend_im_client::core::message::Content;
use friend_im_client::core::wire::DeviceStatus;
use friend_im_client::{AccountNotice, ConvNotice, HistoryItem, Message, Notice, Update, Updates};
use hhh_im_protocol::method::{ConnState, EventsPushParams, SessionExpiredParams, StatusParams};
use hhh_im_protocol::rpc::ReauthReason;
use hhh_im_protocol::types::{Event, Message as Wire, Person, PersonKind};
use tokio::sync::Notify;
use tokio::task::AbortHandle;

use super::Server;
use super::flow::{Input, JoinEvent};
use super::session::Live;
use super::translate;

/// 一批至多几个事件（protocol-v1 §11.1）。
const BATCH_MAX: usize = 500;
/// 撤回推来、原来那条不在最近见过的消息里时，往前翻几页历史找它（每页 100 条）。
const RECALL_SEARCH_PAGES: usize = 5;
/// 回到以前待过的群时，往前翻几页找自己离开的那条（每页 100 条），补推不在的那段。
const REJOIN_BACKFILL_PAGES: usize = 20;

/// 等着推给宿主的事件。
#[derive(Default)]
pub(crate) struct Outbox {
    queue: Mutex<(VecDeque<Event>, Option<u64>)>,
    wake: Notify,
}

impl Outbox {
    pub(crate) fn push(&self, event: Event) {
        self.queue
            .lock()
            .expect("推送队列锁中毒")
            .0
            .push_back(event);
        self.wake.notify_one();
    }

    fn position(&self, log: u64) {
        let mut queue = self.queue.lock().expect("推送队列锁中毒");
        queue.1 = Some(queue.1.map_or(log, |p| p.max(log)));
        drop(queue);
        self.wake.notify_one();
    }

    /// 取下一批：至多 [`BATCH_MAX`] 个事件；这一批把队列取空时带上同步位置（比上次推过的新才带）。
    fn take(&self, sent: Option<u64>) -> Option<(Vec<Event>, Option<u64>)> {
        let mut queue = self.queue.lock().expect("推送队列锁中毒");
        let n = queue.0.len().min(BATCH_MAX);
        let events: Vec<Event> = queue.0.drain(..n).collect();
        let position = queue
            .0
            .is_empty()
            .then_some(queue.1)
            .flatten()
            .filter(|p| sent.is_none_or(|s| *p > s));
        (!events.is_empty() || position.is_some()).then_some((events, position))
    }
}

/// 开始推送：一个任务把更新翻成事件（进 `live` 的队列），一个任务推给宿主。返回两个任务，下线时停掉。
pub(crate) fn start(server: Arc<Server>, live: Arc<Live>, updates: Updates) -> Vec<AbortHandle> {
    let outbox = live.outbox.clone();
    // 上线时已经连着（登录、重置刚做完）就收不到这一次的“连上了”：先看一次重置后退出的群。
    let checking = live.clone();
    tokio::spawn(async move { drop_groups_left_by_reset(&checking).await });
    let translator = tokio::spawn(translate_updates(server.clone(), live, updates));
    let sender = tokio::spawn(send_batches(server, outbox));
    vec![translator.abort_handle(), sender.abort_handle()]
}

/// 推给宿主：一批推完（宿主回复了）才推下一批，失败就退避重推同一批。
async fn send_batches(server: Arc<Server>, outbox: Arc<Outbox>) {
    let mut sent: Option<u64> = None;
    loop {
        outbox.wake.notified().await;
        while let Some((events, position)) = outbox.take(sent) {
            let params = EventsPushParams {
                events,
                sync_state: position.map(|p| p.to_string()),
            };
            let mut delay = server.options.push_retry;
            while let Err(error) = server.peer.request("events/push", &params).await {
                tracing::warn!(
                    ?error,
                    count = params.events.len(),
                    "宿主没收下这批推送，稍后重推"
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(30));
            }
            if position.is_some() {
                sent = position;
            }
        }
    }
}

/// 把客户端库的更新翻成事件，直到客户端停了。
async fn translate_updates(server: Arc<Server>, live: Arc<Live>, mut updates: Updates) {
    let outbox = live.outbox.clone();
    while let Some(update) = updates.recv().await {
        match update {
            Update::FriendRequestsChanged => {
                if server
                    .friend_events
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    server
                        .peer
                        .notify("contacts/requestsChanged", serde_json::json!({}));
                }
            }
            Update::ReadingChanged { conv } => {
                if server
                    .reading_events
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    match live.client.reading_through(&conv).await {
                        Ok(through) => server.peer.notify(
                            "reading/changed",
                            hhh_im_protocol::reading::ReadState {
                                scope: hhh_im_protocol::reading::ReadScope {
                                    conversation_id: conv.to_string(),
                                    thread_root: None,
                                },
                                through: through.map(|p| p.to_string()),
                                read_message_ids: Vec::new(),
                            },
                        ),
                        Err(error) => tracing::warn!(%error,"阅读变更未核实，保留原未读"),
                    }
                }
            }
            Update::Connected { status } => {
                server.peer.notify(
                    "status",
                    StatusParams {
                        state: ConnState::Online,
                        reason: None,
                    },
                );
                if status != DeviceStatus::Active {
                    tracing::warn!(?status, "重连后这台电脑不能用了");
                }
                let live = live.clone();
                tokio::spawn(async move { drop_groups_left_by_reset(&live).await });
            }
            Update::Disconnected => {
                server.peer.notify(
                    "status",
                    StatusParams {
                        state: ConnState::Connecting,
                        reason: Some("和 Cindy IM 服务器断开了，正在重连".into()),
                    },
                );
            }
            Update::Position(log) => outbox.position(log),
            Update::Message(message) => on_message(&live, &outbox, message).await,
            Update::MessageRejected {
                conv,
                id,
                ts_ms,
                sender,
                ..
            } => {
                ensure_conversation(&live, &outbox, &conv).await;
                let names = live.names([sender.clone()]).await;
                let wire = translate::unreadable(conv.as_str(), &id, &sender, ts_ms, &names);
                outbox.push(Event::Messages {
                    conversation_id: conv.to_string(),
                    messages: vec![wire],
                });
            }
            Update::Conv(notice) => {
                // 刚进的会话：发一条个人资料；以前待过、这次是回来的，补推不在的那段（都在后台做，不挡推送）。
                if joined(&live.me, &notice) {
                    let (server, live, conv, log) = (
                        server.clone(),
                        live.clone(),
                        notice.conv.clone(),
                        notice.log,
                    );
                    tokio::spawn(async move {
                        server.announce_to(&live, &conv).await;
                        backfill_rejoined(&live, &conv, log).await;
                    });
                }
                on_notice(&live, &outbox, notice).await;
            }
            Update::ConvRejected { conv, log, reason } => {
                tracing::warn!(%conv, log, %reason, "会话签名链有一环没通过核对，已拒绝");
                let at = crate::server::now_ms();
                outbox.push(Event::Messages {
                    conversation_id: conv.to_string(),
                    messages: vec![translate::conv_rejected(conv.as_str(), log, at)],
                });
            }
            Update::CredentialsChanged => save_credentials(&server, &live).await,
            Update::DeviceRemoved => {
                expire(
                    &server,
                    ReauthReason::Revoked,
                    "这台电脑已被移出你的 Cindy IM 账号，要重新登录。",
                )
                .await;
                return;
            }
            Update::LoggedOut => {
                expire(
                    &server,
                    ReauthReason::Expired,
                    "Cindy IM 的登录已失效，要重新登录。",
                )
                .await;
                return;
            }
            Update::Account { uid, notice, .. } if uid == live.me => match notice {
                AccountNotice::DeviceAdded { name, device }
                    if device != *live.client.device_id() =>
                {
                    server.device_changed(&live, format!("你的账号新增了电脑「{name}」"));
                }
                AccountNotice::DeviceRemoved { name, .. } => {
                    server.device_changed(&live, format!("已移除电脑「{name}」"))
                }
                _ => {}
            },
            // 聊过的人重置账号：会话里的系统提示另外推来（MemberReset），这里不用管。
            Update::Account { .. } | Update::Activated | Update::JoinWrongCode { .. } => {}
            Update::JoinRequested(info) => server.join_requested(&live, info),
            Update::JoinRequests(requests) => server.requests_refreshed(&live, requests),
            Update::JoinApproved { request } => server
                .flows
                .send_to_action(Input::Join(JoinEvent::Approved { request })),
            Update::JoinRetry { request, attempt } => server
                .flows
                .send_to_action(Input::Join(JoinEvent::Retry { request, attempt })),
            Update::JoinClosed { request, reason } => server.join_closed(&live, request, reason),
        }
    }
    tracing::info!("客户端停了，推送结束");
}

/// 新会话：先把会话本身推给宿主（宿主据此加进会话列表）。
async fn ensure_conversation(live: &Live, outbox: &Outbox, conv: &ConvId) {
    if live.knows_conversation(conv) {
        return;
    }
    push_conversation(live, outbox, conv).await;
}

async fn push_conversation(live: &Live, outbox: &Outbox, conv: &ConvId) {
    match live.conversation(conv).await {
        Ok(conversation) => outbox.push(Event::Conversation { conversation }),
        Err(error) => tracing::info!(%conv, %error, "会话资料取不到，先不推会话"),
    }
}

async fn on_message(live: &Live, outbox: &Outbox, message: Message) {
    if let Some(Content::Profile { avatar, photo }) = &message.content {
        // 个人资料不是给人看的消息：记下这个人的头像，变了就告诉宿主（人与私聊会话）。
        let key = super::profile::profile_key(avatar.as_deref(), photo.as_ref());
        profile_seen(live, &message.sender, message.log, key).await;
        return;
    }
    ensure_conversation(live, outbox, &message.conv).await;
    if let Some(Content::Recall { target }) = &message.content {
        if let Some(wire) = recalled(live, &message, target).await {
            outbox.push(Event::Messages {
                conversation_id: message.conv.to_string(),
                messages: vec![wire],
            });
        }
        return;
    }
    let names = live.names(mentioned(&message)).await;
    let Some(wire) = translate::message(&message, &names) else {
        return;
    };
    live.remember(&wire.id, &message.sender, message.ts_ms);
    outbox.push(Event::Messages {
        conversation_id: message.conv.to_string(),
        messages: vec![wire],
    });
}

/// 见到一份个人资料（推来的或翻历史翻到的，头像键见 `profile::profile_key`）：比记下的新、头像变了就推这个人与
/// 和他的私聊。
pub(crate) async fn profile_seen(live: &Live, sender: &Uid, log: u64, key: Option<String>) {
    if *sender == live.me || !live.profiles.note(sender, log, key) {
        return;
    }
    push_person(live, sender).await;
    for conv in live.direct_with(sender) {
        live.forget_conversation(&conv);
        push_conversation(live, &live.outbox, &conv).await;
    }
}

/// 自己的头像换了（宿主交来新头像，契约 provider-protocol v35）：推一条自己的人员资料，宿主换上新头像键。
pub(crate) async fn me_changed(live: &Live) {
    push_person(live, &live.me).await;
}

async fn push_person(live: &Live, uid: &Uid) {
    let names = live.names([uid.clone()]).await;
    let person = Person {
        id: uid.to_string(),
        id_type: None,
        kind: PersonKind::User,
        name: names.get(uid).cloned(),
        avatar: live.avatar_of(uid),
    };
    live.outbox.push(Event::People {
        people: vec![person],
    });
}

/// 一条消息里要显示名字的人：发送人与被提及的人。
pub(crate) fn mentioned(message: &Message) -> Vec<Uid> {
    let mut uids = vec![message.sender.clone()];
    if let Some(Content::Post { parts, .. }) = &message.content {
        uids.extend(parts.iter().filter_map(|p| match p {
            friend_im_client::core::message::Part::Mention { uid: Some(uid), .. } => {
                Some(uid.clone())
            }
            _ => None,
        }));
    }
    uids
}

/// 撤回推来：报原来那条变成“已撤回”（时间与发送人照原来那条，宿主按编号覆盖）。最近没见过就往前翻几页找。
async fn recalled(live: &Live, recall: &Message, target: &MsgId) -> Option<Wire> {
    let found = match live.recalled_from(target.as_str()) {
        Some(found) => Some(found),
        None => search(live, recall, target).await,
    };
    let Some((sender, ts_ms)) = found else {
        tracing::info!(conv = %recall.conv, "撤回的那条往前翻也没找到，等宿主下次读历史时更新");
        return None;
    };
    let names = live.names([sender.clone()]).await;
    Some(translate::recalled(
        recall.conv.as_str(),
        target,
        &sender,
        ts_ms,
        &names,
    ))
}

async fn search(live: &Live, recall: &Message, target: &MsgId) -> Option<(Uid, i64)> {
    let mut before = Some(recall.log);
    for _ in 0..RECALL_SEARCH_PAGES {
        let page = live.client.history(&recall.conv, before, 100).await.ok()?;
        for item in &page.items {
            match item {
                HistoryItem::Message(m) if &m.id == target => {
                    return Some((m.sender.clone(), m.ts_ms));
                }
                HistoryItem::Rejected {
                    id, sender, ts_ms, ..
                } if id == target => return Some((sender.clone(), *ts_ms)),
                _ => {}
            }
        }
        if !page.more {
            return None;
        }
        before = page.items.iter().map(HistoryItem::log).min();
    }
    None
}

/// 重置过账号就退出了所有群（契约 S7）：还记着我旧身份的群推“会话没有了”（宿主只记下，不删本地记录）。每次连上看一次，
/// 推重了无妨。
async fn drop_groups_left_by_reset(live: &Live) {
    match live.client.groups_left_by_reset().await {
        Ok(groups) => {
            for conv in groups {
                live.forget_conversation(&conv);
                live.outbox.push(Event::ConversationRemoved {
                    conversation_id: conv.to_string(),
                });
            }
        }
        Err(error) => tracing::info!(%error, "重置后退出的群没查成，下次连上再看"),
    }
}

/// 这条提示是不是“我离开了这个会话”（自己退群、被移出）。
fn left(me: &Uid, notice: &Notice) -> bool {
    match &notice.change {
        ConvNotice::Left => notice.author == *me,
        ConvNotice::Removed { uid, .. } => uid == me,
        _ => false,
    }
}

/// 回到以前待过的群（被移出或退群后又被邀请、凭链接回来，契约 S12）：宿主本机已有在群期间的消息，只缺不在的那段——
/// 从这次加入往前翻到自己离开的那条，把这段的消息与提示补推给宿主（宿主按编号去重，推重了也不会多一条）。
/// 翻到头也没见自己离开过的，是第一次进：什么也不推，宿主打开会话时自己从头读历史。最多翻 [`REJOIN_BACKFILL_PAGES`] 页。
async fn backfill_rejoined(live: &Live, conv: &ConvId, joined_log: u64) {
    let mut before = Some(joined_log);
    let mut missed = Vec::new();
    for _ in 0..REJOIN_BACKFILL_PAGES {
        let page = match live.client.history(conv, before, 100).await {
            Ok(page) => page,
            Err(error) => {
                tracing::info!(%conv, %error, "回到群里，补推不在的那段时读历史没成");
                return;
            }
        };
        for item in &page.items {
            if let HistoryItem::Notice(notice) = item
                && left(&live.me, notice)
            {
                tracing::info!(%conv, count = missed.len(), "回到群里，补推不在的那段");
                for item in missed.into_iter().rev() {
                    push_history_item(live, conv, item).await;
                }
                return;
            }
            missed.push(item.clone());
        }
        if !page.more {
            return;
        }
        before = page.items.iter().map(HistoryItem::log).min();
    }
    tracing::info!(%conv, "回到群里，往前翻了几页没找到离开的那条，不补推");
}

/// 翻历史翻到的一项照推来的推给宿主：消息、解不开的消息、系统提示。
async fn push_history_item(live: &Live, conv: &ConvId, item: HistoryItem) {
    match item {
        HistoryItem::Message(message) => on_message(live, &live.outbox, message).await,
        HistoryItem::Rejected {
            id, ts_ms, sender, ..
        } => {
            let names = live.names([sender.clone()]).await;
            let wire = translate::unreadable(conv.as_str(), &id, &sender, ts_ms, &names);
            live.outbox.push(Event::Messages {
                conversation_id: conv.to_string(),
                messages: vec![wire],
            });
        }
        HistoryItem::Notice(notice) => {
            let names = live.names(translate::notice_people(&notice)).await;
            if let Some(wire) = translate::notice(&notice, &names, &live.me) {
                live.outbox.push(Event::Messages {
                    conversation_id: conv.to_string(),
                    messages: vec![wire],
                });
            }
        }
    }
}

/// 这条提示是不是“我进了这个会话”（建会话时在成员里、被邀请、凭链接加入）。
fn joined(me: &Uid, notice: &Notice) -> bool {
    match &notice.change {
        ConvNotice::Created { members, .. } | ConvNotice::Added { members } => members.contains(me),
        ConvNotice::JoinedByInvite => notice.author == *me,
        _ => false,
    }
}

/// 会话里的系统提示：会话本身变了就重新推会话（自己离开了就推“会话没有了”），再推这条提示。
async fn on_notice(live: &Live, outbox: &Outbox, notice: Notice) {
    let conv = notice.conv.clone();
    let i_left = left(&live.me, &notice);
    let changed = matches!(
        notice.change,
        ConvNotice::Created { .. }
            | ConvNotice::Added { .. }
            | ConvNotice::JoinedByInvite
            | ConvNotice::ProfileChanged
            | ConvNotice::Left
            | ConvNotice::Removed { .. }
    );
    if changed {
        live.forget_conversation(&conv);
        if !i_left {
            push_conversation(live, outbox, &conv).await;
        }
    } else {
        ensure_conversation(live, outbox, &conv).await;
    }
    let names = live.names(translate::notice_people(&notice)).await;
    if let Some(wire) = translate::notice(&notice, &names, &live.me) {
        outbox.push(Event::Messages {
            conversation_id: conv.to_string(),
            messages: vec![wire],
        });
    }
    if i_left {
        outbox.push(Event::ConversationRemoved {
            conversation_id: conv.to_string(),
        });
    }
}

/// 服务器换发了登录凭证：交给宿主存（借来的凭据不存，到期再说）。头像与“发过的个人资料”照旧带上。
async fn save_credentials(server: &Server, live: &Live) {
    if live.read_only {
        tracing::info!("凭据是借来的，不存新的登录凭证");
        return;
    }
    let device = live.client.credentials().await;
    let credential = {
        let mut current = live.credential.lock().expect("凭据锁中毒");
        current.device = device;
        current.clone()
    };
    if server.save_credential(&credential).await.is_err() {
        tracing::error!("宿主没存下新的登录凭证，下次启动可能要重新登录");
    }
}

/// 这台电脑不能再用了：告诉宿主要重新登录，下线。
async fn expire(server: &Server, reason: ReauthReason, message: &str) {
    tracing::warn!(?reason, "授权失效，下线");
    server.peer.notify(
        "session/expired",
        SessionExpiredParams {
            reason,
            message: message.into(),
        },
    );
    server.close_session().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(n: usize) -> Event {
        Event::ConversationRemoved {
            conversation_id: format!("c{n}"),
        }
    }

    #[test]
    fn batches_carry_the_position_only_when_they_empty_the_queue() {
        let outbox = Outbox::default();
        for n in 0..(BATCH_MAX + 3) {
            outbox.push(event(n));
        }
        outbox.position(40);
        let (first, position) = outbox.take(None).unwrap();
        assert_eq!(
            (first.len(), position),
            (BATCH_MAX, None),
            "队列没推空：不带位置"
        );
        let (rest, position) = outbox.take(None).unwrap();
        assert_eq!((rest.len(), position), (3, Some(40)));
        assert!(outbox.take(Some(40)).is_none(), "推过的位置不再推");
        outbox.position(41);
        assert_eq!(
            outbox.take(Some(40)).map(|(e, p)| (e.len(), p)),
            Some((0, Some(41))),
            "只有位置往前走了也推一次"
        );
        outbox.position(39);
        assert!(outbox.take(Some(41)).is_none(), "位置不往回退");
    }
}
