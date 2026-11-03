//! 会话（protocol-v1 §4.2、§6）：用 HHH 交还的凭据连上服务器，在线期间的客户端、名字与会话资料的缓存，退出与下线。
//!
//! 没有凭据、凭据失效、换了服务器地址时都回 `needsLogin`：宿主随即用 Cindy 账号自动登录（第三阶段，见 [`super::login`]）。
//! 登录与重新打开都经 [`Server::go_live`] 上线，在线后补上待批准的新电脑（[`super::approvals`]）、发个人资料（[`super::profile`]）。

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use friend_im_client::core::conv::ConvKind;
use friend_im_client::core::ids::{ConvId, Uid};
use friend_im_client::core::wire::{DeviceStatus, ErrorCode, JoinRequestInfo};
use friend_im_client::{Client, ClientError, Config, Updates};
use hhh_im_protocol::method::{NeedsLoginReason, SessionOpenParams, SessionOpenResult};
use hhh_im_protocol::rpc::{ErrorKind, RpcError};
use hhh_im_protocol::types::{Account, Conversation, ConversationKind};
use serde_json::Value;
use tokio::task::AbortHandle;

use super::declare::{DEFAULT_SERVER, SETTING_SERVER};
use super::profile::Profiles;
use super::translate::Names;
use super::{Server, errors, push};
use crate::credential::{self, Credential};

/// 名字、会话资料缓存的条数上限：满了整个清空、按需重取（1000 个账号的规模下很少发生）。
const CACHE_MAX: usize = 4096;
/// 电脑增减的提醒至多留几条（契约 S4）。
pub(crate) const DEVICE_NOTES_MAX: usize = 5;

/// 在线的账号。
pub(crate) struct Live {
    pub(crate) client: Client,
    pub(crate) me: Uid,
    /// 是否借来的凭据（不能存新的）。
    pub(crate) read_only: bool,
    /// 现在的凭据（存新登录凭证、记“个人资料发过了”时在它上面改）。
    pub(crate) credential: Mutex<Credential>,
    /// 收到的个人资料（别人的头像）。
    pub(crate) profiles: Profiles,
    /// 宿主交来的本机用户头像（与 [`super::Server`] 共用一份，重新上线也在）。
    pub(crate) photo: Arc<std::sync::Mutex<Option<super::profile::HostPhoto>>>,
    /// 在等批准的新电脑：请求编号 → 请求（旧电脑这边，契约 S2）。
    pub(crate) requests: Mutex<BTreeMap<String, JoinRequestInfo>>,
    /// 电脑增减的提醒（契约 S4）：（编号，文字），看过“我的电脑”就拿掉。
    pub(crate) device_notes: Mutex<Vec<(u64, String)>>,
    /// 等着推给宿主的事件（推送任务与翻历史时认识的人都往这里放）。
    pub(crate) outbox: Arc<push::Outbox>,
    /// 设备之间同步。
    pub(crate) devices: super::devices::Devices,
    names: Mutex<Names>,
    convs: Mutex<HashMap<ConvId, Conversation>>,
    /// 推送的两个后台任务（翻译更新、推给宿主）与发个人资料的任务，下线时停掉。
    tasks: Mutex<Vec<AbortHandle>>,
}

impl Live {
    /// 这些账号的名字：缓存里没有的一次向服务器取（取不到的就没有，显示时写“有人”）。
    pub(crate) async fn names(&self, uids: impl IntoIterator<Item = Uid>) -> Names {
        let mut wanted: Vec<Uid> = uids.into_iter().collect();
        wanted.sort();
        wanted.dedup();
        let missing: Vec<Uid> = {
            let names = self.names.lock().expect("名字缓存锁中毒");
            wanted.iter().filter(|u| !names.contains_key(*u)).cloned().collect()
        };
        if !missing.is_empty() {
            match self.client.profiles(&missing).await {
                Ok(found) => {
                    let mut names = self.names.lock().expect("名字缓存锁中毒");
                    if names.len() + found.len() > CACHE_MAX {
                        names.clear();
                    }
                    names.extend(found.into_iter().map(|p| (p.uid, p.name)));
                }
                Err(error) => tracing::info!(%error, count = missing.len(), "取名字没成，先不显示名字"),
            }
        }
        let names = self.names.lock().expect("名字缓存锁中毒");
        wanted.into_iter().filter_map(|u| names.get(&u).map(|n| (u, n.clone()))).collect()
    }

    /// 这个人现在的头像键：自己用宿主交来的那张（契约 friend-im v6，不再用 Cindy 头像地址），别人用收到的个人资料。
    pub(crate) fn avatar_of(&self, uid: &Uid) -> Option<String> {
        if *uid == self.me {
            return self.photo.lock().expect("头像锁中毒").as_ref().map(super::profile::HostPhoto::self_key);
        }
        self.profiles.avatar(uid)
    }

    /// 会话资料（缓存过就直接给）：群名是解开的群资料里的名字，私聊用对方的名字与头像。
    pub(crate) async fn conversation(&self, conv: &ConvId) -> Result<Conversation, ClientError> {
        if let Some(found) = self.convs.lock().expect("会话缓存锁中毒").get(conv) {
            return Ok(found.clone());
        }
        let info = self.client.conv_info(conv).await?;
        let built = match info.kind {
            ConvKind::Group => {
                let name = match self.client.group_profile(conv).await {
                    Ok(profile) => profile.map(|p| p.name).filter(|n| !n.trim().is_empty()),
                    Err(error) => {
                        tracing::info!(%conv, %error, "群资料解不开，先叫“群聊”");
                        None
                    }
                };
                let name = match name {
                    Some(name) => name,
                    // 重置账号就退出了以前的群、解不开它的资料（契约 S7）：给空名字，宿主留着本机记着的群名，
                    // 不编一个“群聊”盖掉它（重置不删本机已有的聊天记录）。
                    None if self.client.groups_left_by_reset().await.is_ok_and(|left| left.contains(conv)) => String::new(),
                    None => "群聊".into(),
                };
                Conversation {
                    id: conv.to_string(),
                    kind: ConversationKind::Group,
                    name,
                    avatar: None,
                    peer: None,
                    private: false,
                }
            }
            ConvKind::Dm => {
                let peer = info.members.iter().map(|m| m.uid.clone()).find(|u| *u != self.me);
                let name = match &peer {
                    Some(peer) => self.names([peer.clone()]).await.remove(peer),
                    None => None,
                };
                Conversation {
                    id: conv.to_string(),
                    kind: ConversationKind::Direct,
                    name: name.unwrap_or_else(|| "私聊".into()),
                    avatar: peer.as_ref().and_then(|p| self.avatar_of(p)),
                    peer: peer.map(|p| p.to_string()),
                    private: false,
                }
            }
        };
        let mut convs = self.convs.lock().expect("会话缓存锁中毒");
        if convs.len() >= CACHE_MAX {
            convs.clear();
        }
        convs.insert(conv.clone(), built.clone());
        Ok(built)
    }

    /// 会话变了（建群、进出群、改群资料、对方换了头像）：下次重新取。
    pub(crate) fn forget_conversation(&self, conv: &ConvId) {
        self.convs.lock().expect("会话缓存锁中毒").remove(conv);
    }

    /// 和这个人的私聊（缓存里有的），对方换头像时重新推它。
    pub(crate) fn direct_with(&self, uid: &Uid) -> Vec<ConvId> {
        let peer = uid.to_string();
        self.convs
            .lock()
            .expect("会话缓存锁中毒")
            .iter()
            .filter(|(_, c)| c.kind == ConversationKind::Direct && c.peer.as_deref() == Some(peer.as_str()))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// 是否已经知道这个会话（推送新会话的消息前先推会话本身）。
    pub(crate) fn knows_conversation(&self, conv: &ConvId) -> bool {
        self.convs.lock().expect("会话缓存锁中毒").contains_key(conv)
    }

    /// 多一个后台任务（下线时一起停）。
    pub(crate) fn hold(&self, task: AbortHandle) {
        self.tasks.lock().expect("任务表锁中毒").push(task);
    }

    /// 停掉推送任务，断开服务器。
    pub(crate) fn close(&self) {
        for task in self.tasks.lock().expect("任务表锁中毒").drain(..) {
            task.abort();
        }
        self.client.close();
    }
}

/// 读 `session/open` 的服务器地址设置（没给用默认值）。
fn server_setting(params: &SessionOpenParams) -> Result<String, RpcError> {
    let raw = params.settings.get(SETTING_SERVER).map_or(DEFAULT_SERVER, String::as_str);
    credential::server_url(raw).ok_or_else(|| errors::of(ErrorKind::InvalidRequest, format!("服务器地址不对：{raw}（要 https 网址）")))
}

fn needs_login(reason: NeedsLoginReason, message: &str) -> Result<Value, RpcError> {
    Ok(serde_json::to_value(SessionOpenResult::NeedsLogin { reason, message: message.into() }).expect("结果总能写成 JSON"))
}

impl Server {
    /// 在线的账号；没上线时回“还没连上”。
    pub(crate) async fn live(&self) -> Result<Arc<Live>, RpcError> {
        self.state.read().await.clone().ok_or_else(errors::offline)
    }

    /// 下线：停掉推送、断开服务器。
    pub(crate) async fn close_session(&self) {
        if let Some(live) = self.state.write().await.take() {
            live.close();
        }
    }

    /// 最近一次 `session/open` 设置里的服务器地址（登录要连它）；没打开过用默认值。
    pub(crate) fn server_url(&self) -> String {
        self.server_url.lock().expect("服务器地址锁中毒").clone().unwrap_or_else(|| DEFAULT_SERVER.to_owned())
    }

    /// `session/open`：用凭据连上服务器。
    pub(crate) async fn session_open(self: &Arc<Self>, params: SessionOpenParams) -> Result<Value, RpcError> {
        self.close_session().await;
        let server = server_setting(&params)?;
        *self.server_url.lock().expect("服务器地址锁中毒") = Some(server.clone());
        let Some(text) = params.credential.as_deref() else {
            return needs_login(NeedsLoginReason::NoCredential, "用 Cindy 账号登录 Cindy IM。");
        };
        let Some(saved) = Credential::decode(text) else {
            tracing::warn!("凭据读不懂（格式或版本不对），要重新登录");
            return needs_login(NeedsLoginReason::CredentialInvalid, "Cindy IM 的登录信息读不懂了，要重新登录。");
        };
        if saved.server != server {
            tracing::info!(saved = %saved.server, setting = %server, "服务器地址改了，要重新登录");
            return needs_login(NeedsLoginReason::CredentialInvalid, &format!("服务器地址改成了 {server}，要在新服务器上重新登录。"));
        }
        let position = params.sync_state.as_deref().and_then(|s| s.parse::<u64>().ok());
        let config = Config { server: server.clone(), device_name: saved.device_name.clone() };
        let (client, updates) = match Client::connect(config, saved.device.clone(), None, position).await {
            Ok(connected) => connected,
            Err(error) => {
                return match error.code() {
                    Some(ErrorCode::Unauthorized) => needs_login(NeedsLoginReason::Expired, "Cindy IM 的登录已失效，要重新登录。"),
                    Some(ErrorCode::DeviceRemoved) => needs_login(NeedsLoginReason::Revoked, "这台电脑已被移出你的 Cindy IM 账号，要重新登录。"),
                    Some(ErrorCode::NotApproved) => needs_login(NeedsLoginReason::CredentialInvalid, "这台电脑还没被批准加入 Cindy IM 账号。"),
                    _ => {
                        tracing::info!(%error, "连不上服务器");
                        Err(errors::client(&error))
                    }
                };
            }
        };
        let status = client.status().await;
        if client.uid().as_str() != saved.uid || status != DeviceStatus::Active {
            tracing::warn!(?status, "凭据的账号对不上，或这台电脑还不能用");
            client.close();
            return needs_login(NeedsLoginReason::CredentialInvalid, "这台电脑还没开通或还没被批准，要重新登录。");
        }
        let account = self.go_live(client, updates, saved, params.credential_read_only).await;
        Ok(serde_json::to_value(SessionOpenResult::Online { account, adopted_settings: None }).expect("结果总能写成 JSON"))
    }

    /// 上线（重新打开与登录完成共用）：记下在线的账号、开始推送；之后在后台补上待批准的新电脑、发个人资料。返回账号。
    pub(crate) async fn go_live(self: &Arc<Self>, client: Client, updates: Updates, saved: Credential, read_only: bool) -> Account {
        let me = client.uid().clone();
        self.avatars.allow_host_of(saved.avatar.as_deref());
        let account = Account {
            id: me.to_string(),
            id_type: None,
            name: client.name().await,
            // 自己的头像用宿主交来的那张（契约 friend-im v6）：上线时多半还没收到，收到后推人员资料。
            avatar: self.photo.lock().expect("头像锁中毒").as_ref().map(super::profile::HostPhoto::self_key),
            tenant: None,
        };
        let (devices, device_inbox) = super::devices::Devices::new();
        let live = Arc::new(Live {
            client,
            me,
            read_only,
            credential: Mutex::new(saved),
            profiles: Profiles::default(),
            photo: self.photo.clone(),
            requests: Mutex::new(BTreeMap::new()),
            device_notes: Mutex::new(Vec::new()),
            outbox: Arc::new(push::Outbox::default()),
            devices,
            names: Mutex::new(Names::new()),
            convs: Mutex::new(HashMap::new()),
            tasks: Mutex::new(Vec::new()),
        });
        let tasks = push::start(self.clone(), live.clone(), updates);
        live.tasks.lock().expect("任务表锁中毒").extend(tasks);
        live.hold(super::devices::start(self.clone(), live.clone(), device_inbox));
        if let Some(old) = self.state.write().await.replace(live.clone()) {
            old.close();
        }
        tracing::info!("Cindy IM 已上线");
        let (server, after_live) = (self.clone(), live.clone());
        let after = tokio::spawn(async move {
            server.refresh_requests(&after_live).await;
            // 重新上线时已经有宿主交来的头像（插件没重启、只是重连）：没发过就补发。
            server.announce_photo(&after_live).await;
        });
        live.hold(after.abort_handle());
        account
    }

    /// `session/logout`：这台电脑退出 Cindy IM（从“我的电脑”里移除，契约 S22），再下线。
    pub(crate) async fn session_logout(&self) -> Result<Value, RpcError> {
        if let Ok(live) = self.live().await
            && let Err(error) = live.client.logout().await
        {
            tracing::info!(%error, "退出登录时没连上服务器，只在本机下线");
        }
        self.close_session().await;
        Ok(serde_json::json!({}))
    }

    /// 存一份凭据（`credential/save`）：宿主写好了才回成功。
    ///
    /// # Errors
    /// 宿主没存下时返回给人看的原因。
    pub(crate) async fn save_credential(&self, credential: &Credential) -> Result<(), String> {
        let params = hhh_im_protocol::method::CredentialSaveParams { credential: credential.encode(), renew_at_ms: None };
        self.peer.request("credential/save", &params).await.map(|_| ()).map_err(|error| {
            tracing::error!(?error, "宿主没存下 Cindy IM 的凭据");
            "Friend 没存下登录信息，请重试。".to_owned()
        })
    }
}
