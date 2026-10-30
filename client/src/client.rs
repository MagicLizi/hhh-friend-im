//! 对外的客户端：连上服务器、断线自动重连并补拉，把推送和补拉来的事件解开后交给上层。
//!
//! 所有操作和事件处理在同一把异步锁里串行执行（状态只有一份，不会一边换代一边用旧钥匙发消息）；
//! 文件内容的上传下载不占这把锁，传大文件时照常收消息。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use friend_im_core::conv::GroupProfile;
use friend_im_core::file::FileRef;
use friend_im_core::ids::{ConvId, DeviceId, InviteId, MsgId, RequestId, Uid};
use friend_im_core::keys::RecoveryKey;
use friend_im_core::message::Content;
use friend_im_core::wire::{
    AccountInfo, ConvSummary, DeviceInfo, DeviceStatus, ErrorCode, HelloAuth, JoinRequestInfo, Push,
};
use tokio::sync::mpsc;

use crate::book::Book;
use crate::conn::{self, Conn};
use crate::error::{ClientError, Result};
use crate::keyring::Keyring;
use crate::lan::{DirectInbound, Lan};
use crate::links::{FriendLink, InviteLink, http_base, ws_url};
use crate::state::{Flow, State};
use crate::types::{Config, ConvInfo, Credentials, HistoryPage, JoinStart, Update};

/// 断线后第一次重连前等多久；之后每次翻倍，最多 [`RECONNECT_MAX`]。
const RECONNECT_MIN: Duration = Duration::from_secs(1);
/// 重连间隔上限。
const RECONNECT_MAX: Duration = Duration::from_secs(30);

pub(crate) struct Inner {
    pub state: tokio::sync::Mutex<State>,
    conn: Mutex<Option<Arc<Conn>>>,
    pub http: crate::web::Client,
    pub base: String,
    ws: String,
    uid: Uid,
    device: DeviceId,
    pub(crate) lan: Arc<Lan>,
    stopped: AtomicBool,
}

impl Inner {
    fn conn(&self) -> Result<Arc<Conn>> {
        self.conn
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .filter(|c| !c.is_closed())
            .ok_or(ClientError::Disconnected)
    }

    fn set_conn(&self, conn: Option<Arc<Conn>>) {
        *self.conn.lock().unwrap_or_else(|p| p.into_inner()) = conn;
    }

    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(conn) = self.conn.lock().unwrap_or_else(|p| p.into_inner()).take() {
            conn.close();
        }
    }

    fn stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }
}

/// Cindy IM 客户端。克隆后共享同一条连接和状态。
#[derive(Clone)]
pub struct Client {
    pub(crate) inner: Arc<Inner>,
}

/// 推给上层的更新流。
pub type Updates = mpsc::UnboundedReceiver<Update>;

impl Client {
    /// 连上服务器并登录。`cindy_token` 只在这台电脑第一次登录时给（之后用凭据里服务器发的登录凭证）；
    /// `position` 是上次存下的同步位置（新电脑为空，从登录时的位置开始）。
    ///
    /// 返回后客户端在后台处理推送、断线重连与补拉，结果从 [`Updates`] 里取。
    pub async fn connect(
        config: Config,
        mut creds: Credentials,
        cindy_token: Option<String>,
        position: Option<u64>,
    ) -> Result<(Self, Updates)> {
        let ws = ws_url(&config.server);
        let auth = match (cindy_token, &creds.session) {
            (Some(token), _) => HelloAuth::Cindy { token },
            (None, Some(session)) => HelloAuth::Session {
                token: session.clone(),
            },
            (None, None) => return Err(ClientError::state("还没有登录凭证，需要先用 Cindy 登录")),
        };
        let connected = conn::connect(&ws, auth, &creds.device, &config.device_name).await?;
        let welcome = connected.welcome;
        let (updates, rx) = mpsc::unbounded_channel();
        let (direct_tx, direct_rx) = mpsc::unbounded_channel();
        let lan = match Lan::start(welcome.uid.clone(), creds.device.clone(), direct_tx).await {
            Ok(lan) => lan,
            Err(error) => {
                tracing::info!(%error, "局域网直连不可用，自动使用服务器中转");
                Lan::disabled(welcome.uid.clone(), creds.device.clone())
            }
        };
        if let Some(session) = welcome.session.clone() {
            creds.session = Some(session);
            let _ = updates.send(Update::CredentialsChanged);
        }
        let _ = updates.send(Update::Connected {
            status: welcome.status,
        });
        let device = creds.device.id();
        let base = http_base(&config.server);
        let state = State {
            config,
            creds,
            uid: welcome.uid.clone(),
            name: welcome.name.clone(),
            epoch: welcome.epoch,
            status: welcome.status,
            reading: welcome.reading,
            friend_requests: welcome.friend_requests,
            sync_head: welcome.sync_head,
            position,
            book: Book::default(),
            keys: Keyring::new(),
            join: None,
            requests: HashMap::new(),
            approvals: HashMap::new(),
            updates,
            clock: connected.clock,
            seen_messages: std::collections::HashSet::new(),
            seen_order: std::collections::VecDeque::new(),
        };
        let inner = Arc::new(Inner {
            state: tokio::sync::Mutex::new(state),
            conn: Mutex::new(Some(connected.conn.clone())),
            http: crate::web::Client::builder()
                .connect_timeout(Duration::from_secs(15))
                .build()
                .map_err(|e| ClientError::Transfer(e.to_string()))?,
            base,
            ws,
            uid: welcome.uid,
            device,
            lan,
            stopped: AtomicBool::new(false),
        });
        if welcome.status == DeviceStatus::Active {
            let mut state = inner.state.lock().await;
            state.load_account_keys(&connected.conn).await?;
            if welcome.rotation_needed {
                // 有电脑退出了自己：账号钥匙由这台补换一代。
                if let Err(error) = state.rotate_account_key(&connected.conn).await {
                    tracing::info!(%error, "补换账号钥匙没成（可能别的电脑已经换了）");
                }
            }
        }
        tokio::spawn(supervise(inner.clone(), connected.pushes, direct_rx));
        Ok((Self { inner }, rx))
    }

    /// 当前连接（不占状态锁，文件传输用）。
    pub(crate) fn inner_conn(&self) -> Result<Arc<Conn>> {
        self.inner.conn()
    }

    /// 在状态锁里用当前连接执行一个操作。
    pub(crate) async fn call<T>(
        &self,
        f: impl AsyncFnOnce(&mut State, &Conn) -> Result<T>,
    ) -> Result<T> {
        let conn = self.inner.conn()?;
        let mut state = self.inner.state.lock().await;
        f(&mut state, &conn).await
    }

    /// 账号。
    pub fn uid(&self) -> &Uid {
        &self.inner.uid
    }

    /// 这台电脑的编号。
    pub fn device_id(&self) -> &DeviceId {
        &self.inner.device
    }

    /// 现在连着服务器吗：没连着时发的请求一定没出这台电脑。
    pub fn connected(&self) -> bool {
        self.inner.conn().is_ok()
    }

    /// 这台电脑的状态。
    pub async fn status(&self) -> DeviceStatus {
        self.inner.state.lock().await.status
    }

    /// 名字（来自 Cindy）。
    pub async fn name(&self) -> String {
        self.inner.state.lock().await.name.clone()
    }

    /// 要交给 HHH 存的凭据（收到 [`Update::CredentialsChanged`] 后重新存）。
    pub async fn credentials(&self) -> Credentials {
        self.inner.state.lock().await.creds.clone()
    }

    /// 处理到的日志序号（存成同步位置）。
    pub async fn position(&self) -> Option<u64> {
        self.inner.state.lock().await.position
    }

    /// 是否连着服务器。
    pub fn is_connected(&self) -> bool {
        self.inner.conn().is_ok()
    }

    /// 停止：断开连接，不再重连。
    pub fn close(&self) {
        self.inner.stop();
    }

    // ---------- 账号与电脑 ----------

    /// 开通（契约 S1），返回恢复密钥。
    pub async fn provision(&self) -> Result<RecoveryKey> {
        self.call(async |s, c| s.provision(c).await).await
    }

    /// 重置账号（契约 S7），返回新的恢复密钥。
    pub async fn reset(&self) -> Result<RecoveryKey> {
        self.call(async |s, c| s.reset(c).await).await
    }

    /// 本账号现在的电脑。
    pub async fn devices(&self) -> Result<Vec<DeviceInfo>> {
        self.call(async |s, c| s.devices(c).await).await
    }

    /// 移除别的电脑（契约 S5）。
    pub async fn remove_device(&self, device: &DeviceId) -> Result<()> {
        self.call(async |s, c| s.remove_device(c, device).await)
            .await
    }

    /// 重新生成恢复密钥（契约 S6）。
    pub async fn replace_recovery(&self) -> Result<RecoveryKey> {
        self.call(async |s, c| s.replace_recovery(c).await).await
    }

    /// 退出登录（契约 S22）：这台电脑从账号里移除，客户端随即停止。
    pub async fn logout(&self) -> Result<()> {
        self.call(async |s, c| s.logout(c).await).await?;
        self.inner.stop();
        Ok(())
    }

    /// 新电脑：发起批准请求，返回要显示的 4 个词与账号里已登录的电脑。
    pub async fn join_start(&self) -> Result<JoinStart> {
        self.call(async |s, c| s.join_start(c).await).await
    }

    /// 新电脑：不等了。
    pub async fn join_cancel(&self) -> Result<()> {
        self.call(async |s, c| s.join_cancel(c).await).await
    }

    /// 新电脑：用恢复密钥加入（契约 S3）。
    pub async fn join_with_recovery(&self, recovery: &str) -> Result<()> {
        self.call(async |s, c| s.join_with_recovery(c, recovery).await)
            .await
    }

    /// 旧电脑：待处理的批准请求。
    pub async fn join_requests(&self) -> Result<Vec<JoinRequestInfo>> {
        self.call(async |s, c| s.join_requests(c).await).await
    }

    /// 旧电脑：输入新电脑上的 4 个词。对上了自动批准；对不上会收到 [`Update::JoinRetry`]。
    pub async fn join_respond(&self, request: &RequestId, words: &str) -> Result<()> {
        self.call(async |s, c| s.join_respond(c, request, words).await)
            .await
    }

    /// 旧电脑：拒绝。
    pub async fn join_reject(&self, request: &RequestId) -> Result<()> {
        self.call(async |s, c| s.join_reject(c, request).await)
            .await
    }

    // ---------- 好友 ----------

    /// 我的好友链接；`rotate` 为真时换一条（契约 S8）。
    pub async fn friend_link(&self, rotate: bool) -> Result<FriendLink> {
        self.call(async |s, c| s.friend_link(c, rotate).await).await
    }

    /// 按好友链接查对方并核对身份。
    pub async fn resolve_friend(&self, link: &FriendLink) -> Result<AccountInfo> {
        self.call(async |s, c| s.resolve_friend(c, link).await)
            .await
    }

    /// 加好友（契约 S9），返回私聊。
    pub async fn add_friend(&self, link: &FriendLink) -> Result<ConvId> {
        self.call(async |s, c| s.add_friend(c, link).await).await
    }

    /// 重置账号之前就在、还记着旧身份的群：重置后已经用不了（契约 S7）。
    pub async fn groups_left_by_reset(&self) -> Result<Vec<ConvId>> {
        self.call(async |s, c| s.groups_left_by_reset(c).await)
            .await
    }

    /// 和群成员私聊（契约 S10），返回私聊。
    pub async fn open_dm(&self, uid: &Uid, group: &ConvId) -> Result<ConvId> {
        self.call(async |s, c| s.open_dm(c, uid, group).await).await
    }

    /// 一批账号的名字与身份指纹。
    pub async fn profiles(&self, uids: &[Uid]) -> Result<Vec<AccountInfo>> {
        self.call(async |s, c| s.profiles(c, uids).await).await
    }

    // ---------- 群 ----------

    /// 新建群（契约 S11），返回群。
    pub async fn create_group(&self, profile: &GroupProfile, members: &[Uid]) -> Result<ConvId> {
        self.call(async |s, c| s.create_group(c, profile, members).await)
            .await
    }

    /// 邀请成员（契约 S12）。
    pub async fn invite(&self, conv: &ConvId, members: &[Uid]) -> Result<()> {
        self.call(async |s, c| s.invite(c, conv, members).await)
            .await
    }

    /// 复制群邀请链接（契约 S12）。
    pub async fn create_invite_link(&self, conv: &ConvId) -> Result<InviteLink> {
        self.call(async |s, c| s.create_invite_link(c, conv).await)
            .await
    }

    /// 作废群邀请链接。
    pub async fn revoke_invite(&self, conv: &ConvId, invite: &InviteId) -> Result<()> {
        self.call(async |s, c| s.revoke_invite(c, conv, invite).await)
            .await
    }

    /// 凭群邀请链接加入，返回群。
    pub async fn join_by_invite(&self, link: &InviteLink) -> Result<ConvId> {
        self.call(async |s, c| s.join_by_invite(c, link).await)
            .await
    }

    /// 群主移出成员（契约 S13）。
    pub async fn kick(&self, conv: &ConvId, uid: &Uid) -> Result<()> {
        self.call(async |s, c| s.kick(c, conv, uid).await).await
    }

    /// 退群（契约 S13）。
    pub async fn leave(&self, conv: &ConvId) -> Result<()> {
        self.call(async |s, c| s.leave(c, conv).await).await
    }

    /// 改群资料。
    pub async fn set_group_profile(&self, conv: &ConvId, profile: &GroupProfile) -> Result<()> {
        self.call(async |s, c| s.set_group_profile(c, conv, profile).await)
            .await
    }

    /// 群资料（私聊为空）。
    pub async fn group_profile(&self, conv: &ConvId) -> Result<Option<GroupProfile>> {
        self.call(async |s, c| s.group_profile(c, conv).await).await
    }

    /// 会话现状。
    pub async fn conv_info(&self, conv: &ConvId) -> Result<ConvInfo> {
        self.call(async |s, c| s.conv_info(c, conv).await).await
    }

    /// 我所在（和离开过）的会话。
    pub async fn convs(&self) -> Result<Vec<ConvSummary>> {
        self.call(async |s, c| s.convs(c).await).await
    }

    /// 换代（一般不用直接调：发消息时需要会自动换）。
    pub async fn rotate(&self, conv: &ConvId) -> Result<()> {
        self.call(async |s, c| s.rotate(c, conv, Vec::new()).await)
            .await
    }

    // ---------- 消息 ----------

    /// 发消息，返回（日志序号，服务器时间）。同一次发送重试时用同一个 `id`。
    pub async fn send(&self, conv: &ConvId, id: &MsgId, content: Content) -> Result<(u64, i64)> {
        let lan = self.inner.lan.clone();
        self.call(async move |s, c| s.send(c, conv, id, content, &lan).await)
            .await
    }

    /// 撤回自己的一条消息。
    pub async fn recall(&self, conv: &ConvId, id: &MsgId, target: &MsgId) -> Result<(u64, i64)> {
        self.send(
            conv,
            id,
            Content::Recall {
                target: target.clone(),
            },
        )
        .await
    }

    /// 往前翻一页历史（`before` 为空从最新开始）。
    pub async fn history(
        &self,
        conv: &ConvId,
        before: Option<u64>,
        limit: u32,
    ) -> Result<HistoryPage> {
        self.history_in(conv, before, limit, None, None).await
    }

    /// 同 [`Client::history`]，只要服务器时间在 `since_ms`～`until_ms` 之间的（毫秒，两端都含，可以只给一端）。
    /// 系统提示没有服务器时间，按签它的人写的时间筛。
    pub async fn history_in(
        &self,
        conv: &ConvId,
        before: Option<u64>,
        limit: u32,
        since_ms: Option<i64>,
        until_ms: Option<i64>,
    ) -> Result<HistoryPage> {
        self.call(async |s, c| {
            s.history(c, conv, before, limit, (since_ms, until_ms))
                .await
        })
        .await
    }

    /// 会话活动：自己所在的会话里 `since_ms` 起有消息的，每个会话最早、最新一条的服务器时间，按最新的从新到旧。
    /// 只有会话编号和时间，用来尽早发现有新消息的会话（不解内容、不占发送额度）。
    pub async fn activity(&self, since_ms: i64) -> Result<Vec<friend_im_core::wire::ConvActivity>> {
        self.call(async |s, c| s.activity(c, since_ms).await).await
    }

    /// 文件、图片：见 [`crate::files`]。
    pub async fn upload(
        &self,
        conv: &ConvId,
        reader: impl std::io::Read,
        size: u64,
        name: &str,
        mime: &str,
    ) -> Result<FileRef> {
        crate::files::upload(self, conv, reader, size, name, mime).await
    }

    /// 下载并解密到 `out`。
    pub async fn download(&self, file: &FileRef, out: &mut impl std::io::Write) -> Result<()> {
        crate::files::download(self, file, out).await
    }

    /// 只读文件明文的 `offset` 起 `len` 字节（读到文件尾就少给）：只取盖住这一段的加密块，逐块核对后解开。
    /// 给按段读、断了接着读的调用方用（插件的资源读取）；整份下载用 [`Client::download`]。
    pub async fn read_range(&self, file: &FileRef, offset: u64, len: u64) -> Result<Vec<u8>> {
        crate::files::read_range(self, file, offset, len).await
    }
}

/// 后台：处理推送；断了就重连、补拉，直到停止。
async fn supervise(
    inner: Arc<Inner>,
    mut pushes: mpsc::Receiver<Push>,
    mut direct: mpsc::UnboundedReceiver<DirectInbound>,
) {
    // 局域网直连没起来（`Lan::disabled`）时发送端已经扔了：通道一关就不再等它，否则 `recv` 每次立刻回 `None`，循环空转占满一个核。
    let mut direct_open = true;
    loop {
        // 这一轮连接自己的对象：连接关了也要把它推来的东西处理完——服务器移除电脑时先推“已被移出”再关连接。
        let Some(conn) = inner.conn.lock().unwrap_or_else(|p| p.into_inner()).clone() else {
            return;
        };
        if !conn.is_closed() {
            let mut state = inner.state.lock().await;
            if let Err(error) = state.catch_up(&conn).await {
                crate::state::log_failure(&error, "补拉失败，断开重连");
                conn.close();
            }
        }
        loop {
            tokio::select! {
                push = pushes.recv() => {
                    let Some(push) = push else { break };
                    let mut state = inner.state.lock().await;
                    if state.handle_push(&conn, push).await == Flow::Stop {
                        drop(state);
                        inner.stop();
                        return;
                    }
                }
                message = direct.recv(), if direct_open => {
                    let Some(message) = message else {
                        direct_open = false;
                        continue;
                    };
                    let mut state = inner.state.lock().await;
                    state.handle_direct(&conn, message).await;
                }
            }
        }
        inner.set_conn(None);
        if inner.stopped() {
            return;
        }
        inner.state.lock().await.emit(Update::Disconnected);
        let mut delay = RECONNECT_MIN;
        pushes = loop {
            tokio::time::sleep(delay).await;
            if inner.stopped() {
                return;
            }
            match reconnect(&inner).await {
                Ok(next) => break next,
                Err(ClientError::Server(error))
                    if matches!(
                        error.code,
                        ErrorCode::Unauthorized | ErrorCode::DeviceRemoved
                    ) =>
                {
                    tracing::info!(code = ?error.code, "登录凭证失效或电脑已被移除，停止重连");
                    let update = if error.code == ErrorCode::DeviceRemoved {
                        Update::DeviceRemoved
                    } else {
                        Update::LoggedOut
                    };
                    inner.state.lock().await.emit(update);
                    inner.stop();
                    return;
                }
                Err(error) => {
                    tracing::debug!(%error, "重连失败，稍后再试");
                    delay = (delay * 2).min(RECONNECT_MAX);
                }
            }
        };
    }
}

async fn reconnect(inner: &Arc<Inner>) -> Result<mpsc::Receiver<Push>> {
    let (device, session, name) = {
        let state = inner.state.lock().await;
        (
            state.creds.device.clone(),
            state.creds.session.clone(),
            state.config.device_name.clone(),
        )
    };
    let session = session.ok_or_else(|| ClientError::state("没有登录凭证"))?;
    let connected = conn::connect(
        &inner.ws,
        HelloAuth::Session { token: session },
        &device,
        &name,
    )
    .await?;
    let welcome = connected.welcome;
    let mut state = inner.state.lock().await;
    let was_active = state.status == DeviceStatus::Active;
    if welcome.epoch != state.epoch {
        // 账号换了一轮：旧一轮的签名链和钥匙都用不上了。
        state.book.clear();
        state.keys.clear();
    }
    state.status = welcome.status;
    state.reading = welcome.reading;
    state.friend_requests = welcome.friend_requests;
    state.sync_head = welcome.sync_head;
    state.epoch = welcome.epoch;
    state.clock = connected.clock;
    inner.set_conn(Some(connected.conn.clone()));
    if welcome.status == DeviceStatus::Active && !was_active {
        // 断线期间被批准了：取账号钥匙、从登录前的位置开始同步。
        state.join = None;
        if let Err(error) = state.activate(&connected.conn).await {
            tracing::warn!(%error, "重连后准备账号失败");
        }
    }
    if welcome.status == DeviceStatus::Active
        && welcome.rotation_needed
        && let Err(error) = state.rotate_account_key(&connected.conn).await
    {
        tracing::info!(%error, "补换账号钥匙没成（可能别的电脑已经换了）");
    }
    // 批准请求不在消息同步日志里。补读失败沿用连接退避，不能带旧列表宣告恢复。
    if welcome.status == DeviceStatus::Active
        && let Err(error) = state.join_requests(&connected.conn).await
    {
        connected.conn.close();
        inner.set_conn(None);
        return Err(error);
    }
    state.emit(Update::Connected {
        status: welcome.status,
    });
    tracing::info!("已重连");
    Ok(connected.pushes)
}
