//! 客户端的内部状态与事件处理：控制面补拉、推送、设备帧、消息验签解密、签名链变化。
//!
//! 控制面事件按日志序号递增处理，处理过的序号记在 `position`：断线重连后从这里补拉，
//! 推送里序号不大于它的跳过——不漏、不重（契约 S19）。消息不在这里，走设备对账（[`crate::sync`]）。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use friend_im_core::account::{AccountChange, AccountState};
use friend_im_core::conv::MemberRef;
use friend_im_core::ids::{ConvId, DeviceId, RequestId, Uid};
use friend_im_core::keys::{ConvSeed, DevicePublic};
use friend_im_core::limits;
use friend_im_core::message::Envelope;
use friend_im_core::pake::{ApproverHandshake, NewDeviceHandshake};
use friend_im_core::peer::SealedFrame;
use friend_im_core::wire::{
    AccountKeyBundle, DeviceKeyBox, DeviceStatus, Event, JoinCloseReason, JoinRequestInfo, Push,
    Request, Response, SyncEvent,
};
use friend_im_core::words::JoinCode;
use friend_im_core::{crypto, keys};
use tokio::sync::mpsc;

use crate::book::Book;
use crate::conn::Conn;
use crate::error::{ClientError, Result};
use crate::keyring::Keyring;
use crate::reading::ReadingBook;
use crate::sync::PeerFrame;
use crate::types::{AccountNotice, Config, Credentials, Message, Notice, Update};

/// 新电脑这边进行中的批准。
pub(crate) struct NewDeviceJoin {
    pub code: JoinCode,
    pub request: RequestId,
    pub attempt: u32,
    pub handshake: Option<NewDeviceHandshake>,
}

/// 旧电脑这边回应过、等新电脑确认码的一次批准。
pub(crate) struct Approval {
    pub info: JoinRequestInfo,
    pub handshake: ApproverHandshake,
}

/// 处理完一条推送后要不要停。
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Flow {
    Continue,
    Stop,
}

/// 客户端的全部可变状态（在一把异步锁里）。
pub(crate) struct State {
    pub config: Config,
    pub creds: Credentials,
    pub uid: Uid,
    pub name: String,
    pub epoch: u32,
    pub status: DeviceStatus,
    pub friend_requests: bool,
    /// 当前连接登录时服务器的日志序号：新电脑从这里开始同步。
    pub sync_head: u64,
    /// 处理到的日志序号。
    pub position: Option<u64>,
    pub book: Book,
    pub keys: Keyring,
    pub join: Option<NewDeviceJoin>,
    /// 旧电脑看到的待处理请求（来自推送或列表）。
    pub requests: HashMap<RequestId, JoinRequestInfo>,
    pub approvals: HashMap<RequestId, Approval>,
    pub updates: mpsc::UnboundedSender<Update>,
    /// 当前连接认下的服务器的钟。
    pub clock: ServerClock,
    /// 各设备的已读记录（只在内存里）。
    pub readings: ReadingBook,
    /// 见过的设备 → 账号（在线状态与帧里来的）。
    pub owners: HashMap<DeviceId, Uid>,
    /// 为判断对账权限刚补取过签名链的会话：不让一个被拒的伙伴反复触发补取。
    pub refreshed: HashMap<ConvId, Instant>,
}

/// 同一个会话的签名链，为判断对账权限至多多久补取一次。
const REFRESH_GAP: Duration = Duration::from_secs(10);

/// 记一次失败：连接断了是预期内的（重连后补拉），只记普通信息；其余的要关注。
pub(crate) fn log_failure(error: &ClientError, what: &str) {
    match error {
        ClientError::Disconnected | ClientError::Timeout => tracing::info!(%error, "{what}"),
        _ => tracing::warn!(%error, "{what}"),
    }
}

/// 服务器的钟：签名链与消息里写的时间按它写。本机钟快了的话，刚签的系统提示（如“X 重置了账号”）会排到紧接着发出、
/// 带服务器时间的那条消息后面（契约 S16）。每次连上，按服务器第一帧里的时间认一次和本机钟的差。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServerClock {
    offset_ms: i64,
}

impl ServerClock {
    /// 服务器第一帧里的时间，与收到它时本机的时间（都是毫秒）。
    pub(crate) fn from_challenge(server_ms: i64, local_ms: i64) -> Self {
        Self {
            offset_ms: server_ms.saturating_sub(local_ms),
        }
    }

    /// 按服务器的钟，现在是几点（毫秒）。
    pub(crate) fn now_ms(&self) -> i64 {
        now_ms().saturating_add(self.offset_ms)
    }
}

/// 本机的毫秒时间（要写进签名、和服务器时间比的用 [`State::now_ms`]）。
pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl State {
    /// 按服务器的钟，现在是几点（毫秒）：写进签名链、消息正文、群邀请链接到期时间的都用它。
    pub(crate) fn now_ms(&self) -> i64 {
        self.clock.now_ms()
    }

    pub fn emit(&self, update: Update) {
        let _ = self.updates.send(update);
    }

    pub fn require_active(&self) -> Result<()> {
        match self.status {
            DeviceStatus::Active => Ok(()),
            DeviceStatus::Pending => Err(ClientError::state("这台电脑还没被批准")),
            DeviceStatus::Unprovisioned => Err(ClientError::state("账号还没开通")),
        }
    }

    pub fn require_pending(&self) -> Result<()> {
        match self.status {
            DeviceStatus::Pending => Ok(()),
            DeviceStatus::Active => Err(ClientError::state("这台电脑已经可用了")),
            DeviceStatus::Unprovisioned => Err(ClientError::state("账号还没开通，直接开通即可")),
        }
    }

    /// 自己账号当前一轮的签名链（缓存里没有就取）。
    pub async fn me(&mut self, conn: &Conn) -> Result<AccountState> {
        if self
            .book
            .current(&self.uid)
            .is_none_or(|s| s.epoch != self.epoch)
        {
            self.book
                .load_account(conn, &self.uid, Some(self.epoch))
                .await?;
        }
        self.book
            .current(&self.uid)
            .cloned()
            .ok_or_else(|| ClientError::state("账号还没开通"))
    }

    /// 自己的成员身份（账号 + 当前身份指纹）。
    pub async fn my_ref(&mut self, conn: &Conn) -> Result<MemberRef> {
        let state = self.me(conn).await?;
        Ok(MemberRef {
            uid: self.uid.clone(),
            eldest: state.eldest,
        })
    }

    /// 取封装给这台电脑的账号钥匙（全部代）。
    pub async fn load_account_keys(&mut self, conn: &Conn) -> Result<()> {
        self.book
            .load_account(conn, &self.uid, Some(self.epoch))
            .await?;
        let Response::AccountKeys { epoch, boxes, prev } =
            conn.request(Request::GetAccountKeys).await?
        else {
            return Err(ClientError::protocol("取账号钥匙的回执不对"));
        };
        if epoch != self.epoch {
            return Err(ClientError::state("账号已经在别处重置"));
        }
        let state = self.me(conn).await?;
        self.keys
            .open_account_keys(&self.creds.device, &state, &boxes, &prev)
    }

    /// 保证手里有账号钥匙的当前一代。
    pub async fn ensure_account_keys(&mut self, conn: &Conn) -> Result<AccountState> {
        let state = self.me(conn).await?;
        if self
            .keys
            .account_seed(state.epoch, state.current_key().generation)
            .is_none()
        {
            self.load_account_keys(conn).await?;
        }
        self.me(conn).await
    }

    /// 某会话某一代的钥匙：缓存里没有就向服务器取封装给我的、解开并核对。
    pub async fn conv_seed(
        &mut self,
        conn: &Conn,
        conv: &ConvId,
        generation: u32,
    ) -> Result<ConvSeed> {
        self.optional_conv_seed(conn, conv, generation)
            .await?
            .ok_or_else(|| ClientError::verify(format!("拿不到第 {generation} 代会话钥匙")))
    }

    /// 旧身份或入群前的钥匙可以不存在；验签、解封或协议错误仍然向上传递。
    pub async fn optional_conv_seed(
        &mut self,
        conn: &Conn,
        conv: &ConvId,
        generation: u32,
    ) -> Result<Option<ConvSeed>> {
        if let Some(seed) = self.keys.conv_seed(conv, generation) {
            return Ok(Some(seed));
        }
        if self
            .book
            .conv(conn, conv)
            .await?
            .state
            .key(generation)
            .is_none()
        {
            self.book.load_conv(conn, conv).await?;
        }
        let state = self.book.conv(conn, conv).await?.state.clone();
        if state.key(generation).is_none() {
            return Err(ClientError::verify("会话签名链里没有这一代钥匙"));
        }
        let Response::ConvKeys { boxes, prev, .. } = conn
            .request(Request::GetConvKeys { conv: conv.clone() })
            .await?
        else {
            return Err(ClientError::protocol("取会话钥匙的回执不对"));
        };
        // 封装给了我账号钥匙更新的一代（别的电脑刚换过代）：先把账号钥匙取全。
        let me = self.me(conn).await?;
        let newer = boxes.iter().any(|b| {
            b.account_epoch == me.epoch
                && self
                    .keys
                    .account_seed(b.account_epoch, b.account_generation)
                    .is_none()
        });
        if newer {
            self.load_account_keys(conn).await?;
        }
        self.keys.open_conv_keys(&self.uid, &state, &boxes, &prev)?;
        Ok(self.keys.conv_seed(conv, generation))
    }

    /// 把账号钥匙某一代封装给一台电脑（或恢复密钥）。
    pub fn seal_account_seed(
        &self,
        epoch: u32,
        generation: u32,
        seed: &keys::AccountSeed,
        to: &keys::DevicePublic,
    ) -> Result<DeviceKeyBox> {
        let info = keys::account_seed_info(&self.uid, epoch, generation, &to.id());
        Ok(DeviceKeyBox {
            device: to.id(),
            sealed: crypto::seal_to(&to.enc.0, &info, seed.as_bytes())?,
        })
    }

    /// 账号钥匙换一代：封装给账号现在的全部电脑和恢复密钥，带上一代的旧钥匙链。`state` 是接上新一环之后的现状。
    pub fn account_bundle(
        &self,
        state: &AccountState,
        seed: &keys::AccountSeed,
        previous: &keys::AccountSeed,
    ) -> Result<AccountKeyBundle> {
        let generation = state.current_key().generation;
        let mut boxes = Vec::new();
        for (_, record) in state.active_devices() {
            boxes.push(self.seal_account_seed(state.epoch, generation, seed, &record.keys)?);
        }
        boxes.push(self.seal_account_seed(state.epoch, generation, seed, &state.recovery)?);
        Ok(AccountKeyBundle {
            generation,
            boxes,
            prev: Some(seed.wrap_previous(&self.uid, state.epoch, generation, previous)),
        })
    }

    // ---------- 同步 ----------

    /// 补拉：从处理到的位置一直拉到没有为止。
    pub async fn catch_up(&mut self, conn: &Conn) -> Result<()> {
        if self.status != DeviceStatus::Active {
            return Ok(());
        }
        let mut since = *self.position.get_or_insert(self.sync_head);
        loop {
            let response = conn
                .request(Request::Sync {
                    since,
                    limit: limits::SYNC_PAGE_MAX,
                })
                .await?;
            let Response::SyncBatch { events, next, more } = response else {
                return Err(ClientError::protocol("补拉的回执不对"));
            };
            for event in events {
                self.process_event(conn, event).await;
            }
            since = next.max(since);
            if self.position.is_some_and(|p| p < since) {
                self.position = Some(since);
            }
            self.emit(Update::Position(since));
            if !more {
                return Ok(());
            }
        }
    }

    /// 处理一条同步事件（推送或补拉来的）。序号不大于处理到的位置就跳过。
    pub async fn process_event(&mut self, conn: &Conn, event: SyncEvent) {
        if self.status != DeviceStatus::Active {
            return;
        }
        if self.position.is_some_and(|p| event.log <= p) {
            return;
        }
        let log = event.log;
        match event.event {
            Event::ConvLink { conv, link } => self.on_conv_link(conn, &conv, &link, log).await,
            // 会话钥匙按需取，新封装不用当场处理。
            Event::ConvKeys { .. } => {}
            Event::AccountLink { uid, epoch, link } => {
                self.on_account_link(conn, &uid, epoch, &link, log).await
            }
        }
        self.position = Some(log);
    }

    /// 收到别的设备的一帧（服务器转交或局域网）：核对发送设备属于这个账号、解开，交给上层。
    pub async fn handle_frame(&mut self, conn: &Conn, frame: SealedFrame) {
        if self.status != DeviceStatus::Active {
            return;
        }
        match self.open_frame(conn, &frame).await {
            Ok(opened) => {
                self.owners.insert(frame.from.clone(), frame.uid.clone());
                self.emit(Update::Frame { uid: frame.uid, from: frame.from, frame: opened });
            }
            Err(ClientError::Disconnected | ClientError::Timeout) => {
                tracing::info!("这会儿核对不了发来帧的设备，丢掉，下次对账再来");
            }
            Err(error) => tracing::warn!(%error, device = %frame.from, "发来的帧验不过，丢掉"),
        }
    }

    async fn open_frame(&mut self, conn: &Conn, frame: &SealedFrame) -> Result<PeerFrame> {
        let key = self.current_device(conn, &frame.uid, &frame.from).await?;
        let plain = frame.open(&self.creds.device, &key)?;
        serde_json::from_slice(&plain).map_err(|_| ClientError::verify("帧读不懂"))
    }

    /// 这个账号现在的这台设备的公钥；缓存里没有就补取一次。
    async fn current_device(&mut self, conn: &Conn, uid: &Uid, device: &DeviceId) -> Result<DevicePublic> {
        let find = |book: &Book| {
            book.current(uid)
                .and_then(|state| state.active_devices().find(|(id, _)| *id == device).map(|(_, record)| record.keys))
        };
        if let Some(key) = find(&self.book) {
            return Ok(key);
        }
        self.book.load_account(conn, uid, None).await?;
        find(&self.book).ok_or_else(|| ClientError::verify("这台设备不属于这个账号，或已被移除"))
    }

    /// 封一帧给一台设备。
    pub(crate) async fn seal_frame(&mut self, conn: &Conn, to: &DeviceId, frame: &PeerFrame) -> Result<SealedFrame> {
        let uid = self.owners.get(to).cloned().ok_or_else(|| ClientError::state("不认识这台设备"))?;
        let key = self.current_device(conn, &uid, to).await?;
        let plain = serde_json::to_vec(frame).map_err(|_| ClientError::protocol("帧写不出"))?;
        Ok(SealedFrame::seal(&self.uid, &self.creds.device, &key, &plain)?)
    }

    /// 这台设备能不能和我交换这个会话：同账号，或双方都是会话的当前成员（以我验过的签名链为准）。
    pub(crate) async fn may_share(&mut self, conn: &Conn, conv: &ConvId, peer: &DeviceId) -> bool {
        let Some(uid) = self.owners.get(peer).cloned() else {
            return false;
        };
        if uid == self.uid {
            return true;
        }
        let me = self.uid.clone();
        let both = |book: &Book| book.convs.get(conv).is_some_and(|record| record.state.members.contains_key(&me) && record.state.members.contains_key(&uid));
        if both(&self.book) {
            return true;
        }
        // 手里的链可能旧了（对方刚进群）：补取一次再看。
        if self.refreshed.get(conv).is_some_and(|at| at.elapsed() < REFRESH_GAP) {
            return false;
        }
        self.refreshed.insert(conv.clone(), Instant::now());
        match self.book.load_conv(conn, conv).await {
            Ok(_) => both(&self.book),
            Err(error) => {
                tracing::debug!(%conv, %error, "补取会话签名链没成，这次不和对方交换");
                false
            }
        }
    }

    /// 第 `generation` 代钥匙在用的日志区间；手里的链还没有这一代就补取一次。
    pub(crate) async fn generation_window(&mut self, conn: &Conn, conv: &ConvId, generation: u32) -> Result<(u64, Option<u64>)> {
        if let Some(window) = self.book.convs.get(conv).and_then(|record| record.generation_window(generation)) {
            return Ok(window);
        }
        self.book.load_conv(conn, conv).await?;
        self.book.convs[conv].generation_window(generation).ok_or_else(|| ClientError::verify("会话签名链里没有这一代钥匙"))
    }

    async fn on_conv_link(
        &mut self,
        conn: &Conn,
        conv: &ConvId,
        link: &friend_im_core::conv::ConvLink,
        log: u64,
    ) {
        let result = self.accept_link_event(conn, conv, link, log).await;
        match result {
            Ok(()) => {
                if let Some(notice) = Notice::from_link(conv, link, log) {
                    self.after_conv_notice(conn, &notice, link).await;
                    self.emit(Update::Conv(notice));
                }
            }
            Err(ClientError::Disconnected) => {
                tracing::info!(conv = %conv, log, "连接断了，会话签名链这一环重连后补拉")
            }
            Err(error) => {
                tracing::warn!(conv = %conv, log, %error, "会话签名链验不过");
                self.emit(Update::ConvRejected {
                    conv: conv.clone(),
                    log,
                    reason: error.to_string(),
                });
            }
        }
    }

    async fn accept_link_event(
        &mut self,
        conn: &Conn,
        conv: &ConvId,
        link: &friend_im_core::conv::ConvLink,
        log: u64,
    ) -> Result<()> {
        let body = link
            .parse()
            .map_err(|e| ClientError::verify(format!("会话签名链：{e}")))?;
        let next = self.book.convs.get(conv).map(|r| r.state.seq + 1);
        match next {
            // 已经接过（自己刚做的操作，或补取时已接上）：核对是同一环。
            Some(next) if body.seq < next => {
                let same = self.book.convs[conv]
                    .links
                    .iter()
                    .any(|(l, lg)| *lg == log && l.hash() == link.hash());
                if same {
                    Ok(())
                } else {
                    Err(ClientError::verify("服务器给的会话签名链前后不一致"))
                }
            }
            Some(next) if body.seq == next => {
                self.book.accept_conv_link(conn, conv, link, log).await
            }
            _ => {
                self.book.load_conv(conn, conv).await?;
                let record = &self.book.convs[conv];
                if record
                    .links
                    .iter()
                    .any(|(l, lg)| *lg == log && l.hash() == link.hash())
                {
                    Ok(())
                } else {
                    Err(ClientError::verify("推送的一环不在服务器给的会话签名链里"))
                }
            }
        }
    }

    /// 系统提示之后要顺手做的事：凭邀请加入的人只拿到发邀请时那一代钥匙，群已经换过代就补发当前一代（谁先补上算谁的）。
    async fn after_conv_notice(
        &mut self,
        conn: &Conn,
        notice: &Notice,
        link: &friend_im_core::conv::ConvLink,
    ) {
        use friend_im_core::conv::ConvChange;
        let Ok(body) = link.parse() else { return };
        let ConvChange::JoinByInvite { member, invite, .. } = &body.change else {
            return;
        };
        if member.uid == self.uid {
            return;
        }
        let Some(record) = self.book.convs.get(&notice.conv) else {
            return;
        };
        let current = record.state.current_key().generation;
        if record
            .invite_generations
            .get(invite)
            .is_none_or(|g| *g >= current)
            || !record.state.members.contains_key(&self.uid)
        {
            return;
        }
        let member = member.clone();
        if let Err(error) = self.grant(conn, &notice.conv, &member, current).await {
            tracing::info!(conv = %notice.conv, %error, "补发会话钥匙没成（多半别的成员已补）");
        }
    }

    async fn grant(
        &mut self,
        conn: &Conn,
        conv: &ConvId,
        member: &MemberRef,
        generation: u32,
    ) -> Result<()> {
        let seed = self.conv_seed(conn, conv, generation).await?;
        let boxes = self
            .seal_to_members(
                conn,
                conv,
                generation,
                &seed,
                std::slice::from_ref(member),
                true,
            )
            .await?;
        conn.request(Request::GrantConvKeys {
            conv: conv.clone(),
            keys: friend_im_core::wire::ConvKeyBundle {
                generation,
                boxes,
                prev: None,
            },
        })
        .await?;
        Ok(())
    }

    async fn on_account_link(
        &mut self,
        conn: &Conn,
        uid: &Uid,
        epoch: u32,
        link: &friend_im_core::account::AccountLink,
        log: u64,
    ) {
        let Ok(body) = link.parse() else {
            tracing::warn!(uid = %uid, "账号签名链的一环读不懂");
            return;
        };
        let known = self.book.accounts.contains_key(uid);
        if uid != &self.uid && !known && !matches!(body.change, AccountChange::Eldest { .. }) {
            // 没聊过的人（缓存已淘汰）：用到时再取。
            return;
        }
        if let Err(error) = self.book.load_account(conn, uid, Some(epoch)).await {
            log_failure(&error, "取账号签名链失败");
            return;
        }
        let name_of = |book: &Book, device| {
            book.accounts
                .get(uid)
                .and_then(|c| c.epochs.get(&epoch))
                .and_then(|s| s.devices.get(device))
                .map(|d| d.name.clone())
                .unwrap_or_default()
        };
        let notice = match &body.change {
            AccountChange::Eldest { .. } => AccountNotice::Started { reset: epoch > 0 },
            AccountChange::AddDevice { device, .. } => AccountNotice::DeviceAdded {
                device: device.keys.id(),
                name: device.name.clone(),
            },
            AccountChange::RemoveDevice { device, .. } => AccountNotice::DeviceRemoved {
                device: device.clone(),
                name: name_of(&self.book, device),
            },
            AccountChange::RotateKey { .. } => AccountNotice::KeyRotated,
            AccountChange::ReplaceRecovery { .. } => AccountNotice::RecoveryReplaced,
        };
        if uid == &self.uid && epoch == self.epoch {
            // 自己的账号钥匙换了代（别的电脑做的）：把新一代取回来。
            let rotated = matches!(
                body.change,
                AccountChange::RemoveDevice { key: Some(_), .. }
                    | AccountChange::RotateKey { .. }
                    | AccountChange::ReplaceRecovery { .. }
            );
            let removed_me = matches!(&body.change, AccountChange::RemoveDevice { device, .. } if device == &self.creds.device.id());
            // 别的电脑退出了自己、没有换代：在线的电脑当场补换一代，退出的那台拿着的旧代读不到之后的消息。
            // 几台电脑同时补换时只有一台成功，其余的被服务器拒绝，不影响。
            let left_without_rotation =
                matches!(&body.change, AccountChange::RemoveDevice { key: None, .. })
                    && !removed_me;
            if rotated
                && !removed_me
                && let Err(error) = self.ensure_account_keys(conn).await
            {
                tracing::warn!(%error, "取新一代账号钥匙失败");
            }
            if left_without_rotation
                && self
                    .book
                    .current(&self.uid)
                    .is_some_and(|s| s.rotation_pending)
                && let Err(error) = self.rotate_account_key(conn).await
            {
                tracing::info!(%error, "补换账号钥匙没成（可能别的电脑已经换了）");
            }
        }
        if uid == &self.uid || matches!(notice, AccountNotice::Started { reset: true }) {
            self.emit(Update::Account {
                uid: uid.clone(),
                log,
                notice,
            });
        }
    }

    /// 解开并核对一封信封：这一代钥匙在用的时候发送人是成员、发送电脑属于发送账号且有效、签名对、密文没被改。
    pub(crate) async fn open_envelope(&mut self, conn: &Conn, env: &Envelope) -> Result<Message> {
        let (mut start, mut end) = self.generation_window(conn, &env.conv, env.generation).await?;
        let member = |book: &Book, start, end| book.convs[&env.conv].member_during(&env.sender, &env.sender_eldest, start, end);
        if !member(&self.book, start, end) {
            self.book.load_conv(conn, &env.conv).await?;
            (start, end) = self.generation_window(conn, &env.conv, env.generation).await?;
            if !member(&self.book, start, end) {
                return Err(ClientError::verify("发送的人当时不在这个会话里"));
            }
        }
        let device = self.book.ensure_device_during(conn, &env.sender, &env.sender_eldest, &env.device, start, end).await?;
        let seed = self.conv_seed(conn, &env.conv, env.generation).await?;
        let body = env.open(&seed, &device)?;
        Ok(Message {
            conv: env.conv.clone(),
            id: env.id.clone(),
            sender: env.sender.clone(),
            sender_eldest: env.sender_eldest,
            device: env.device.clone(),
            ctime_ms: body.ctime_ms,
            content: body.content,
        })
    }

    // ---------- 推送 ----------

    /// 处理一条服务器推送。
    pub async fn handle_push(&mut self, conn: &Conn, push: Push) -> Flow {
        match push {
            Push::Relayed { frame, .. } => self.handle_frame(conn, frame).await,
            Push::Presence { uid, device, online } => {
                if online {
                    self.owners.insert(device.clone(), uid.clone());
                }
                self.emit(Update::Presence { uid, device, online });
            }
            Push::FriendRequestsChanged => self.emit(Update::FriendRequestsChanged),
            Push::Event { event } => {
                let log = event.log;
                self.process_event(conn, event).await;
                if self.status == DeviceStatus::Active {
                    self.emit(Update::Position(log));
                }
            }
            Push::JoinRequested { request } => {
                self.requests
                    .insert(request.request.clone(), request.clone());
                self.emit(Update::JoinRequested(request));
            }
            Push::JoinRetry {
                request,
                attempt,
                pake,
            } => {
                self.approvals.remove(&request);
                if let Some(info) = self.requests.get_mut(&request) {
                    info.attempt = attempt;
                    info.pake = pake;
                }
                self.emit(Update::JoinRetry { request, attempt });
            }
            Push::JoinAnswered {
                request,
                attempt,
                pake,
                confirm,
            } => {
                if let Err(error) = self
                    .on_join_answered(conn, &request, attempt, &pake, &confirm)
                    .await
                {
                    tracing::warn!(%error, "处理旧电脑的回应失败");
                }
            }
            Push::JoinConfirmed {
                request,
                attempt,
                confirm,
            } => {
                if let Err(error) = self
                    .on_join_confirmed(conn, &request, attempt, &confirm)
                    .await
                {
                    tracing::warn!(%error, "批准新电脑失败");
                }
            }
            Push::JoinClosed { request, reason } => {
                // 新电脑被批准的那一刻已算账号里的电脑，“结束”会按电脑和按账号各推一次：只报认识的请求，第二次不再报。
                let listed = self.requests.remove(&request).is_some();
                let answered = self.approvals.remove(&request).is_some();
                let mine = self.join.as_ref().is_some_and(|j| j.request == request);
                if mine {
                    self.join = None;
                }
                if listed || answered || mine {
                    self.emit(Update::JoinClosed {
                        request: request.clone(),
                        reason,
                    });
                }
                if mine
                    && reason == JoinCloseReason::Approved
                    && let Err(error) = self.activate(conn).await
                {
                    tracing::warn!(%error, "批准后准备账号失败");
                }
            }
            Push::DeviceRemoved => {
                tracing::info!("这台电脑已被移出账号");
                self.emit(Update::DeviceRemoved);
                return Flow::Stop;
            }
        }
        Flow::Continue
    }

    /// 这台电脑变成可用：取签名链和账号钥匙，从登录时的位置开始同步。
    pub async fn activate(&mut self, conn: &Conn) -> Result<()> {
        self.status = DeviceStatus::Active;
        self.load_account_keys(conn).await?;
        self.emit(Update::Activated);
        self.catch_up(conn).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 本机钟快一秒（验收那台电脑实测）：按服务器的钟写，比本机钟早一秒左右，而不是照抄本机钟。
    #[test]
    fn the_server_clock_follows_the_server_not_the_local_clock() {
        let local = now_ms();
        let clock = ServerClock::from_challenge(local - 1_000, local);
        let now = clock.now_ms();
        assert!(now < now_ms(), "本机钟快时，按服务器的钟写的时间更早");
        assert!((now - (local - 1_000)).abs() < 1_000);
        assert_eq!(ServerClock::default().offset_ms, 0, "没连上过就按本机钟");
    }
}
