//! 账本：从服务器取来、一环一环验过的账号签名链和会话签名链。
//!
//! - 只认自己验过的链：服务器给的每一环都按 core 的规则重新验，验不过就报 [`ClientError::Verify`]，不进缓存。
//! - 缓存乐观使用：校验时先用手里的链，签名人对不上再向服务器补取一次（别人刚加了电脑、刚重置）。
//! - 缓存有上限（各 [`CACHE_MAX`] 项），超过就清空、按需重新取；插件内存不随账号和会话数无限增长。

use std::collections::{BTreeMap, HashMap};

use friend_im_core::account::{AccountLink, AccountState};
use friend_im_core::bytes::Fixed;
use friend_im_core::conv::{ConvChange, ConvLink, ConvState, Directory, MemberRef};
use friend_im_core::ids::{ConvId, DeviceId, InviteId, Uid};
use friend_im_core::keys::DevicePublic;
use friend_im_core::wire::{Request, Response};

use crate::conn::Conn;
use crate::error::{ClientError, Result};

/// 账号签名链、会话签名链各缓存多少项。
pub const CACHE_MAX: usize = 4096;

/// 一个账号各轮签名链。
#[derive(Clone, Debug, Default)]
pub(crate) struct AccountChains {
    /// 服务器说的当前一轮。
    pub current_epoch: u32,
    /// 各轮验过的现状。
    pub epochs: BTreeMap<u32, AccountState>,
}

impl AccountChains {
    pub fn current(&self) -> Option<&AccountState> {
        self.epochs.get(&self.current_epoch)
    }
}

/// 某人在会话里的一段成员身份：从加入的日志位置到离开（或被改记）的位置。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Stint {
    pub uid: Uid,
    pub eldest: Fixed<32>,
    pub from: u64,
    pub until: Option<u64>,
    /// 同一段身份按签名链里写的时间：和消息的发送时间比（消息不再有服务器日志序号）。
    pub from_ms: i64,
    pub until_ms: Option<i64>,
}

/// 一个会话：验过的现状 + 原始的环（翻历史时合进系统提示）+ 成员身份区间。
#[derive(Clone, Debug)]
pub(crate) struct ConvRecord {
    pub state: ConvState,
    pub links: Vec<(ConvLink, u64)>,
    pub stints: Vec<Stint>,
    /// 每个群邀请是在第几代钥匙时发的（凭邀请加入的人只拿得到那一代，之后换过代就要补发）。
    pub invite_generations: BTreeMap<InviteId, u32>,
}

impl ConvRecord {
    /// 这个身份在日志区间 `[start, end)` 里是不是当过成员（`end` 为空到现在）。
    pub fn member_during(&self, uid: &Uid, eldest: &Fixed<32>, start: u64, end: Option<u64>) -> bool {
        self.stints.iter().any(|s| {
            &s.uid == uid && &s.eldest == eldest && end.is_none_or(|end| s.from < end) && s.until.is_none_or(|until| until > start)
        })
    }

    /// 第 `generation` 代钥匙在用的日志区间：从这一代出现，到下一代出现（还在用为空）。
    pub fn generation_window(&self, generation: u32) -> Option<(u64, Option<u64>)> {
        let mut current = 0;
        let mut start = None;
        for (link, log) in &self.links {
            let body = link.parse().ok()?;
            if matches!(body.change, ConvChange::Create { .. } | ConvChange::Rotate { .. } | ConvChange::MemberReset { .. }) {
                current += 1;
                if current == generation {
                    start = Some(*log);
                } else if current == generation + 1 {
                    return Some((start?, Some(*log)));
                }
            }
        }
        start.map(|start| (start, None))
    }

    fn open_stint(&mut self, member: &MemberRef, log: u64, at: i64) {
        self.stints.push(Stint {
            uid: member.uid.clone(),
            eldest: member.eldest,
            from: log,
            until: None,
            from_ms: at,
            until_ms: None,
        });
    }

    fn close_stint(&mut self, uid: &Uid, log: u64, at: i64) {
        for stint in self.stints.iter_mut().filter(|s| &s.uid == uid && s.until.is_none()) {
            stint.until = Some(log);
            stint.until_ms = Some(at);
        }
    }

    /// 记下已验过的一环带来的成员区间与邀请代数变化。
    fn record(&mut self, link: &ConvLink, log: u64) {
        let Ok(body) = link.parse() else { return };
        let at = body.ctime_ms;
        match &body.change {
            ConvChange::Create { members, .. } | ConvChange::Add { members } => {
                for m in members {
                    self.open_stint(m, log, at);
                }
            }
            ConvChange::JoinByInvite { member, .. } => self.open_stint(member, log, at),
            ConvChange::Remove { uid, .. } => self.close_stint(uid, log, at),
            ConvChange::Leave => self.close_stint(&body.author, log, at),
            ConvChange::MemberReset { member, .. } => {
                self.close_stint(&member.uid, log, at);
                self.open_stint(member, log, at);
            }
            ConvChange::CreateInvite { invite, .. } => {
                self.invite_generations.insert(invite.clone(), self.state.current_key().generation);
            }
            _ => {}
        }
        self.links.push((link.clone(), log));
    }
}

/// 账本。
#[derive(Default)]
pub(crate) struct Book {
    pub accounts: HashMap<Uid, AccountChains>,
    pub convs: HashMap<ConvId, ConvRecord>,
}

impl Directory for Book {
    fn device(&self, uid: &Uid, eldest: &Fixed<32>, device: &DeviceId, log: u64) -> Option<DevicePublic> {
        self.accounts
            .get(uid)?
            .epochs
            .values()
            .find(|s| &s.eldest == eldest)
            .and_then(|s| s.device_at(device, log))
    }

    fn eldest(&self, uid: &Uid) -> Option<Fixed<32>> {
        self.accounts.get(uid)?.current().map(|s| s.eldest)
    }
}

impl Book {
    /// 某账号当前一轮的现状（只看缓存）。
    pub fn current(&self, uid: &Uid) -> Option<&AccountState> {
        self.accounts.get(uid)?.current()
    }

    /// 清空全部缓存（重置账号后、或超过上限时）。
    pub fn clear(&mut self) {
        self.accounts.clear();
        self.convs.clear();
    }

    /// 向服务器补取某账号某一轮（`None` 为当前一轮）的签名链并验过，返回取到的是哪一轮。
    pub async fn load_account(&mut self, conn: &Conn, uid: &Uid, epoch: Option<u32>) -> Result<u32> {
        if self.accounts.len() > CACHE_MAX {
            self.accounts.clear();
        }
        let known = self.accounts.get(uid);
        let wanted = epoch.or(known.map(|k| k.current_epoch));
        let after = wanted.and_then(|e| known?.epochs.get(&e)).map_or(0, |s| s.seq);
        let response = conn.request(Request::GetChain { uid: uid.clone(), epoch, after }).await?;
        let Response::Chain {
            uid: got,
            epoch: got_epoch,
            current_epoch,
            entries,
        } = response
        else {
            return Err(ClientError::protocol("取签名链的回执不对"));
        };
        if &got != uid || epoch.is_some_and(|e| e != got_epoch) {
            return Err(ClientError::protocol("取到的不是要的签名链"));
        }
        // 问的是“当前一轮”，而服务器的当前一轮已经变了（对方重置）：从新一轮的第一环重新取。
        if epoch.is_none() && Some(got_epoch) != wanted && after > 0 {
            return Box::pin(self.load_account(conn, uid, Some(got_epoch))).await;
        }
        let chains = self.accounts.entry(uid.clone()).or_default();
        chains.current_epoch = chains.current_epoch.max(current_epoch);
        let links: Vec<(AccountLink, u64)> = entries.into_iter().map(|e| (e.link, e.log)).collect();
        match chains.epochs.get_mut(&got_epoch) {
            Some(state) => {
                for (link, log) in &links {
                    state.apply(link, *log).map_err(|e| ClientError::verify(format!("账号签名链：{e}")))?;
                }
            }
            None if links.is_empty() => {}
            None => {
                let state = AccountState::verify_chain(uid, got_epoch, &links).map_err(|e| ClientError::verify(format!("账号签名链：{e}")))?;
                chains.epochs.insert(got_epoch, state);
            }
        }
        Ok(got_epoch)
    }

    /// 确保手里有某账号身份指纹为 `eldest` 的那一轮，返回是哪一轮。
    pub async fn ensure_identity(&mut self, conn: &Conn, uid: &Uid, eldest: &Fixed<32>) -> Result<u32> {
        if let Some(epoch) = self.find_identity(uid, eldest) {
            return Ok(epoch);
        }
        let current = self.load_account(conn, uid, None).await?;
        if let Some(epoch) = self.find_identity(uid, eldest) {
            return Ok(epoch);
        }
        for epoch in (0..current).rev() {
            if self.accounts.get(uid).is_some_and(|c| c.epochs.contains_key(&epoch)) {
                continue;
            }
            self.load_account(conn, uid, Some(epoch)).await?;
            if self.find_identity(uid, eldest) == Some(epoch) {
                return Ok(epoch);
            }
        }
        Err(ClientError::verify("找不到这个身份的签名链"))
    }

    fn find_identity(&self, uid: &Uid, eldest: &Fixed<32>) -> Option<u32> {
        self.accounts.get(uid)?.epochs.iter().find(|(_, s)| &s.eldest == eldest).map(|(e, _)| *e)
    }

    /// 确保某账号某身份的电脑 `device` 在日志位置 `log` 时有效，返回它的公钥；缓存里没有就补取一次。
    pub async fn ensure_device(&mut self, conn: &Conn, uid: &Uid, eldest: &Fixed<32>, device: &DeviceId, log: u64) -> Result<DevicePublic> {
        if let Some(key) = self.device(uid, eldest, device, log) {
            return Ok(key);
        }
        let epoch = self.ensure_identity(conn, uid, eldest).await?;
        if let Some(key) = self.device(uid, eldest, device, log) {
            return Ok(key);
        }
        self.load_account(conn, uid, Some(epoch)).await?;
        self.device(uid, eldest, device, log)
            .ok_or_else(|| ClientError::verify("签名的电脑不属于这个账号，或当时已被移除"))
    }

    fn device_during(&self, uid: &Uid, eldest: &Fixed<32>, device: &DeviceId, start: u64, end: Option<u64>) -> Option<DevicePublic> {
        let record = self.accounts.get(uid)?.epochs.values().find(|s| &s.eldest == eldest)?.devices.get(device)?;
        let in_window = end.is_none_or(|end| record.added.log < end) && record.removed.as_ref().is_none_or(|removed| removed.log > start);
        in_window.then_some(record.keys)
    }

    /// 确保某账号某身份的电脑在日志区间 `[start, end)` 里有效过，返回它的公钥；缓存里没有就补取一次。
    pub async fn ensure_device_during(&mut self, conn: &Conn, uid: &Uid, eldest: &Fixed<32>, device: &DeviceId, start: u64, end: Option<u64>) -> Result<DevicePublic> {
        if let Some(key) = self.device_during(uid, eldest, device, start, end) {
            return Ok(key);
        }
        let epoch = self.ensure_identity(conn, uid, eldest).await?;
        if let Some(key) = self.device_during(uid, eldest, device, start, end) {
            return Ok(key);
        }
        self.load_account(conn, uid, Some(epoch)).await?;
        self.device_during(uid, eldest, device, start, end).ok_or_else(|| ClientError::verify("签名的电脑不属于这个账号，或当时已被移除"))
    }

    /// 校验一环之前把需要的签名链准备好：签名人当时的电脑、被“因重置移出”的人的当前一轮。
    async fn prepare(&mut self, conn: &Conn, link: &ConvLink, log: u64) -> Result<()> {
        let body = link.parse().map_err(|e| ClientError::verify(format!("会话签名链：{e}")))?;
        self.ensure_device(conn, &body.author, &body.author_eldest, &link.by, log).await?;
        if let ConvChange::Remove { uid, .. } = &body.change {
            self.load_account(conn, uid, None).await?;
        }
        Ok(())
    }

    /// 向服务器补取一个会话的签名链（只取缓存之后的环）并验过。返回新接上的环。
    pub async fn load_conv(&mut self, conn: &Conn, conv: &ConvId) -> Result<Vec<(ConvLink, u64)>> {
        if self.convs.len() > CACHE_MAX {
            self.convs.clear();
        }
        let after = self.convs.get(conv).map_or(0, |r| r.state.seq);
        let response = conn.request(Request::GetConv { conv: conv.clone(), after }).await?;
        let Response::ConvChain { conv: got, entries } = response else {
            return Err(ClientError::protocol("取会话签名链的回执不对"));
        };
        if &got != conv {
            return Err(ClientError::protocol("取到的不是要的会话"));
        }
        let mut added = Vec::new();
        for entry in entries {
            self.accept_conv_link(conn, conv, &entry.link, entry.log).await?;
            added.push((entry.link, entry.log));
        }
        if !self.convs.contains_key(conv) {
            return Err(ClientError::verify("会话签名链是空的"));
        }
        Ok(added)
    }

    /// 验过一环并接到缓存的会话上（第一环则新建）。
    pub async fn accept_conv_link(&mut self, conn: &Conn, conv: &ConvId, link: &ConvLink, log: u64) -> Result<()> {
        self.prepare(conn, link, log).await?;
        let verify = |e: friend_im_core::CoreError| ClientError::verify(format!("会话签名链：{e}"));
        match self.convs.get(conv) {
            Some(record) => {
                let mut state = record.state.clone();
                state.apply(link, log, self).map_err(verify)?;
                let record = self.convs.get_mut(conv).expect("刚查到");
                record.state = state;
                record.record(link, log);
            }
            None => {
                let state = ConvState::create(conv, link, log, self).map_err(verify)?;
                let mut record = ConvRecord {
                    state,
                    links: Vec::new(),
                    stints: Vec::new(),
                    invite_generations: BTreeMap::new(),
                };
                record.record(link, log);
                self.convs.insert(conv.clone(), record);
            }
        }
        Ok(())
    }

    /// 某会话的现状；没有就向服务器取。
    pub async fn conv(&mut self, conn: &Conn, conv: &ConvId) -> Result<&ConvRecord> {
        if !self.convs.contains_key(conv) {
            self.load_conv(conn, conv).await?;
        }
        self.convs.get(conv).ok_or_else(|| ClientError::verify("会话签名链是空的"))
    }

    /// 我在哪些会话里见过这个人、核对过的身份指纹（最近的一次）。
    pub fn pinned_identity(&self, uid: &Uid) -> Option<Fixed<32>> {
        self.convs
            .values()
            .flat_map(|r| r.stints.iter())
            .filter(|s| &s.uid == uid)
            .max_by_key(|s| s.from)
            .map(|s| s.eldest)
    }
}
