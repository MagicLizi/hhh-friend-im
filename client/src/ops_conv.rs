//! 会话：私聊、群、邀请、移出与退群、换代、发消息、翻历史。
//!
//! 换代（[`State::rotate`]）是所有“之后的新内容要用新钥匙”的入口：有人离开、成员换了账号钥匙、对方重置了账号。
//! 它在同一个请求里先补上需要的环——群里把重置过账号的人移出；私聊里改记对方的新身份（这一代不带旧钥匙链，
//! 重置的人读不到以前的消息）——再封装新一代给现在的全部成员。

use friend_im_core::conv::{
    ConvChange, ConvKind, ConvLink, ConvState, GroupProfile, MemberRef, RemoveReason, Via, create_body, invite_join_proof,
};
use friend_im_core::crypto;
use friend_im_core::ids::{ConvId, DeviceId, InviteId, MsgId, Uid};
use friend_im_core::keys::{ConvSeed, InviteSecret, conv_seed_info};
use friend_im_core::limits;
use friend_im_core::message::{Content, Envelope, MESSAGE_VERSION, MessageBody, Sender};
use friend_im_core::wire::{ConvActivity, ConvKeyBundle, ConvSummary, ErrorCode, InviteSeed, MemberKeyBox, Request, Response};

use crate::conn::Conn;
use crate::error::{ClientError, Result};
use crate::links::{InviteLink, http_base};
use crate::lan::Lan;
use crate::state::State;
use crate::types::{ConvInfo, HistoryItem, HistoryPage, Notice};

/// 自己签、还没提交的环在本地预演时用的日志位置：比任何真实位置都大，签名电脑一定还在。
const PREVIEW_LOG: u64 = u64::MAX - 1;
/// 换代、发消息遇到并发变化时最多重试几次。
const RETRIES: usize = 3;

/// 本地预演一批环：每签一环就在会话现状的副本上接上，后面的环、成员表、封装对象都按预演后的样子算。
struct Batch {
    state: ConvState,
    links: Vec<ConvLink>,
}

impl State {
    fn sign_conv(&self, batch: &mut Batch, me: &MemberRef, change: ConvChange) -> Result<()> {
        let body = batch.state.next_body(&me.uid, me.eldest, change, self.now_ms());
        let link = ConvLink::sign(&body, &self.creds.device);
        batch
            .state
            .apply(&link, PREVIEW_LOG, &self.book)
            .map_err(|e| ClientError::state(format!("这样改不了：{e}")))?;
        batch.links.push(link);
        Ok(())
    }

    /// 把会话钥匙某一代封装给一批成员（封装给他们账号钥匙的当前一代）。成员现在的身份必须和要封装的身份一致：
    /// 对方重置了账号就不封装，新钥匙不会落到只凭 Cindy 账号重置的人手里。
    pub(crate) async fn seal_to_members(&mut self, conn: &Conn, conv: &ConvId, generation: u32, seed: &ConvSeed, members: &[MemberRef], refresh: bool) -> Result<Vec<MemberKeyBox>> {
        let mut boxes = Vec::with_capacity(members.len());
        for member in members {
            if refresh || self.book.current(&member.uid).is_none() {
                self.book.load_account(conn, &member.uid, None).await?;
            }
            let state = self.book.current(&member.uid).ok_or_else(|| ClientError::state("对方还没开通"))?;
            if state.eldest != member.eldest {
                return Err(ClientError::verify(format!("{} 重置过账号，身份变了", member.uid)));
            }
            let key = state.current_key();
            let info = conv_seed_info(conv, generation, &member.uid, state.epoch, key.generation);
            boxes.push(MemberKeyBox {
                uid: member.uid.clone(),
                account_epoch: state.epoch,
                account_generation: key.generation,
                sealed: crypto::seal_to(&key.enc.0, &info, seed.as_bytes())?,
            });
        }
        Ok(boxes)
    }

    /// 我在某个会话里认识的这个人的身份（加好友时核对过、或邀请人签进群里的）。缓存里没有（刚启动）就把会话逐个取来找。
    async fn known_member(&mut self, conn: &Conn, uid: &Uid) -> Result<MemberRef> {
        if self.book.pinned_identity(uid).is_none() {
            for summary in self.convs(conn).await? {
                if summary.member && !self.book.convs.contains_key(&summary.conv) {
                    self.book.load_conv(conn, &summary.conv).await?;
                    if self.book.pinned_identity(uid).is_some() {
                        break;
                    }
                }
            }
        }
        let eldest = self.book.pinned_identity(uid).ok_or_else(|| ClientError::state("还不认识这个人，先加好友"))?;
        Ok(MemberRef { uid: uid.clone(), eldest })
    }

    /// 建会话：签第一环、封装第一代钥匙，成员账号钥匙刚换过代时刷新后重试一次。
    async fn create(&mut self, conn: &Conn, kind: ConvKind, members: Vec<MemberRef>, profile: Option<&GroupProfile>, via: Option<Via>) -> Result<ConvId> {
        self.require_active()?;
        self.ensure_account_keys(conn).await?;
        let me = self.my_ref(conn).await?;
        let conv = ConvId::random();
        let seed = ConvSeed::generate();
        let profile = profile.map(|p| p.seal(&conv, 1, &seed)).transpose()?;
        let change = ConvChange::Create {
            kind,
            members: members.clone(),
            key: seed.public(1),
            profile,
            via,
        };
        let link = ConvLink::sign(&create_body(&conv, &me, change, self.now_ms()), &self.creds.device);
        let mut refresh = false;
        loop {
            let boxes = self.seal_to_members(conn, &conv, 1, &seed, &members, refresh).await?;
            let request = Request::CreateConv {
                link: link.clone(),
                keys: ConvKeyBundle { generation: 1, boxes, prev: None },
            };
            match conn.request(request).await {
                Ok(Response::ConvCreated { .. }) => break,
                Ok(_) => return Err(ClientError::protocol("回执不对")),
                Err(ClientError::Server(error)) if error.code == ErrorCode::Conflict && error.message.starts_with("existing:") => {
                    // 私聊已经存在（比如两人同时加了对方）：直接用已有的。
                    let existing = ConvId::parse(&error.message["existing:".len()..]).map_err(|_| ClientError::protocol("已有私聊的编号不对"))?;
                    self.book.load_conv(conn, &existing).await?;
                    return Ok(existing);
                }
                Err(ClientError::Server(error)) if error.code == ErrorCode::RotationRequired && !refresh => refresh = true,
                Err(error) => return Err(error),
            }
        }
        self.keys.put_conv_seed(&conv, 1, seed);
        self.book.load_conv(conn, &conv).await?;
        tracing::info!(conv = %conv, ?kind, "会话已建");
        Ok(conv)
    }

    /// 加好友（契约 S9）：核对链接里的身份后直接建私聊，对方不用再点同意。返回私聊。
    pub async fn add_friend(&mut self, conn: &Conn, link: &crate::links::FriendLink) -> Result<ConvId> {
        let info = self.resolve_friend(conn, link).await?;
        if info.uid == self.uid {
            return Err(ClientError::state("这是你自己的好友链接"));
        }
        let me = self.my_ref(conn).await?;
        let them = MemberRef {
            uid: info.uid,
            eldest: link.eldest,
        };
        self.create(conn, ConvKind::Dm, vec![me, them], None, Some(Via::FriendLink)).await
    }

    /// 和群里的某个成员私聊（契约 S10）：身份以群里邀请人的签名为准。
    pub async fn open_dm(&mut self, conn: &Conn, uid: &Uid, group: &ConvId) -> Result<ConvId> {
        self.book.load_conv(conn, group).await?;
        let record = self.book.conv(conn, group).await?;
        if uid == &self.uid
            || record.state.kind != ConvKind::Group
            || !record.state.members.contains_key(&self.uid)
        {
            return Err(ClientError::state("只能添加同群的其他成员为好友"));
        }
        let eldest = record.state.members.get(uid).map(|m| m.eldest).ok_or_else(|| ClientError::state("对方不在这个群里"))?;
        let me = self.my_ref(conn).await?;
        let them = MemberRef { uid: uid.clone(), eldest };
        self.create(conn, ConvKind::Dm, vec![me, them], None, Some(Via::Group { conv: group.clone() })).await
    }

    /// 新建群（契约 S11）：成员是认识的人（好友或群友）。
    pub async fn create_group(&mut self, conn: &Conn, profile: &GroupProfile, uids: &[Uid]) -> Result<ConvId> {
        let mut members = vec![self.my_ref(conn).await?];
        for uid in uids {
            if members.iter().all(|m| &m.uid != uid) {
                let member = self.known_member(conn, uid).await?;
                members.push(member);
            }
        }
        self.create(conn, ConvKind::Group, members, Some(profile), None).await
    }

    /// 提交一批环（可带封装与群邀请种子），并发冲突时由调用方重试。
    async fn append(&mut self, conn: &Conn, conv: &ConvId, links: Vec<ConvLink>, keys: Option<ConvKeyBundle>, invite: Option<InviteSeed>) -> Result<()> {
        match conn
            .request(Request::AppendConv {
                conv: conv.clone(),
                links,
                keys,
                invite,
            })
            .await?
        {
            Response::Appended { .. } => {
                self.book.load_conv(conn, conv).await?;
                Ok(())
            }
            _ => Err(ClientError::protocol("回执不对")),
        }
    }

    async fn fresh_batch(&mut self, conn: &Conn, conv: &ConvId) -> Result<(Batch, MemberRef)> {
        self.require_active()?;
        self.book.load_conv(conn, conv).await?;
        let me = self.my_ref(conn).await?;
        let state = self.book.convs[conv].state.clone();
        Ok((Batch { state, links: Vec::new() }, me))
    }

    /// 这个会话里记的是我重置之前的身份（账号签名链第一环变了）。
    fn reset_here(&self, conv: &ConvId, me: &MemberRef) -> bool {
        self.book.convs.get(conv).is_some_and(|record| record.state.members.get(&self.uid).is_some_and(|mine| mine.eldest != me.eldest))
    }

    /// 我重置过账号的私聊。
    fn reset_in_dm(&self, conv: &ConvId, me: &MemberRef) -> bool {
        self.reset_here(conv, me) && self.book.convs.get(conv).is_some_and(|record| record.state.kind == ConvKind::Dm)
    }

    fn retryable(error: &ClientError) -> bool {
        matches!(error.code(), Some(ErrorCode::Invalid | ErrorCode::Conflict | ErrorCode::RotationRequired))
    }

    /// 邀请成员进群（契约 S12）：新成员拿到当前一代钥匙，沿旧钥匙链能看到以前的全部消息。
    pub async fn invite(&mut self, conn: &Conn, conv: &ConvId, uids: &[Uid]) -> Result<()> {
        let mut last = None;
        for attempt in 0..RETRIES {
            let (mut batch, me) = self.fresh_batch(conn, conv).await?;
            let mut members = Vec::with_capacity(uids.len());
            for uid in uids {
                members.push(self.known_member(conn, uid).await?);
            }
            self.sign_conv(&mut batch, &me, ConvChange::Add { members: members.clone() })?;
            let generation = batch.state.current_key().generation;
            let seed = self.conv_seed(conn, conv, generation).await?;
            let boxes = self.seal_to_members(conn, conv, generation, &seed, &members, attempt > 0).await?;
            let keys = ConvKeyBundle { generation, boxes, prev: None };
            match self.append(conn, conv, batch.links, Some(keys), None).await {
                Ok(()) => return Ok(()),
                Err(error) if Self::retryable(&error) => last = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(last.unwrap_or(ClientError::Timeout))
    }

    /// 换代：先补上需要的环（`before`，如移出某人），再处理重置过账号的成员，最后封装新一代给现在的全部成员。
    pub async fn rotate(&mut self, conn: &Conn, conv: &ConvId, before: Vec<ConvChange>) -> Result<()> {
        let mut last = None;
        for _ in 0..RETRIES {
            let (mut batch, me) = self.fresh_batch(conn, conv).await?;
            let previous_generation = batch.state.current_key().generation;
            for change in before.clone() {
                self.sign_conv(&mut batch, &me, change)?;
            }
            // 成员现在的身份：账号签名链当前一轮（刷新一次，换代很少发生）。
            let members: Vec<MemberRef> = batch.state.members.iter().map(|(uid, m)| MemberRef { uid: uid.clone(), eldest: m.eldest }).collect();
            let mut reset = None;
            for member in &members {
                self.book.load_account(conn, &member.uid, None).await?;
                let current = self.book.current(&member.uid).map(|s| s.eldest);
                if current == Some(member.eldest) {
                    continue;
                }
                match (batch.state.kind, current) {
                    (ConvKind::Group, _) => self.sign_conv(
                        &mut batch,
                        &me,
                        ConvChange::Remove {
                            uid: member.uid.clone(),
                            reason: RemoveReason::Reset,
                        },
                    )?,
                    (ConvKind::Dm, Some(eldest)) => reset = Some(MemberRef { uid: member.uid.clone(), eldest }),
                    (ConvKind::Dm, None) => return Err(ClientError::state("对方的账号不见了")),
                }
            }
            let seed = ConvSeed::generate();
            let generation = batch.state.current_key().generation + 1;
            let key = seed.public(generation);
            match &reset {
                Some(member) => {
                    // 重置的人自己接上私聊时以新身份签；对方改记时以我自己的身份签。
                    let author = if member.uid == self.uid { member.clone() } else { me.clone() };
                    self.sign_conv(&mut batch, &author, ConvChange::MemberReset { member: member.clone(), key })?;
                }
                None => self.sign_conv(&mut batch, &me, ConvChange::Rotate { key })?,
            }
            let members_after: Vec<MemberRef> = batch.state.members.iter().map(|(uid, m)| MemberRef { uid: uid.clone(), eldest: m.eldest }).collect();
            let boxes = self.seal_to_members(conn, conv, generation, &seed, &members_after, false).await?;
            // 对方重置后的这一代不带旧钥匙链：重置的人读不到以前的消息。
            let prev = match reset {
                Some(_) => None,
                None => {
                    let previous = self.conv_seed(conn, conv, previous_generation).await?;
                    Some(seed.wrap_previous(conv, generation, &previous))
                }
            };
            let keys = ConvKeyBundle { generation, boxes, prev };
            match self.append(conn, conv, batch.links, Some(keys), None).await {
                Ok(()) => {
                    self.keys.put_conv_seed(conv, generation, seed);
                    tracing::info!(conv = %conv, generation, "会话已换代");
                    return Ok(());
                }
                Err(error) if Self::retryable(&error) => {
                    tracing::info!(conv = %conv, %error, "换代时会话刚变过，刷新后重试");
                    last = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last.unwrap_or(ClientError::Timeout))
    }

    /// 群主移出成员（契约 S13）：同一个请求里换代，被移出的人读不到之后的消息。
    pub async fn kick(&mut self, conn: &Conn, conv: &ConvId, uid: &Uid) -> Result<()> {
        self.rotate(
            conn,
            conv,
            vec![ConvChange::Remove {
                uid: uid.clone(),
                reason: RemoveReason::Kicked,
            }],
        )
        .await
    }

    /// 退群（契约 S13）：剩下的成员下次发消息前换代。
    pub async fn leave(&mut self, conn: &Conn, conv: &ConvId) -> Result<()> {
        let (mut batch, me) = self.fresh_batch(conn, conv).await?;
        self.sign_conv(&mut batch, &me, ConvChange::Leave)?;
        self.append(conn, conv, batch.links, None, None).await
    }

    /// 改群名、头像、简介（只有成员看得到）。
    pub async fn set_group_profile(&mut self, conn: &Conn, conv: &ConvId, profile: &GroupProfile) -> Result<()> {
        let (mut batch, me) = self.fresh_batch(conn, conv).await?;
        let generation = batch.state.current_key().generation;
        let seed = self.conv_seed(conn, conv, generation).await?;
        let sealed = profile.seal(conv, generation, &seed)?;
        self.sign_conv(&mut batch, &me, ConvChange::SetProfile { profile: sealed, generation })?;
        self.append(conn, conv, batch.links, None, None).await
    }

    /// 群资料（解开后的群名、头像、简介）；私聊为空。
    pub async fn group_profile(&mut self, conn: &Conn, conv: &ConvId) -> Result<Option<GroupProfile>> {
        let Some((sealed, generation)) = self.book.conv(conn, conv).await?.state.profile.clone() else {
            return Ok(None);
        };
        let seed = self.conv_seed(conn, conv, generation).await?;
        Ok(Some(GroupProfile::open(&sealed, conv, generation, &seed)?))
    }

    /// 复制群邀请链接（契约 S12）：链接里的钥匙包着当前一代会话钥匙，服务器解不开。
    pub async fn create_invite_link(&mut self, conn: &Conn, conv: &ConvId) -> Result<InviteLink> {
        let (mut batch, me) = self.fresh_batch(conn, conv).await?;
        let secret = InviteSecret::generate();
        let invite = InviteId::random();
        let change = ConvChange::CreateInvite {
            invite: invite.clone(),
            public: secret.public(),
            expires_ms: self.now_ms() + limits::INVITE_TTL_MS,
        };
        self.sign_conv(&mut batch, &me, change)?;
        let generation = batch.state.current_key().generation;
        let seed = self.conv_seed(conn, conv, generation).await?;
        let wrapped = InviteSeed {
            invite: invite.clone(),
            generation,
            seed: secret.wrap_seed(conv, generation, &seed),
        };
        self.append(conn, conv, batch.links, None, Some(wrapped)).await?;
        Ok(InviteLink {
            base: http_base(&self.config.server),
            invite,
            secret,
        })
    }

    /// 作废群邀请链接。
    pub async fn revoke_invite(&mut self, conn: &Conn, conv: &ConvId, invite: &InviteId) -> Result<()> {
        let (mut batch, me) = self.fresh_batch(conn, conv).await?;
        self.sign_conv(&mut batch, &me, ConvChange::RevokeInvite { invite: invite.clone() })?;
        self.append(conn, conv, batch.links, None, None).await
    }

    /// 凭群邀请链接加入（契约 S12）：不用等别的成员在线。
    pub async fn join_by_invite(&mut self, conn: &Conn, link: &InviteLink) -> Result<ConvId> {
        self.require_active()?;
        self.ensure_account_keys(conn).await?;
        let Response::Invite {
            conv,
            generation,
            seed,
            entries,
        } = conn.request(Request::GetInvite { invite: link.invite.clone() }).await?
        else {
            return Err(ClientError::protocol("回执不对"));
        };
        // 还不是成员，取不到会话签名链：用邀请回执里的那一份，同样一环一环验。
        // 退过群的人本地还留着一份，但停在退群那一环（之后的换代、新邀请都收不到），只接它之后的环；
        // 不补齐就会在旧的链头上签加入，服务器按序号和上一环摘要拒掉。
        let known = self.book.convs.get(&conv).map(|r| r.state.seq);
        for entry in &entries {
            let seq = entry.link.parse().map_err(|e| ClientError::verify(format!("会话签名链：{e}")))?.seq;
            if known.is_none_or(|k| seq > k) {
                self.book.accept_conv_link(conn, &conv, &entry.link, entry.log).await?;
            }
        }
        let state = self.book.conv(conn, &conv).await?.state.clone();
        let invite = state.invites.get(&link.invite).ok_or_else(|| ClientError::verify("会话签名链里没有这个群邀请"))?;
        if invite.revoked || invite.expires_ms <= self.now_ms() {
            return Err(ClientError::state("群邀请已作废或过期"));
        }
        if invite.public != link.secret.public() {
            return Err(ClientError::verify("链接里的钥匙和群邀请对不上"));
        }
        let expected = state.key(generation).ok_or_else(|| ClientError::verify("群邀请的钥匙代数不在会话签名链里"))?;
        let conv_seed = link.secret.unwrap_seed(&conv, generation, &seed)?;
        conv_seed.check(expected).map_err(|e| ClientError::verify(e.to_string()))?;
        let me = self.my_ref(conn).await?;
        let proof = invite_join_proof(&link.secret, &conv, &link.invite, &me);
        let change = ConvChange::JoinByInvite {
            member: me.clone(),
            invite: link.invite.clone(),
            proof,
        };
        let body = state.next_body(&me.uid, me.eldest, change, self.now_ms());
        let join = ConvLink::sign(&body, &self.creds.device);
        let boxes = self.seal_to_members(conn, &conv, generation, &conv_seed, std::slice::from_ref(&me), false).await?;
        let response = conn
            .request(Request::JoinByInvite {
                conv: conv.clone(),
                link: join,
                keys: ConvKeyBundle { generation, boxes, prev: None },
            })
            .await?;
        if !matches!(response, Response::Appended { .. }) {
            return Err(ClientError::protocol("回执不对"));
        }
        self.keys.put_conv_seed(&conv, generation, conv_seed);
        self.book.load_conv(conn, &conv).await?;
        tracing::info!(conv = %conv, "已凭群邀请加入");
        Ok(conv)
    }

    /// 会话现状。
    pub async fn conv_info(&mut self, conn: &Conn, conv: &ConvId) -> Result<ConvInfo> {
        let record = self.book.conv(conn, conv).await?;
        let state = &record.state;
        Ok(ConvInfo {
            conv: conv.clone(),
            kind: state.kind,
            owner: state.owner.clone(),
            members: state.members.iter().map(|(uid, m)| MemberRef { uid: uid.clone(), eldest: m.eldest }).collect(),
            via: state.via.clone(),
            member: state.members.contains_key(&self.uid),
        })
    }

    /// 我重置账号之前就在、还记着我旧身份的群（契约 S7：重置后退出所有群，要群里的人重新邀请）。
    pub async fn groups_left_by_reset(&mut self, conn: &Conn) -> Result<Vec<ConvId>> {
        let me = self.my_ref(conn).await?;
        let mut left = Vec::new();
        for summary in self.convs(conn).await? {
            if summary.kind != ConvKind::Group {
                continue;
            }
            self.book.conv(conn, &summary.conv).await?;
            if self.reset_here(&summary.conv, &me) {
                left.push(summary.conv);
            }
        }
        Ok(left)
    }

    /// 我所在（和离开过）的会话。
    pub async fn convs(&mut self, conn: &Conn) -> Result<Vec<ConvSummary>> {
        self.require_active()?;
        match conn.request(Request::ListConvs).await? {
            Response::Convs { convs } => Ok(convs),
            _ => Err(ClientError::protocol("回执不对")),
        }
    }

    /// 发消息（契约 S14）。`id` 由调用方取：同一次发送重试时用同一个编号，服务器保证不会出现两条。
    /// 会话要先换代时（有人离开、成员换了钥匙、对方重置）先换代再发。返回（日志序号，服务器时间）。
    pub async fn send(&mut self, conn: &Conn, conv: &ConvId, id: &MsgId, content: Content, lan: &Lan) -> Result<(u64, i64)> {
        self.require_active()?;
        self.ensure_account_keys(conn).await?;
        let me = self.my_ref(conn).await?;
        let body = MessageBody {
            v: MESSAGE_VERSION,
            ctime_ms: self.now_ms(),
            content,
        };
        let mut last = None;
        for _ in 0..RETRIES {
            let record = self.book.conv(conn, conv).await?;
            if record.state.rotation_pending {
                self.rotate(conn, conv, Vec::new()).await?;
            }
            let generation = self.book.convs[conv].state.current_key().generation;
            let seed = match self.conv_seed(conn, conv, generation).await {
                Ok(seed) => seed,
                // 我重置过账号（契约 S7）：私聊的钥匙封装给的是旧身份，拿不到。以新身份接上这个私聊（换一代、封装给现在的
                // 两个人，对方看到“X 重置了账号”），再用新一代发。
                Err(error) if self.reset_in_dm(conv, &me) => {
                    self.rotate(conn, conv, Vec::new()).await?;
                    last = Some(error);
                    continue;
                }
                // 群里不能自己接上：要群里的人重新邀请（契约 S7）。
                Err(_) if self.reset_here(conv, &me) => {
                    return Err(ClientError::state("你重置过账号，要群里的人重新邀请你，才能在这个群里说话。"));
                }
                Err(error) => return Err(error),
            };
            let sender = Sender {
                uid: &self.uid,
                eldest: me.eldest,
                device: &self.creds.device,
            };
            let env = Envelope::seal(conv, id.clone(), generation, &seed, &sender, &body)?;
            let members: Vec<Uid> = self.book.convs[conv].state.members.keys().cloned().collect();
            let mut allowed_devices = Vec::<DeviceId>::new();
            for uid in &members {
                if self.book.current(uid).is_none() { let _ = self.book.load_account(conn, uid, None).await; }
                if let Some(account) = self.book.current(uid) {
                    allowed_devices.extend(account.active_devices().map(|(device, _)| device.clone()));
                }
            }
            let offered = lan.offer(&env, &members, &allowed_devices).await;
            let direct = !offered.is_empty();
            let request = if direct { Request::SendLan { env: env.clone() } } else { Request::Send { env: env.clone() } };
            match conn.request(request).await {
                Ok(Response::Sent { log, ts_ms }) if direct => {
                    let delivered = lan.commit(id, log, ts_ms, &offered).await;
                    if let Err(error) = conn.request(Request::ReleaseMessage { conv: conv.clone(), id: id.clone(), direct_devices: delivered.clone() }).await {
                        // 消息已经持久化；释放失败时保留服务器同步语义，重连后仍能补拉。
                        tracing::warn!(%error, conv = %conv, "释放直连消息的服务器推送失败，稍后由同步补齐");
                    }
                    return Ok((log, ts_ms));
                }
                Ok(Response::Sent { log, ts_ms }) => return Ok((log, ts_ms)),
                Ok(_) => return Err(ClientError::protocol("回执不对")),
                Err(error) => {
                    if direct { lan.cancel(id, &offered).await; }
                    match error.code() {
                    Some(ErrorCode::RotationRequired) => {
                        self.rotate(conn, conv, Vec::new()).await?;
                        last = Some(error);
                    }
                    Some(ErrorCode::Conflict) => {
                        // 别人刚换过代：刷新会话签名链后用新一代重发；代数没变就是消息编号被占用。
                        self.book.load_conv(conn, conv).await?;
                        if self.book.convs[conv].state.current_key().generation == generation {
                            return Err(error);
                        }
                        last = Some(error);
                    }
                        _ => return Err(error),
                    }
                }
            }
        }
        Err(last.unwrap_or(ClientError::Timeout))
    }

    /// 往前翻一页历史：消息解开核对，会话签名链里同一段的系统提示合进来，按日志序号从新到旧。
    /// `window` 是服务器时间的范围（毫秒，两端都含、可以只给一端）：消息按服务器时间筛，系统提示按签它的人写的时间筛。
    pub async fn history(&mut self, conn: &Conn, conv: &ConvId, before: Option<u64>, limit: u32, window: (Option<i64>, Option<i64>)) -> Result<HistoryPage> {
        self.require_active()?;
        let (since_ms, until_ms) = window;
        let Response::Messages { items, more } = conn
            .request(Request::History {
                conv: conv.clone(),
                before,
                limit: limit.clamp(1, limits::HISTORY_PAGE_MAX),
                since_ms,
                until_ms,
            })
            .await?
        else {
            return Err(ClientError::protocol("回执不对"));
        };
        self.book.load_conv(conn, conv).await?;
        let upper = before.unwrap_or(u64::MAX);
        let lower = if more { items.last().map_or(0, |m| m.log) } else { 0 };
        let mut page = Vec::with_capacity(items.len());
        for msg in &items {
            match self.open_message(conn, msg).await {
                Ok(message) => page.push(HistoryItem::Message(message)),
                Err(error) => page.push(HistoryItem::Rejected {
                    id: msg.env.id.clone(),
                    log: msg.log,
                    ts_ms: msg.ts_ms,
                    sender: msg.env.sender.clone(),
                    reason: error.to_string(),
                }),
            }
        }
        let record = &self.book.convs[conv];
        let in_window = |ms: i64| since_ms.is_none_or(|s| ms >= s) && until_ms.is_none_or(|u| ms <= u);
        for (link, log) in &record.links {
            if *log > lower
                && *log < upper
                && let Some(notice) = Notice::from_link(conv, link, *log)
                && in_window(notice.ctime_ms)
            {
                page.push(HistoryItem::Notice(notice));
            }
        }
        page.sort_by_key(|item| std::cmp::Reverse(item.log()));
        Ok(HistoryPage { items: page, more })
    }

    /// 会话活动：自己所在的会话里 `since_ms` 起有消息的，每个会话最早、最新一条的服务器时间（不解任何内容）。
    pub async fn activity(&mut self, conn: &Conn, since_ms: i64) -> Result<Vec<ConvActivity>> {
        self.require_active()?;
        match conn.request(Request::Activity { since_ms }).await? {
            Response::Activity { items } => Ok(items),
            _ => Err(ClientError::protocol("回执不对")),
        }
    }
}
