//! Explicit, encrypted friend approval. List/get never create a conversation.
use crate::{Client, ClientError, FriendLink, Result, conn::Conn, state::State};
use friend_im_core::{
    bytes::Fixed,
    conv::{ConvKind, MemberRef, Via},
    friends::{
        FriendRequestBody, FriendRequestEnvelope, FriendRequestStatus, FriendSource,
        StoredFriendRequest,
    },
    ids::{ConvId, RequestId, Uid},
    wire::{Request, Response},
};

#[derive(Clone, Debug)]
pub struct FriendRequestInfo {
    pub record: StoredFriendRequest,
    /// None when this account has reset and can no longer decrypt the old identity.
    pub message: Option<String>,
}
#[derive(Clone, Debug)]
pub struct FriendRequestPage {
    pub requests: Vec<FriendRequestInfo>,
    pub next: Option<u64>,
    pub pending: u32,
}

impl State {
    fn require_friends(&self) -> Result<()> {
        self.require_active()?;
        if !self.friend_requests {
            return Err(ClientError::state(
                "当前服务器尚未支持好友批准，请等待服务器升级",
            ));
        }
        Ok(())
    }

    async fn open_friend_request(
        &mut self,
        conn: &Conn,
        record: StoredFriendRequest,
    ) -> Result<FriendRequestInfo> {
        let b = &record.envelope.body;
        let me = self.my_ref(conn).await?;
        let member = if b.from.uid == self.uid {
            &b.from
        } else if b.to.uid == self.uid {
            &b.to
        } else {
            return Err(ClientError::verify("好友申请不属于当前账号"));
        };
        let device = self
            .book
            .ensure_device(
                conn,
                &b.from.uid,
                &b.from.eldest,
                &record.envelope.device,
                record.log,
            )
            .await?;
        record.envelope.verify(&device)?;
        let message = if member.eldest != me.eldest {
            None
        } else {
            let sealed = b
                .messages
                .iter()
                .find(|m| m.uid == self.uid)
                .ok_or_else(|| ClientError::verify("缺少验证消息"))?;
            if self
                .keys
                .account_seed(sealed.epoch, sealed.generation)
                .is_none()
            {
                self.load_account_keys(conn).await?;
            }
            let seed = self
                .keys
                .account_seed(sealed.epoch, sealed.generation)
                .ok_or_else(|| ClientError::verify("无法解开验证消息"))?;
            Some(record.envelope.open_message(&self.uid, seed, &device)?)
        };
        Ok(FriendRequestInfo { record, message })
    }

    async fn friend_result(
        &mut self,
        conn: &Conn,
        response: Response,
    ) -> Result<FriendRequestInfo> {
        let Response::FriendRequest { request } = response else {
            return Err(ClientError::protocol("好友申请回执不正确"));
        };
        self.open_friend_request(conn, *request).await
    }

    async fn send_friend_request(
        &mut self,
        conn: &Conn,
        id: &RequestId,
        to: MemberRef,
        source: FriendSource,
        message: &str,
    ) -> Result<FriendRequestInfo> {
        self.require_friends()?;
        let from = self.my_ref(conn).await?;
        // Recover an uncertain acknowledgement using the operation id before sealing again.
        match conn
            .request(Request::FriendRequestGet {
                request: id.clone(),
            })
            .await
        {
            Ok(response) => {
                let existing = self.friend_result(conn, response).await?;
                let b = &existing.record.envelope.body;
                if b.from != from
                    || b.to != to
                    || b.source != source
                    || existing.message.as_deref() != Some(message)
                {
                    return Err(ClientError::state("申请编号已用于另一条申请，请刷新后重试"));
                }
                return Ok(existing);
            }
            Err(ClientError::Server(e)) if e.code == friend_im_core::wire::ErrorCode::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut body = FriendRequestBody {
            id: id.clone(),
            from: from.clone(),
            to: to.clone(),
            source,
            messages: vec![],
        };
        for member in [&from, &to] {
            self.book.load_account(conn, &member.uid, None).await?;
            let account = self
                .book
                .current(&member.uid)
                .ok_or_else(|| ClientError::state("账号尚未开通"))?;
            if account.eldest != member.eldest {
                return Err(ClientError::verify("账号身份已变化，请重新打开名片"));
            }
            let key = account.current_key();
            body.seal_message(
                member.uid.clone(),
                account.epoch,
                key.generation,
                &key.enc.0,
                message,
            )?;
        }
        let envelope = FriendRequestEnvelope::sign(body, &self.creds.device)?;
        let response = conn
            .request(Request::FriendRequestSend { envelope })
            .await?;
        self.friend_result(conn, response).await
    }

    async fn request_group_friend(
        &mut self,
        conn: &Conn,
        id: &RequestId,
        uid: &Uid,
        group: &ConvId,
        message: &str,
    ) -> Result<FriendRequestInfo> {
        self.require_friends()?;
        self.book.load_conv(conn, group).await?;
        let state = &self.book.conv(conn, group).await?.state;
        if uid == &self.uid
            || state.kind != ConvKind::Group
            || !state.members.contains_key(&self.uid)
        {
            return Err(ClientError::state("只能添加同群的其他成员"));
        }
        let eldest = state
            .members
            .get(uid)
            .ok_or_else(|| ClientError::state("对方不在群里"))?
            .eldest;
        self.send_friend_request(
            conn,
            id,
            MemberRef {
                uid: uid.clone(),
                eldest,
            },
            FriendSource::Group {
                conv: group.clone(),
            },
            message,
        )
        .await
    }

    async fn request_link_friend(
        &mut self,
        conn: &Conn,
        id: &RequestId,
        link: &FriendLink,
        message: &str,
    ) -> Result<FriendRequestInfo> {
        self.require_friends()?;
        let info = self.resolve_friend(conn, link).await?;
        let token = Fixed(
            link.token
                .0
                .as_slice()
                .try_into()
                .map_err(|_| ClientError::state("好友链接无效"))?,
        );
        self.send_friend_request(
            conn,
            id,
            MemberRef {
                uid: info.uid,
                eldest: link.eldest,
            },
            FriendSource::Link { token },
            message,
        )
        .await
    }

    async fn list_friend_requests(
        &mut self,
        conn: &Conn,
        incoming: bool,
        before: Option<u64>,
        peer: Option<Uid>,
    ) -> Result<FriendRequestPage> {
        self.require_friends()?;
        let Response::FriendRequests {
            requests,
            next,
            pending,
        } = conn
            .request(Request::FriendRequests {
                before,
                limit: 50,
                incoming,
                peer: peer.clone(),
            })
            .await?
        else {
            return Err(ClientError::protocol("好友申请列表回执不正确"));
        };
        if requests.len() > 50 {
            return Err(ClientError::protocol("好友申请列表超过分页边界"));
        }
        let mut result = vec![];
        for record in requests {
            let b = &record.envelope.body;
            let (owner, other) = if incoming {
                (&b.to.uid, &b.from.uid)
            } else {
                (&b.from.uid, &b.to.uid)
            };
            if owner != &self.uid || peer.as_ref().is_some_and(|p| p != other) {
                return Err(ClientError::verify("好友申请查询范围不一致"));
            }
            result.push(self.open_friend_request(conn, record).await?);
        }
        Ok(FriendRequestPage {
            requests: result,
            next,
            pending,
        })
    }

    async fn accept_friend(&mut self, conn: &Conn, id: &RequestId) -> Result<FriendRequestInfo> {
        self.require_friends()?;
        let response = conn
            .request(Request::FriendRequestGet {
                request: id.clone(),
            })
            .await?;
        let info = self.friend_result(conn, response).await?;
        let b = &info.record.envelope.body;
        if b.to.uid != self.uid {
            return Err(ClientError::state("只有接收方可以同意"));
        }
        if info.record.status != FriendRequestStatus::Pending {
            return Ok(info);
        }
        if info.message.is_none() {
            return Err(ClientError::state("身份已变化，请让对方重新申请"));
        }
        let via = match &b.source {
            FriendSource::Group { conv } => Via::Group { conv: conv.clone() },
            FriendSource::Link { .. } => Via::FriendLink,
        };
        self.create_accepted_friend(conn, id, vec![b.to.clone(), b.from.clone()], via)
            .await?;
        let response = conn
            .request(Request::FriendRequestGet {
                request: id.clone(),
            })
            .await?;
        self.friend_result(conn, response).await
    }
}

impl Client {
    pub async fn resend_friend_request(
        &self,
        request: &RequestId,
        new_request: &RequestId,
        message: &str,
    ) -> Result<FriendRequestInfo> {
        self.call(async |s, c| {
            s.require_friends()?;
            let response = c
                .request(Request::FriendRequestGet {
                    request: request.clone(),
                })
                .await?;
            let previous = s.friend_result(c, response).await?;
            let body = previous.record.envelope.body;
            if body.from.uid != s.uid {
                return Err(ClientError::state("只能重新发送自己发出的申请"));
            }
            match body.source {
                FriendSource::Group { conv } => {
                    s.request_group_friend(c, new_request, &body.to.uid, &conv, message)
                        .await
                }
                source @ FriendSource::Link { .. } => {
                    s.send_friend_request(c, new_request, body.to, source, message)
                        .await
                }
            }
        })
        .await
    }
    pub async fn supports_friend_requests(&self) -> Result<bool> {
        self.call(async |s, _| Ok(s.friend_requests)).await
    }
    pub async fn friend_requests(
        &self,
        incoming: bool,
        before: Option<u64>,
        peer: Option<Uid>,
    ) -> Result<FriendRequestPage> {
        self.call(async |s, c| s.list_friend_requests(c, incoming, before, peer).await)
            .await
    }
    pub async fn request_group_friend(
        &self,
        id: &RequestId,
        uid: &Uid,
        group: &ConvId,
        message: &str,
    ) -> Result<FriendRequestInfo> {
        self.call(async |s, c| s.request_group_friend(c, id, uid, group, message).await)
            .await
    }
    pub async fn request_link_friend(
        &self,
        id: &RequestId,
        link: &FriendLink,
        message: &str,
    ) -> Result<FriendRequestInfo> {
        self.call(async |s, c| s.request_link_friend(c, id, link, message).await)
            .await
    }
    pub async fn accept_friend(&self, id: &RequestId) -> Result<FriendRequestInfo> {
        self.call(async |s, c| s.accept_friend(c, id).await).await
    }
    pub async fn close_friend_request(
        &self,
        id: &RequestId,
        withdraw: bool,
    ) -> Result<FriendRequestInfo> {
        self.call(async |s, c| {
            s.require_friends()?;
            let response = c
                .request(if withdraw {
                    Request::FriendRequestWithdraw {
                        request: id.clone(),
                    }
                } else {
                    Request::FriendRequestReject {
                        request: id.clone(),
                    }
                })
                .await?;
            s.friend_result(c, response).await
        })
        .await
    }
}
