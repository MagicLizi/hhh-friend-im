//! Translate the encrypted account ledger into the host's optional approval UI.
use super::{Server, errors};
use friend_im_client::{
    FriendRequestInfo,
    core::{
        friends::{FriendRequestStatus as Status, FriendSource, REQUEST_COOLDOWN_MS},
        ids::{ConvId, RequestId, Uid},
    },
};
use hhh_im_protocol::{
    contact_requests::*,
    rpc::{ErrorKind, RpcError},
};
use serde_json::Value;

impl Server {
    pub(crate) async fn friend_requests(
        &self,
        command: ContactRequestsCommand,
    ) -> Result<Value, RpcError> {
        if !command.valid() {
            return Err(errors::of(ErrorKind::InvalidRequest, "好友申请参数无效。"));
        }
        // Calling this optional method opts this host connection into ledger invalidations.
        self.friend_events
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let live = self.live().await?;
        let invalid = || errors::of(ErrorKind::InvalidRequest, "好友申请编号或身份无效。");
        let (records, next) = match command {
            ContactRequestsCommand::List {
                incoming,
                cursor,
                user_id,
            } => {
                let before = cursor
                    .map(|c| c.parse::<u64>().map_err(|_| invalid()))
                    .transpose()?;
                let peer = user_id
                    .map(|s| Uid::parse(&s).map_err(|_| invalid()))
                    .transpose()?;
                let page = live
                    .client
                    .friend_requests(incoming, before, peer)
                    .await
                    .map_err(|e| errors::client(&e))?;
                (page.requests, page.next.map(|n| n.to_string()))
            }
            ContactRequestsCommand::Send {
                request_id,
                conversation_id,
                user_id,
                message,
            } => {
                let id = RequestId::parse(&request_id).map_err(|_| invalid())?;
                let group = ConvId::parse(&conversation_id).map_err(|_| invalid())?;
                let user = Uid::parse(&user_id).map_err(|_| invalid())?;
                let request = live
                    .client
                    .request_group_friend(&id, &user, &group, &message)
                    .await
                    .map_err(|e| errors::client(&e))?;
                (vec![request], None)
            }
            ContactRequestsCommand::Respond { request_id, action } => {
                let id = RequestId::parse(&request_id).map_err(|_| invalid())?;
                let request = match action {
                    ContactRequestAction::Accept => live.client.accept_friend(&id).await,
                    ContactRequestAction::Reject => {
                        live.client.close_friend_request(&id, false).await
                    }
                    ContactRequestAction::Withdraw => {
                        live.client.close_friend_request(&id, true).await
                    }
                }
                .map_err(|e| errors::client(&e))?;
                (vec![request], None)
            }
            ContactRequestsCommand::Resend {
                request_id,
                new_request_id,
                message,
            } => {
                let id = RequestId::parse(&request_id).map_err(|_| invalid())?;
                let new_id = RequestId::parse(&new_request_id).map_err(|_| invalid())?;
                let request = live
                    .client
                    .resend_friend_request(&id, &new_id, &message)
                    .await
                    .map_err(|e| errors::client(&e))?;
                (vec![request], None)
            }
        };
        let mut items = vec![];
        for FriendRequestInfo { record, message } in records {
            let body = &record.envelope.body;
            let incoming = body.to.uid == live.me;
            let user = if incoming {
                &body.from.uid
            } else {
                &body.to.uid
            };
            let names = live.names([user.clone()]).await;
            let (source_conversation_id, source_label) = match &body.source {
                FriendSource::Group { conv } => (
                    Some(conv.to_string()),
                    match live.conversation(conv).await {
                        Ok(group) => format!("来自群聊 · {}", group.name),
                        Err(_) => "来自已不可用的群聊".into(),
                    },
                ),
                FriendSource::Link { .. } => (None, "来自好友链接".into()),
            };
            let retry_after_ms = matches!(record.status, Status::Rejected | Status::Withdrawn)
                .then(|| record.updated_ms.saturating_add(REQUEST_COOLDOWN_MS));
            items.push(ContactRequest {
                request_id: body.id.to_string(),
                incoming,
                user_id: user.to_string(),
                name: names.get(user).cloned().unwrap_or_else(|| "群友".into()),
                message,
                source_conversation_id,
                source_label,
                state: match record.status {
                    Status::Pending => ContactRequestState::Pending,
                    Status::Accepted => ContactRequestState::Accepted,
                    Status::Rejected => ContactRequestState::Rejected,
                    Status::Withdrawn => ContactRequestState::Withdrawn,
                    Status::Expired => ContactRequestState::Expired,
                },
                created_ms: record.created_ms,
                updated_ms: record.updated_ms,
                expires_ms: record.expires_ms,
                retry_after_ms,
                conversation_id: record.conversation.map(|c| c.to_string()),
            });
        }
        let pending = live
            .client
            .friend_requests(true, None, None)
            .await
            .map_err(|e| errors::client(&e))?
            .pending;
        Ok(serde_json::to_value(ContactRequestsResult {
            items,
            next,
            pending,
        })
        .expect("friend result serializes"))
    }
}
