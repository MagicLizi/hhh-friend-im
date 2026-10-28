//! 只恢复已建立关系的好友资料；不按消息时间筛选、不读取或发送消息。
use super::{Server, errors};
use friend_im_client::core::{conv::ConvKind, ids::ConvId, wire::ConvSummary};
use hhh_im_protocol::{
    method::{ConversationsListParams, Page},
    rpc::{ErrorKind, RpcError},
};
use serde_json::Value;

fn directory_page(
    summaries: Vec<ConvSummary>,
    params: &ConversationsListParams,
) -> Result<Page<ConvId>, RpcError> {
    if !(1..=100).contains(&params.limit) {
        return Err(errors::of(
            ErrorKind::InvalidRequest,
            "联系人每页条数应在 1 至 100 之间。",
        ));
    }
    if let Some(cursor) = &params.cursor {
        ConvId::parse(cursor)
            .map_err(|_| errors::of(ErrorKind::InvalidRequest, "联系人翻页位置无效。"))?;
    }
    let mut ids: Vec<_> = summaries
        .into_iter()
        .filter(|s| s.member && s.kind == ConvKind::Dm)
        .map(|s| s.conv)
        .filter(|id| {
            params
                .cursor
                .as_ref()
                .is_none_or(|c| id.as_str() > c.as_str())
        })
        .collect();
    ids.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    ids.dedup();
    let more = ids.len() > usize::from(params.limit);
    ids.truncate(usize::from(params.limit));
    let next = more.then(|| ids.last().expect("nonempty page").to_string());
    Ok(Page { items: ids, next })
}

impl Server {
    pub(crate) async fn contacts_list(
        &self,
        params: ConversationsListParams,
    ) -> Result<Value, RpcError> {
        let live = self.live().await?;
        let summaries = live.client.convs().await.map_err(|e| errors::client(&e))?;
        let page = directory_page(summaries, &params)?;
        let mut contacts = Vec::with_capacity(page.items.len());
        for id in page.items {
            // 不跳过取不到的好友并推进游标：整页失败，下次仍从同一个位置重试。
            let contact = live.conversation(&id).await.map_err(|e| {
                tracing::warn!(%id,error=%e,"好友资料未取到，保留这一页等待重试");
                errors::client(&e)
            })?;
            if contact
                .peer
                .as_deref()
                .is_none_or(|peer| peer.is_empty() || peer == live.me.as_str())
            {
                return Err(errors::of(
                    ErrorKind::InvalidRequest,
                    "好友身份未核对完整，请稍后重试。",
                ));
            }
            contacts.push(contact);
        }
        tracing::debug!(
            count = contacts.len(),
            more = page.next.is_some(),
            "已读取好友资料，没有读取聊天消息"
        );
        Ok(serde_json::to_value(Page {
            items: contacts,
            next: page.next,
        })
        .expect("contact page serializes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn summary(n: u8, kind: ConvKind, member: bool, last_log: u64) -> ConvSummary {
        ConvSummary {
            conv: ConvId::from_raw([n; 16]),
            kind,
            member,
            last_log,
            chain_seq: 1,
        }
    }
    #[test]
    fn contacts_include_empty_and_old_private_chats_without_groups_or_departed_members() {
        let page = directory_page(
            vec![
                summary(1, ConvKind::Dm, true, 0),
                summary(2, ConvKind::Dm, true, 7),
                summary(3, ConvKind::Group, true, 100),
                summary(4, ConvKind::Dm, false, 100),
            ],
            &ConversationsListParams {
                limit: 100,
                cursor: None,
            },
        )
        .unwrap();
        assert_eq!(page.items.len(), 2);
        assert!(page.next.is_none());
    }
    #[test]
    fn contact_pages_are_stable_deduplicated_and_validate_the_cursor() {
        let all = vec![
            summary(2, ConvKind::Dm, true, 0),
            summary(1, ConvKind::Dm, true, 0),
            summary(2, ConvKind::Dm, true, 0),
        ];
        let first = directory_page(
            all.clone(),
            &ConversationsListParams {
                limit: 1,
                cursor: None,
            },
        )
        .unwrap();
        let second = directory_page(
            all,
            &ConversationsListParams {
                limit: 1,
                cursor: first.next,
            },
        )
        .unwrap();
        assert_ne!(first.items, second.items);
        assert!(second.next.is_none());
        assert!(
            directory_page(
                vec![],
                &ConversationsListParams {
                    limit: 0,
                    cursor: None
                }
            )
            .is_err()
        );
        assert!(
            directory_page(
                vec![],
                &ConversationsListParams {
                    limit: 1,
                    cursor: Some("invalid".into())
                }
            )
            .is_err()
        );
    }
}
