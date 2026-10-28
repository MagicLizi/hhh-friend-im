//! `initialize`（protocol-v1 §4.1、§5）：插件信息、平台说明、能力与设置项。`tests/initialize.rs` 用 hhh-im-check 同一套规则核对。
//!
//! - 能重读历史（`history = server`）：服务器按会话存着全部密文，随时能翻；新消息另有实时推送。
//! - 每条消息能回复；本人发的能撤回，不限时（服务器上的密文随之删除）。不能编辑、不能点表情、没有话题。
//! - 附件上限与服务器一致：图片、文件都到 100 MiB；文件名按字节算，255 字节以内（服务器按 255 个字收）。
//! - 设置只有一项：服务器地址，默认填用户自己部署的那台。
//! - 第三阶段：只有一种登录方式“用 Cindy 账号登录”（`host`，[`super::login`]）；账号级操作五项、群的操作三项
//!   （[`super::actions`]）；能读头像（头像键是 Cindy 头像地址）、会推“人变了”（收到别人的个人资料）。

use friend_im_client::core::limits;
use hhh_im_protocol::method::{
    ActionDecl, ActionScope, InitializeParams, InitializeResult, ProviderInfo,
};
use hhh_im_protocol::platform::{
    AccountCaps, ActionRules, AvatarShape, Capabilities, ConversationCaps, DiscoveryDesc,
    EventCaps, HistoryMode, Limits, MessageCaps, OwnWithin, PeopleCaps, PlatformDesc, RateBudget,
    ResourceCaps, SendCaps, SettingDecl,
};
use hhh_im_protocol::rpc::{ErrorKind, RpcError};
use hhh_im_protocol::types::ConversationKind;
use serde_json::Value;

use super::{actions, errors, login};

/// 插件编号（同清单 `id`）。
pub(crate) const PROVIDER_ID: &str = "friend-im";
/// 给用户看的名字（同清单 `name`）。
pub(crate) const PROVIDER_NAME: &str = "Cindy IM";
/// 设置项：服务器地址。
pub(crate) const SETTING_SERVER: &str = "serverUrl";
/// 服务器地址的默认值：Cindy IM 的官方服务器（契约 §8：服务器地址是插件的设置项，默认填官方的那台）。
pub(crate) const DEFAULT_SERVER: &str = "https://hhh-friend-im.magiclizi.com";
/// 一页最多几条（同服务器的上限）。
pub(crate) const PAGE_MAX: u32 = limits::HISTORY_PAGE_MAX;
/// 文件按多大一段读：16 个加密块，正好 1 MiB 明文（协议一段的上限）。
pub(crate) const FILE_SEGMENT_BYTES: u64 = 1024 * 1024;
/// 附件名的上限（字节）：服务器按 255 个字收，这里按字节写 255，任何写法都不会超。
const ATTACHMENT_NAME_MAX_BYTES: u32 = 255;

/// 平台说明。
pub(crate) fn platform() -> PlatformDesc {
    PlatformDesc {
        avatar_shape: AvatarShape::Circle,
        avatar_identity: None,
        history: HistoryMode::Server,
        actions: ActionRules {
            reply: true,
            thread: false,
            react: false,
            recall: Some(OwnWithin {
                own: true,
                within_secs: None,
            }),
            edit: None,
        },
        chat_link: None,
        image_name_prefix: Some(PROVIDER_NAME.into()),
        conversation_nouns: None,
        page_max: Some(PAGE_MAX),
        // 服务器不限读取；新电脑补齐 1 万条要翻 100 页（契约 §7：5 分钟内），比宿主默认的每分钟 120 次放宽一些。
        reads: Some(RateBudget {
            per_second: 20,
            per_minute: 600,
        }),
        downloads: None,
        file_segment_bytes: Some(FILE_SEGMENT_BYTES),
        limits: Some(Limits {
            image_upload_max_bytes: limits::FILE_PLAIN_MAX,
            file_upload_max_bytes: limits::FILE_PLAIN_MAX,
            attachment_name_max_bytes: ATTACHMENT_NAME_MAX_BYTES,
        }),
        read_defaults: None,
        threads: None,
        deleted_messages_vanish: false,
        reactions_in_reads: false,
        emoji_per_account: false,
        emoji: None,
        // 会话发现：一次问到底（服务器一次给全，至多 1000 个会话）。
        discovery: Some(DiscoveryDesc {
            fastest_secs: 30,
            pages: 1,
            cold_pages: 1,
        }),
        user_adjustable: Vec::new(),
        edits_by_content: Vec::new(),
        retranslate_rules: Vec::new(),
        content_repairs: Vec::new(),
        content_rereads: Vec::new(),
    }
}

/// 能力：做得到的都声明，做不到的（搜索、编辑、表情、定位私聊）不声明。
pub(crate) fn capabilities() -> Capabilities {
    Capabilities {
        rich_send: Default::default(),
        stickers: Default::default(),
        conversations: ConversationCaps {
            list: true,
            search: false,
            members: true,
            find_direct: false,
            recent_activity: true,
        },
        messages: MessageCaps {
            list: true,
            get: false,
        },
        people: PeopleCaps {
            contacts: true,
            get: true,
            search: false,
            ..Default::default()
        },
        send: Some(SendCaps {
            text: true,
            mentions: true,
            mention_all: true,
            image: true,
            file: true,
            lookup: true,
        }),
        recall: true,
        edit: false,
        reactions: Default::default(),
        resources: ResourceCaps {
            variants: true,
            read: true,
            avatars: true,
        },
        events: EventCaps {
            messages: true,
            deletions: false,
            reactions: false,
            conversations: true,
            people: true,
        },
        retranslate: false,
        message_maintenance: false,
        session: Default::default(),
        // 收宿主交来的本机用户头像，设成本人在 Cindy IM 的头像（契约 friend-im v6、provider-protocol v35）。
        account: AccountCaps { host_avatar: true },
        // 伙伴代发署名不声明（不在这一版范围）；性能自报由运行时替插件声明。
        agent_attribution: Default::default(),
        perf: false,
    }
}

/// 设置项：服务器地址。
pub(crate) fn settings() -> Vec<SettingDecl> {
    vec![SettingDecl {
        id: SETTING_SERVER.into(),
        label: "服务器地址".into(),
        required: true,
        // 同 `credential::server_url`：https 网址本身；本机测试可以是 http://127.0.0.1 或 http://localhost。
        pattern: Some(
            r"^\s*(https://[^\s/?#@]+|http://(127\.0\.0\.1|localhost)(:[0-9]+)?)/?\s*$".into(),
        ),
        help: Some("你的 Cindy IM 服务器（https 网址）。换了服务器要重新登录。".into()),
        field_type: Some("text".into()),
        default: Some(DEFAULT_SERVER.into()),
        ..Default::default()
    }]
}

/// 插件的操作（原型 friend-im-v2）：账号级的进“管理”菜单，群的三项进群的会话菜单；“删除会话”（HHH 契约
/// provider-protocol v18 §4）不写种类，私聊、群都有，排在最后。
pub(crate) fn actions() -> Vec<ActionDecl> {
    let account = |id: &str, label: &str, shortcut: bool| ActionDecl {
        id: id.into(),
        label: label.into(),
        scope: ActionScope::Account,
        shortcut,
        conversation_kinds: Vec::new(),
    };
    let group = |id: &str, label: &str| ActionDecl {
        id: id.into(),
        label: label.into(),
        scope: ActionScope::Conversation,
        shortcut: false,
        conversation_kinds: vec![ConversationKind::Group],
    };
    vec![
        account(actions::DEVICES, "我的设备", false),
        account(actions::ADD, "加好友", true),
        account(actions::GROUP, "新建群", true),
        account(actions::LINK, "我的好友链接", true),
        account(actions::ABOUT, "关于加密", false),
        group(actions::MEMBERS, "群成员"),
        group(actions::INVITE, "邀请成员"),
        group(actions::LEAVE, "退出群"),
        ActionDecl {
            id: actions::DELETE.into(),
            label: "删除会话".into(),
            scope: ActionScope::Conversation,
            shortcut: false,
            conversation_kinds: Vec::new(),
        },
    ]
}

/// 握手结果。
pub(crate) fn result() -> InitializeResult {
    InitializeResult {
        protocol_version: 1,
        provider: ProviderInfo {
            id: PROVIDER_ID.into(),
            name: PROVIDER_NAME.into(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
        platform: platform(),
        capabilities: capabilities(),
        settings: settings(),
        login_methods: login::login_methods(),
        actions: actions(),
        // 读取前不向宿主申请额度：Cindy IM 是自己的服务器，没有平台限频要宿主统一结算。
        read_request_gating: false,
    }
}

/// `initialize`：宿主列出的版本里要有 1。
pub(crate) fn initialize(params: &InitializeParams) -> Result<Value, RpcError> {
    if !params.protocol_versions.contains(&1) {
        return Err(errors::of(
            ErrorKind::Unsupported,
            "Cindy IM 插件只会协议第 1 版，和这个 HHH 不兼容。",
        ));
    }
    Ok(serde_json::to_value(result()).expect("握手结果总能写成 JSON"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declaration_is_consistent() {
        let result = serde_json::to_value(result()).unwrap();
        assert_eq!(result["provider"]["id"], PROVIDER_ID);
        assert_eq!(result["platform"]["history"], "server");
        assert_eq!(result["platform"]["pageMax"], 100);
        assert_eq!(
            result["capabilities"]["messages"]["list"], true,
            "history=server 必须能读消息（§5.2）"
        );
        assert_eq!(
            result["capabilities"]["conversations"]["recentActivity"], true,
            "声明了会话发现就要能答"
        );
        assert_eq!(result["settings"][0]["default"], DEFAULT_SERVER);
        assert_eq!(
            result["loginMethods"][0]["kind"], "host",
            "只有用 Cindy 账号登录"
        );
        assert_eq!(result["loginMethods"].as_array().unwrap().len(), 1);
        assert_eq!(result["capabilities"]["resources"]["avatars"], true);
        assert_eq!(
            result["capabilities"]["account"]["hostAvatar"], true,
            "收宿主交来的头像"
        );
        assert_eq!(result["capabilities"]["events"]["people"], true);
        let actions = actions();
        assert_eq!(actions.len(), 9);
        assert_eq!(
            actions
                .iter()
                .filter(|a| a.shortcut)
                .map(|a| a.id.as_str())
                .collect::<Vec<_>>(),
            vec![actions::ADD, actions::GROUP, actions::LINK]
        );
        assert!(
            actions
                .iter()
                .filter(|a| a.shortcut)
                .all(|a| a.scope == ActionScope::Account)
        );
        for decl in &actions {
            assert_eq!(
                hhh_im_protocol::method::action_problem(decl),
                None,
                "{decl:?}"
            );
        }
        let ids: std::collections::HashSet<&str> = actions.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids.len(), actions.len(), "编号不重复");
        // 会话菜单：私聊只有“删除会话”，群是 群成员 · 邀请成员 · 退出群 · 删除会话（一份声明，HHH 契约 v18 §4）。
        let menu = |kind| {
            actions
                .iter()
                .filter(|a| a.scope == ActionScope::Conversation && a.applies_to(kind))
                .map(|a| a.label.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(menu(ConversationKind::Direct), ["删除会话"]);
        assert_eq!(
            menu(ConversationKind::Group),
            ["群成员", "邀请成员", "退出群", "删除会话"]
        );
        // 清单与握手的编号、名字一致。
        let manifest: Value =
            serde_json::from_str(include_str!("../../hhh-im-provider.json")).unwrap();
        assert_eq!(manifest["id"], PROVIDER_ID);
        assert_eq!(manifest["name"], PROVIDER_NAME);
        assert_eq!(
            manifest["version"],
            env!("CARGO_PKG_VERSION"),
            "清单与 Cargo.toml 的版本一致"
        );
    }
}
