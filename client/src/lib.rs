//! Cindy IM 客户端库：连服务器、核对签名链、钥匙缓存、同步与断线重连。不认识 HHH 协议，插件把它翻成 HHH 的插件协议。
//!
//! - 只认自己验过的东西：服务器给的账号签名链、会话签名链、钥匙封装、消息，每一样都按 `friend-im-core` 的规则核对，
//!   对不上就报 [`ClientError::Verify`] 或推 [`Update::ConvRejected`] / [`Update::MessageRejected`]，不当成正常内容。
//! - 不存聊天记录：要长期保存的只有 [`Credentials`]（电脑私钥 + 服务器登录凭证，交给 HHH 存系统凭据库）
//!   和同步位置（[`Update::Position`]）；账号钥匙、会话钥匙每次连上后从服务器取回再解，内存里的缓存都有上限。
//! - 断线自动重连，从同步位置补拉，不漏不重。
//!
//! # Examples
//!
//! ```no_run
//! use friend_im_client::{Client, Config, Credentials, Update};
//! use friend_im_client::core::ids::MsgId;
//! use friend_im_client::core::message::{Content, Part};
//!
//! # async fn demo(cindy_token: String) -> friend_im_client::Result<()> {
//! let config = Config { server: "https://im.example.com".into(), device_name: "台式机".into() };
//! // 第一次登录：新生成电脑钥匙，交 Cindy 凭证；之后用凭据里服务器发的登录凭证。
//! let (client, mut updates) = Client::connect(config, Credentials::generate(), Some(cindy_token), None).await?;
//! let recovery = client.provision().await?; // 第一台电脑开通，恢复密钥只给用户看一次
//! let _ = recovery.to_groups();
//! let link = client.friend_link(false).await?; // 发给朋友
//! # let friend_link = link.clone();
//! let dm = client.add_friend(&friend_link).await?;
//! let text = Content::Post { parts: vec![Part::Text { text: "你好".into() }], reply_to: None };
//! client.send(&dm, &MsgId::random(), text).await?;
//! while let Some(update) = updates.recv().await {
//!     if let Update::Message(message) = update {
//!         println!("{} 发来一条消息", message.sender);
//!     }
//! }
//! # Ok(())
//! # }
//! ```

mod book;
mod client;
mod conn;
mod error;
mod files;
mod friends;
mod keyring;
mod lan;
mod links;
mod ops_account;
mod ops_conv;
mod reading;
mod state;
mod types;
#[cfg(target_os = "wasi")]
mod wasi_net;

/// HTTP 客户端（文件上传下载、取头像）：原生构建就是 reqwest；WASI 构建是 `web_wasi.rs` 里接口同名的小实现，
/// 调用处不分平台。
#[cfg(not(target_os = "wasi"))]
pub use reqwest as web;
#[cfg(target_os = "wasi")]
#[path = "web_wasi.rs"]
pub mod web;

pub use client::{Client, Updates};
pub use error::{ClientError, Result};
pub use friends::{FriendRequestInfo, FriendRequestPage};
pub use links::{FriendLink, InviteLink};
pub use reading::{MessageReceipt, ReadingMark};
pub use types::{
    AccountNotice, Config, ConvInfo, ConvNotice, Credentials, HistoryItem, HistoryPage, JoinStart,
    Message, Notice, Update,
};

/// 两边共用的格式（编号、消息内容、群资料等），原样转出，插件不用另外依赖。
pub use friend_im_core as core;
