//! 插件的凭据（protocol-v1 §6.2）：HHH 存进系统凭据库、`session/open` 时原样交还的那一串。
//!
//! 里面是重新上线要的全部东西：服务器地址、账号编号、这台电脑的名字，以及客户端库的 [`Credentials`]
//! （电脑私钥 + 服务器发的登录凭证，约 0.2 KiB）。账号钥匙、会话钥匙每次连上后从服务器取回再解，不在这里。

use std::fmt;

use friend_im_client::Credentials;
use serde::{Deserialize, Serialize};

/// 凭据格式的版本：改格式时加 1，读到不认识的版本当成要重新登录。
pub const VERSION: u32 = 1;

/// 插件交给 HHH 保存的凭据。
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    /// 格式版本，见 [`VERSION`]。
    pub version: u32,
    /// 服务器地址（[`server_url`] 规整过的）。
    pub server: String,
    /// 账号编号。
    pub uid: String,
    /// 这台电脑的名字（第一次登录时报给服务器，“我的电脑”里显示）。
    pub device_name: String,
    /// 电脑私钥与登录凭证。
    pub device: Credentials,
    /// 自己的 Cindy 头像地址（旧宿主登录时给的 `hostAccount.avatarUrl`，第三阶段）；没有为空。新版不再用它当头像
    /// （契约 friend-im v6），只留着认旧好友头像所在的主机。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
}

impl Credential {
    /// 一份新凭据。
    pub fn new(server: &str, uid: &str, device_name: &str, device: Credentials) -> Self {
        Self {
            version: VERSION,
            server: server.to_owned(),
            uid: uid.to_owned(),
            device_name: device_name.to_owned(),
            device,
            avatar: None,
        }
    }

    /// 带上自己的头像地址（只收 https，别的当没有）。
    pub fn with_avatar(mut self, avatar: Option<&str>) -> Self {
        self.avatar = avatar.filter(|url| url.starts_with("https://")).map(str::to_owned);
        self
    }

    /// 写成交给 HHH 的字符串。
    pub fn encode(&self) -> String {
        serde_json::to_string(self).expect("凭据总能写成 JSON")
    }

    /// 读回 HHH 交还的字符串；格式不对或版本不认识时为 `None`（当成要重新登录）。
    pub fn decode(text: &str) -> Option<Self> {
        let credential: Self = serde_json::from_str(text).ok()?;
        (credential.version == VERSION).then_some(credential)
    }
}

impl fmt::Debug for Credential {
    // 不输出私钥与登录凭证。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Credential({}, {}, {:?})", self.server, self.uid, self.device)
    }
}

/// 规整服务器地址：去掉首尾空白与末尾的 `/`。只收 `https://`，以及本机测试用的 `http://127.0.0.1`、`http://localhost`；
/// 只能是网址本身（不带路径、查询、空白）。不合要求时为 `None`。
pub fn server_url(text: &str) -> Option<String> {
    let url = text.trim().trim_end_matches('/');
    let host = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://").filter(|rest| is_loopback(rest)))?;
    let valid = !host.is_empty() && !host.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '?' | '#' | '@'));
    valid.then(|| url.to_owned())
}

fn is_loopback(host_port: &str) -> bool {
    let host = host_port.rsplit_once(':').map_or(host_port, |(host, port)| if port.chars().all(|c| c.is_ascii_digit()) { host } else { host_port });
    matches!(host, "127.0.0.1" | "localhost")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_urls_are_https_or_local_and_only_the_origin() {
        assert_eq!(server_url(" https://im.example.com/ ").as_deref(), Some("https://im.example.com"));
        assert_eq!(server_url("http://127.0.0.1:18090").as_deref(), Some("http://127.0.0.1:18090"));
        assert_eq!(server_url("http://localhost").as_deref(), Some("http://localhost"));
        for bad in ["http://im.example.com", "https://", "im.example.com", "https://a.com/x", "https://a.com?x=1", "https://a b.com", "ftp://a.com", "https://user@a.com"] {
            assert_eq!(server_url(bad), None, "{bad}");
        }
    }

    #[test]
    fn credentials_round_trip_and_unknown_versions_are_refused() {
        let credential = Credential::new("https://im.example.com", "u", "台式机", Credentials::generate());
        let text = credential.encode();
        let back = Credential::decode(&text).expect("读得回来");
        assert_eq!((back.server.as_str(), back.uid.as_str(), back.device_name.as_str()), ("https://im.example.com", "u", "台式机"));
        assert_eq!(back.device.device.id(), credential.device.device.id());
        let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
        value["version"] = 2.into();
        assert!(Credential::decode(&value.to_string()).is_none());
        assert!(Credential::decode("不是 JSON").is_none());
        assert!(!format!("{credential:?}").contains(&text[text.len() - 20..]), "Debug 不带私钥");
    }

    // 头像地址是可选字段——不带时与第二阶段的凭据一字不差；旧版存的（带“发过的个人资料”）照样读回。
    #[test]
    fn the_avatar_field_is_optional_and_old_credentials_still_read() {
        let plain = Credential::new("https://im.example.com", "u", "台式机", Credentials::generate());
        let text = plain.encode();
        assert!(!text.contains("avatar"), "{text}");
        let old = plain.clone().with_avatar(Some("https://cdn.example.com/a.png"));
        let mut json: serde_json::Value = serde_json::from_str(&old.encode()).unwrap();
        json["announced"] = serde_json::json!({ "avatar": "https://cdn.example.com/a.png" });
        let back = Credential::decode(&json.to_string()).unwrap();
        assert_eq!(back.avatar, old.avatar, "旧版存的读得回");
        assert!(plain.with_avatar(Some("http://insecure/a.png")).avatar.is_none(), "只收 https");
    }
}
