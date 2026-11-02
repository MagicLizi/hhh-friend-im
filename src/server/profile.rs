//! 加密的个人资料与头像（契约 friend-im v6：头像用 HHH 自己的；第三阶段 plan-v1 §14.4 的个人资料机制沿用）。
//!
//! - **发出**：宿主经 `account/avatar` 交来本机用户的头像（自定义的，或画着名字的默认头像，契约 provider-protocol v35），
//!   插件在内存里记最新一张。个人资料不进对账集合：它连同头像字节直接交给在线的会话成员，每次和一台设备对账时也交一份，
//!   所以离线的人回来后照样拿到最新的。借来的凭据不发。不再写 Cindy 头像地址。
//! - **收到**：个人资料不显示成消息；按发送人记最新的一份（发送时间大的为准，内存里至多 [`PROFILES_MAX`] 人），推
//!   `people` 事件告诉宿主这个人的头像键；之后人名、成员、私聊会话都带上它。头像字节留在内存缓存里。
//! - **头像键**：头像文件写成 [`PHOTO_KEY_PREFIX`] 开头的键（文件编号、随机值、大小、类型）；自己的头像是 [`SELF_KEY_PREFIX`]
//!   开头的键，直接给内存里宿主交来的那张。旧版好友发的 https 地址仍按地址取（过渡）：
//!   只取 https、主机在允许的名单里、至多 [`AVATAR_MAX_BYTES`]、只收 PNG / JPEG / WebP / GIF。名单：Cindy 两个区域的域名
//!   （[`CINDY_AVATAR_DOMAINS`]，含子域名、只走默认端口），再加上自己旧头像地址的主机；好友不能借个人资料让插件去连任意网站。
//!   取过的都在内存里留最近 [`AVATAR_CACHE_MAX`] 张、合计不超过 [`AVATAR_CACHE_MAX_BYTES`]。

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64_URL};
use friend_im_client::core::bytes::Fixed;
use friend_im_client::core::file::FileRef;
use friend_im_client::core::ids::{FileId, Uid};
use friend_im_client::core::message::PHOTO_MAX;
use hhh_im_protocol::method::{AccountAvatarParams, AvatarsReadParams, ResourceChunk};
use hhh_im_protocol::rpc::{ErrorKind, RpcError};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use super::session::Live;
use super::{Server, errors};

/// 加密头像文件的头像键前缀：`fim-photo:v1:<文件编号>.<钥匙>.<字节数>.<p|j>`（约 90 字节，不超过协议的编号上限）。
pub(crate) const PHOTO_KEY_PREFIX: &str = "fim-photo:v1:";
/// 自己头像的头像键前缀：`fim-self:<摘要前 16 位>`，换了头像键就变、宿主重读。
pub(crate) const SELF_KEY_PREFIX: &str = "fim-self:";

/// 宿主交来的本机用户头像（`account/avatar`）：只在内存里，凭据里只记发过的摘要。
#[derive(Clone)]
pub(crate) struct HostPhoto {
    pub(crate) mime: String,
    pub(crate) bytes: std::sync::Arc<Vec<u8>>,
    pub(crate) sha256: String,
}

impl HostPhoto {
    /// 自己头像的头像键。
    pub(crate) fn self_key(&self) -> String {
        format!("{SELF_KEY_PREFIX}{}", &self.sha256[..16])
    }
}

/// 一份加密头像文件写成头像键。
pub(crate) fn photo_key(file: &FileRef) -> String {
    let kind = if file.mime == "image/jpeg" { 'j' } else { 'p' };
    format!("{PHOTO_KEY_PREFIX}{}.{}.{}.{kind}", file.id.as_str(), BASE64_URL.encode(file.key.0), file.size)
}

/// 头像键读回加密头像文件；不是这种键或写法不对为空。
pub(crate) fn parse_photo_key(key: &str) -> Option<FileRef> {
    let rest = key.strip_prefix(PHOTO_KEY_PREFIX)?;
    let mut parts = rest.split('.');
    let (id, secret, size, kind) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let secret: [u8; 32] = BASE64_URL.decode(secret).ok()?.try_into().ok()?;
    let size: u64 = size.parse().ok()?;
    let (name, mime) = match kind {
        "p" => ("avatar.png", "image/png"),
        "j" => ("avatar.jpg", "image/jpeg"),
        _ => return None,
    };
    (size <= PHOTO_MAX).then_some(FileRef {
        id: FileId::parse(id).ok()?,
        key: Fixed(secret),
        size,
        name: name.to_owned(),
        mime: mime.to_owned(),
        sha256: None,
    })
}

/// 收到的头像字节和个人资料里写的对得上：大小、摘要都一样，确实是图片。
pub(crate) fn photo_fits(file: &FileRef, bytes: &[u8]) -> bool {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    bytes.len() as u64 == file.size
        && bytes.len() as u64 <= PHOTO_MAX
        && file.sha256.is_some_and(|expected| expected.0 == digest)
        && image_mime(bytes).is_some()
}

/// 一份个人资料的头像键：新版的加密头像文件优先，旧版的 https 地址其次。
pub(crate) fn profile_key(avatar: Option<&str>, photo: Option<&FileRef>) -> Option<String> {
    photo.map(photo_key).or_else(|| avatar.and_then(avatar_key))
}

/// 记多少人的个人资料。
pub(crate) const PROFILES_MAX: usize = 4096;
/// 头像键（头像地址）至多多少字节：协议的编号上限。
pub(crate) const AVATAR_KEY_MAX: usize = 256;
/// 一张头像至多多少字节。
pub(crate) const AVATAR_MAX_BYTES: usize = 10 * 1024 * 1024;
/// 内存里留几张取过的头像。
pub(crate) const AVATAR_CACHE_MAX: usize = 64;
/// 内存里留的头像合计至多多少字节（张数没到也按它丢最旧的）。
pub(crate) const AVATAR_CACHE_MAX_BYTES: usize = 16 * 1024 * 1024;
/// 取一张头像至多等多久。
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);
/// 读头像一段至多多少（协议上限）。
const SEGMENT_MAX: u64 = 1024 * 1024;
/// Cindy 头像所在的域名（中国区、国际区）：头像在它们或它们的子域名上（实测中国区是 `hotfix.cindy.com.cn`）。
/// 两个区的人连同一个 Cindy IM 服务器、可以互加好友，所以两个都认。
pub(crate) const CINDY_AVATAR_DOMAINS: [&str; 2] = ["cindy.com.cn", "cindy.app"];

/// 一个头像地址能不能当头像键：https、不太长、没有空白与控制字符。
pub(crate) fn avatar_key(url: &str) -> Option<String> {
    (url.starts_with("https://")
        && url.len() <= AVATAR_KEY_MAX
        && !url.chars().any(|c| c.is_whitespace() || c.is_control()))
    .then(|| url.to_owned())
}

/// 地址的主机（`https://host[:port]/…` 里的 host:port，小写）。
pub(crate) fn host_of(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    (!host.is_empty() && !host.contains('@')).then(|| host.to_ascii_lowercase())
}

/// 主机（[`host_of`] 给的 host:port）是不是 Cindy 的头像域名或它的子域名：只认字母、数字、`-`、`.`，没有空段，
/// 端口只能不写或写 443。`evilcindy.app`、`cindy.app.evil.com` 都不算。
pub(crate) fn is_cindy_avatar_host(host: &str) -> bool {
    let name = match host.split_once(':') {
        Some((name, "443")) => name,
        Some(_) => return false,
        None => host,
    };
    let well_formed = !name.is_empty()
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
        && name.split('.').all(|label| !label.is_empty());
    well_formed
        && CINDY_AVATAR_DOMAINS
            .iter()
            .any(|domain| name == *domain || name.strip_suffix(domain).is_some_and(|sub| sub.ends_with('.')))
}

/// 这么多字节的头像收不收（不超过 [`AVATAR_MAX_BYTES`]）。
pub(crate) fn avatar_fits(len: usize) -> bool {
    len <= AVATAR_MAX_BYTES
}

/// 按文件头认出图片格式（只收这四种）。
pub(crate) fn image_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        Some("image/png")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else {
        None
    }
}

/// 收到的个人资料：账号 → （发送时间，头像键）。
#[derive(Default)]
pub(crate) struct Profiles {
    seen: Mutex<HashMap<Uid, (u64, Option<String>)>>,
}

impl Profiles {
    /// 记下一份个人资料（头像键见 [`profile_key`]）；比已记的新（发送时间大）才算数。返回这个人的头像是不是变了
    /// （变了要告诉宿主）。
    pub(crate) fn note(&self, uid: &Uid, log: u64, key: Option<String>) -> bool {
        let mut seen = self.seen.lock().expect("个人资料锁中毒");
        if let Some((known, previous)) = seen.get(uid) {
            if *known >= log {
                return false;
            }
            if *previous == key {
                seen.insert(uid.clone(), (log, key));
                return false;
            }
        }
        if seen.len() >= PROFILES_MAX && !seen.contains_key(uid) {
            // 满了：丢掉最旧的那份，下次对账时再认识。
            if let Some(oldest) = seen.iter().min_by_key(|(_, (log, _))| *log).map(|(uid, _)| uid.clone()) {
                seen.remove(&oldest);
            }
        }
        seen.insert(uid.clone(), (log, key));
        true
    }

    /// 这个人现在的头像键。
    pub(crate) fn avatar(&self, uid: &Uid) -> Option<String> {
        self.seen.lock().expect("个人资料锁中毒").get(uid).and_then(|(_, key)| key.clone())
    }
}

/// 取过的头像（地址 → 字节），按最近使用留 [`AVATAR_CACHE_MAX`] 张、合计不超过 [`AVATAR_CACHE_MAX_BYTES`]。
pub(crate) struct Avatars {
    http: friend_im_client::web::Client,
    /// 除 Cindy 头像域名外再允许取头像的主机（自己头像地址的主机）。
    allowed: Mutex<Option<String>>,
    cache: Mutex<VecDeque<(String, std::sync::Arc<Vec<u8>>)>>,
}

impl Default for Avatars {
    fn default() -> Self {
        Self {
            http: friend_im_client::web::Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .timeout(FETCH_TIMEOUT)
                .redirect(friend_im_client::web::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            allowed: Mutex::new(None),
            cache: Mutex::new(VecDeque::new()),
        }
    }
}

impl Avatars {
    /// 认下自己头像地址的主机（登录、上线时）。
    pub(crate) fn allow_host_of(&self, own_avatar: Option<&str>) {
        if let Some(host) = own_avatar.and_then(host_of) {
            *self.allowed.lock().expect("头像名单锁中毒") = Some(host);
        }
    }

    /// 这个地址能不能取：https、主机是 Cindy 的头像域名，或是自己头像地址的主机。
    pub(crate) fn may_fetch(&self, url: &str) -> bool {
        avatar_key(url).is_some()
            && host_of(url).is_some_and(|host| {
                is_cindy_avatar_host(&host) || self.allowed.lock().expect("头像名单锁中毒").as_deref() == Some(host.as_str())
            })
    }

    /// 一张头像的全部字节（先看内存，没有再取）。
    ///
    /// # Errors
    /// 地址不让取、取不到、太大、不是图片时返回给人看的原因。
    pub(crate) async fn get(&self, url: &str) -> Result<std::sync::Arc<Vec<u8>>, String> {
        if let Some(found) = self.cached(url) {
            return Ok(found);
        }
        if !self.may_fetch(url) {
            tracing::info!("头像地址不在允许的主机上，不取");
            return Err("这个头像不能显示。".into());
        }
        let mut response = self.http.get(url).send().await.map_err(|error| {
            tracing::info!(%error, "头像取不到");
            "头像取不到。".to_owned()
        })?;
        if !response.status().is_success() {
            tracing::info!(status = %response.status(), "头像取不到");
            return Err("头像取不到。".into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|error| {
            tracing::info!(%error, "头像没取完");
            "头像取不到。".to_owned()
        })? {
            bytes.extend_from_slice(&chunk);
            if !avatar_fits(bytes.len()) {
                tracing::info!("头像太大，不取");
                return Err("头像太大。".into());
            }
        }
        if image_mime(&bytes).is_none() {
            tracing::info!("取到的头像不是认得的图片");
            return Err("头像不是图片。".into());
        }
        let bytes = std::sync::Arc::new(bytes);
        self.remember(url, bytes.clone());
        Ok(bytes)
    }

    /// 记进缓存（最新的放最后），再按张数与合计字节数丢最旧的；最新的一张总留着。
    pub(crate) fn remember(&self, url: &str, bytes: std::sync::Arc<Vec<u8>>) {
        let mut cache = self.cache.lock().expect("头像缓存锁中毒");
        cache.retain(|(key, _)| key != url);
        cache.push_back((url.to_owned(), bytes));
        let mut total: usize = cache.iter().map(|(_, bytes)| bytes.len()).sum();
        while cache.len() > 1 && (cache.len() > AVATAR_CACHE_MAX || total > AVATAR_CACHE_MAX_BYTES) {
            if let Some((_, dropped)) = cache.pop_front() {
                total -= dropped.len();
            }
        }
    }

    pub(crate) fn cached(&self, url: &str) -> Option<std::sync::Arc<Vec<u8>>> {
        let mut cache = self.cache.lock().expect("头像缓存锁中毒");
        let at = cache.iter().position(|(key, _)| key == url)?;
        let entry = cache.remove(at)?;
        let bytes = entry.1.clone();
        cache.push_back(entry);
        Some(bytes)
    }

    /// 测试用：放一张进缓存。
    #[cfg(test)]
    pub(crate) fn put(&self, url: &str, bytes: Vec<u8>) {
        self.remember(url, std::sync::Arc::new(bytes));
    }
}

/// 宿主交来的头像核对后读出来：形状合规（协议 v35）、base64 解得开、字节数与摘要对得上、确实是 PNG / JPEG。
///
/// # Errors
/// 哪一项对不上就回参数错误（给人看的原因）。
pub(crate) fn host_photo(params: AccountAvatarParams) -> Result<Option<HostPhoto>, RpcError> {
    let Some(avatar) = params.avatar else {
        return Ok(None);
    };
    if let Some(problem) = avatar.problem() {
        return Err(errors::of(ErrorKind::InvalidRequest, problem));
    }
    let bytes = BASE64
        .decode(avatar.data.as_bytes())
        .map_err(|_| errors::of(ErrorKind::InvalidRequest, "头像 base64 解不开。"))?;
    let sha256: String = Sha256::digest(&bytes).iter().map(|byte| format!("{byte:02x}")).collect();
    if bytes.len() as u64 != avatar.size || sha256 != avatar.sha256 {
        return Err(errors::of(ErrorKind::InvalidRequest, "头像的字节数或摘要对不上。"));
    }
    if image_mime(&bytes) != Some(avatar.mime.as_str()) {
        return Err(errors::of(ErrorKind::InvalidRequest, "头像内容与类型对不上。"));
    }
    Ok(Some(HostPhoto { mime: avatar.mime, bytes: std::sync::Arc::new(bytes), sha256 }))
}

impl Server {
    /// `account/avatar`（契约 provider-protocol v35）：记下宿主交来的本机用户头像，告诉宿主“我的头像换了”，在线时在后台
    /// 交给各会话的在线成员。
    pub(crate) async fn account_avatar(self: &std::sync::Arc<Self>, params: AccountAvatarParams) -> Result<Value, RpcError> {
        let photo = host_photo(params)?;
        tracing::info!(
            has_avatar = photo.is_some(),
            size = photo.as_ref().map_or(0, |p| p.bytes.len()),
            "收到宿主交来的本机用户头像"
        );
        *self.photo.lock().expect("头像锁中毒") = photo;
        if let Ok(live) = self.live().await {
            super::push::me_changed(&live).await;
            let (server, sending) = (self.clone(), live.clone());
            let task = tokio::spawn(async move { server.announce_photo(&sending).await });
            live.hold(task.abort_handle());
        }
        Ok(serde_json::json!({}))
    }

    /// 把头像交给各会话的在线成员。借来的凭据不发；还没收到头像不发；不在线的人下次对账时拿到。
    pub(crate) async fn announce_photo(&self, live: &Live) {
        if live.read_only || self.photo.lock().expect("头像锁中毒").is_none() {
            return;
        }
        let convs = match live.client.convs().await {
            Ok(convs) => convs,
            Err(error) => {
                tracing::info!(%error, "会话列表取不到，个人资料下次再发");
                return;
            }
        };
        for summary in convs.into_iter().filter(|summary| summary.member) {
            live.devices.announce(summary.conv);
        }
    }

    /// 一张头像的全部字节：自己的直接给内存里那张；别人的在收到个人资料时存进了缓存；旧版的 https 地址按允许名单取。
    async fn avatar_bytes(&self, key: &str) -> Result<std::sync::Arc<Vec<u8>>, String> {
        if key.starts_with(SELF_KEY_PREFIX) {
            return self.photo.lock().expect("头像锁中毒").as_ref().map(|photo| photo.bytes.clone()).ok_or_else(|| {
                tracing::info!("自己的头像还没收到");
                "还没有头像。".to_owned()
            });
        }
        if parse_photo_key(key).is_none() {
            return self.avatars.get(key).await;
        }
        self.avatars.cached(key).ok_or_else(|| {
            tracing::debug!("这张头像还没从对方那里收到");
            "头像取不到。".to_owned()
        })
    }

    /// `avatars/read`：按头像键读一段。不让取、取不到时回“没有”。
    pub(crate) async fn read_avatar(&self, params: AvatarsReadParams) -> Result<Value, RpcError> {
        let bytes = self.avatar_bytes(&params.key).await.map_err(|reason| errors::of(ErrorKind::NotFound, reason))?;
        let total = bytes.len() as u64;
        if params.offset > total {
            return Err(errors::of(ErrorKind::InvalidRequest, "读的位置超出了头像大小。"));
        }
        let end = (params.offset + params.length.min(SEGMENT_MAX)).min(total);
        let chunk = ResourceChunk {
            data: BASE64.encode(&bytes[params.offset as usize..end as usize]),
            total: Some(total),
            sha256: None,
            eof: end >= total,
        };
        Ok(serde_json::to_value(chunk).expect("结果总能写成 JSON"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 头像键：只收 https、不太长、不含空白；主机取地址里的那一段。
    #[test]
    fn avatar_keys_and_hosts() {
        assert_eq!(avatar_key("https://a.example.com/u/1.png").as_deref(), Some("https://a.example.com/u/1.png"));
        assert!(avatar_key("http://a.example.com/1.png").is_none());
        assert!(avatar_key(&format!("https://a.com/{}", "x".repeat(AVATAR_KEY_MAX))).is_none());
        assert!(avatar_key("https://a.com/a b").is_none());
        assert_eq!(host_of("https://CDN.example.com:443/a?b").as_deref(), Some("cdn.example.com:443"));
        assert!(host_of("https://user@evil.com/a").is_none());
        assert!(host_of("ftp://a.com/x").is_none());
    }

    // 只收四种图片。
    #[test]
    fn only_known_images_are_avatars() {
        assert_eq!(image_mime(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0]), Some("image/png"));
        assert_eq!(image_mime(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("image/jpeg"));
        assert_eq!(image_mime(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert_eq!(image_mime(b"GIF89a.."), Some("image/gif"));
        assert_eq!(image_mime(b"<svg>"), None);
    }

    // 个人资料按日志序号认最新的；头像没变不报；满了丢最旧的。
    #[test]
    fn the_latest_profile_wins() {
        let profiles = Profiles::default();
        let (a, b) = (Uid::from_raw([1; 16]), Uid::from_raw([2; 16]));
        let key = |url: &str| profile_key(Some(url), None);
        assert!(profiles.note(&a, 10, key("https://x.com/1.png")));
        assert!(!profiles.note(&a, 9, key("https://x.com/0.png")), "旧的不算");
        assert!(!profiles.note(&a, 11, key("https://x.com/1.png")), "没变不报");
        assert!(profiles.note(&a, 12, None), "撤掉头像要报");
        assert_eq!(profiles.avatar(&a), None);
        assert!(profiles.note(&b, 1, key("http://x.com/insecure.png")), "第一次见要报");
        assert_eq!(profiles.avatar(&b), None, "不是 https 的不当头像");
    }

    fn photo(mime: &str, size: u64) -> FileRef {
        let name = if mime == "image/jpeg" { "avatar.jpg" } else { "avatar.png" };
        FileRef { id: FileId::from_raw([3; 16]), key: Fixed([4; 32]), size, name: name.into(), mime: mime.into(), sha256: None }
    }

    // 加密头像文件写成头像键再读回来不走样；写法不对、太大、类型不认的都读不出来。
    #[test]
    fn photo_keys_round_trip_and_reject_bad_ones() {
        for mime in ["image/png", "image/jpeg"] {
            let file = photo(mime, 70_000);
            let key = photo_key(&file);
            assert!(key.starts_with(PHOTO_KEY_PREFIX));
            assert!(key.len() <= AVATAR_KEY_MAX, "头像键要放得进协议的编号");
            assert_eq!(parse_photo_key(&key), Some(file));
        }
        let key = photo_key(&photo("image/png", 70_000));
        assert!(parse_photo_key(&format!("{key}.x")).is_none(), "多一段不认");
        assert!(parse_photo_key(&key.replace(".p", ".g")).is_none(), "类型不认");
        assert!(parse_photo_key(&photo_key(&photo("image/png", PHOTO_MAX + 1))).is_none(), "太大不认");
        assert!(parse_photo_key("https://x.com/1.png").is_none());
    }

    // 个人资料带了加密头像文件就用它，没带才认旧版的 https 地址（过渡期）。
    #[test]
    fn a_profile_photo_wins_over_the_old_avatar_address() {
        let file = photo("image/png", 100);
        assert_eq!(profile_key(Some("https://x.com/1.png"), Some(&file)), Some(photo_key(&file)));
        assert_eq!(profile_key(Some("https://x.com/1.png"), None).as_deref(), Some("https://x.com/1.png"));
        assert_eq!(profile_key(Some("http://x.com/1.png"), None), None);
        assert_eq!(profile_key(None, None), None);
    }

    fn host_avatar(mime: &str, bytes: &[u8]) -> hhh_im_protocol::method::HostAvatar {
        hhh_im_protocol::method::HostAvatar {
            mime: mime.into(),
            data: BASE64.encode(bytes),
            sha256: Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect(),
            size: bytes.len() as u64,
        }
    }

    // 宿主交来的头像：合规的收下、撤掉的为空；摘要、字节数、内容类型对不上的回参数错误。
    #[test]
    fn host_photos_are_checked_before_use() {
        let png = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0];
        let ok = host_photo(AccountAvatarParams { avatar: Some(host_avatar("image/png", &png)) }).unwrap().unwrap();
        assert_eq!((ok.mime.as_str(), ok.bytes.len()), ("image/png", png.len()));
        assert_eq!(ok.self_key(), format!("{SELF_KEY_PREFIX}{}", &ok.sha256[..16]));
        assert!(host_photo(AccountAvatarParams { avatar: None }).unwrap().is_none());

        let mut tampered = host_avatar("image/png", &png);
        tampered.sha256 = "0".repeat(64);
        let wrong_type = host_avatar("image/jpeg", &png);
        let mut wrong_size = host_avatar("image/png", &png);
        wrong_size.size += 1;
        for avatar in [tampered, wrong_type, wrong_size] {
            let err = host_photo(AccountAvatarParams { avatar: Some(avatar) }).err().expect("要拒绝");
            assert!(matches!(err.data.map(|data| data.kind), Some(ErrorKind::InvalidRequest)));
        }
    }

    // Cindy 的头像实测有 1 MiB 出头的（一个组织身份的 PNG 是 1,062,747 字节）：照 HHH 读头像的上限收，不当成“太大”。
    #[test]
    fn a_cindy_avatar_a_little_over_one_mib_is_taken() {
        assert!(avatar_fits(1_062_747));
        assert!(avatar_fits(10 * 1024 * 1024), "和宿主读头像的上限一样");
        assert!(!avatar_fits(10 * 1024 * 1024 + 1));
    }

    // 缓存既按张数、也按合计字节数留最近的：大头像多了也占不了多少内存，最新的一张总在。
    #[test]
    fn the_avatar_cache_stays_within_count_and_bytes() {
        let avatars = Avatars::default();
        for i in 0..3 {
            avatars.put(&format!("https://x.com/{i}.png"), vec![0; 7 * 1024 * 1024]);
        }
        assert!(avatars.cached("https://x.com/0.png").is_none(), "超出合计字节数，最旧的丢掉");
        assert!(avatars.cached("https://x.com/2.png").is_some());
        for i in 0..AVATAR_CACHE_MAX + 6 {
            avatars.put(&format!("https://y.com/{i}.png"), vec![0; 10]);
        }
        let cache = avatars.cache.lock().unwrap();
        assert_eq!(cache.len(), AVATAR_CACHE_MAX);
        assert!(cache.iter().map(|(_, bytes)| bytes.len()).sum::<usize>() <= AVATAR_CACHE_MAX_BYTES);
    }

    // 只从自己头像的主机取；缓存里的直接给。
    #[tokio::test]
    async fn avatars_come_only_from_the_allowed_host() {
        let avatars = Avatars::default();
        assert!(!avatars.may_fetch("https://cdn.example.com/a.png"), "还没认主机");
        avatars.allow_host_of(Some("https://cdn.example.com/me.png"));
        assert!(avatars.may_fetch("https://cdn.example.com/a.png"));
        assert!(!avatars.may_fetch("https://evil.example.org/a.png"), "别的主机不取");
        assert!(avatars.get("https://evil.example.org/a.png").await.is_err());
        avatars.put("https://cdn.example.com/a.png", vec![0xFF, 0xD8, 0xFF, 0xE0]);
        assert_eq!(avatars.get("https://cdn.example.com/a.png").await.unwrap().len(), 4);
    }

    // 自己的 Cindy 身份没有头像（宿主给的 avatarUrl 为空）时，名单里没有自己头像的主机，好友的 Cindy 头像照样能取；
    // 以前名单只有自己头像的主机，自己没头像就谁的头像都不取。
    #[test]
    fn friends_cindy_avatars_are_taken_without_an_avatar_of_my_own() {
        let avatars = Avatars::default();
        avatars.allow_host_of(None);
        assert!(avatars.may_fetch("https://hotfix.cindy.com.cn/cindy/public/avatar/m1/a.png"), "中国区实测的头像主机");
        assert!(avatars.may_fetch("https://cdn.cindy.app/avatar/m1/a.png"), "国际区");
        assert!(avatars.may_fetch("https://cindy.app/avatar/a.png"));
        assert!(!avatars.may_fetch("https://cdn.example.com/a.png"), "别的网站仍不取");
        assert!(!avatars.may_fetch("http://hotfix.cindy.com.cn/a.png"), "只取 https");
    }

    // 只认 Cindy 的域名本身与子域名，默认端口；冒名的域名、别的端口都不算。
    #[test]
    fn only_real_cindy_hosts_count() {
        for host in ["cindy.com.cn", "hotfix.cindy.com.cn", "a.b.cindy.com.cn", "cindy.app", "cdn.cindy.app", "cdn.cindy.app:443"] {
            assert!(is_cindy_avatar_host(host), "{host}");
        }
        for host in [
            "evilcindy.app",
            "cindy.app.evil.com",
            "cindy.com.cn.evil.com",
            "xcindy.com.cn",
            "com.cn",
            "app",
            ".cindy.app",
            "a..cindy.app",
            "cdn.cindy.app:8443",
            "cdn.cindy.app:",
            "[::1]",
            "cindy_app",
            "",
        ] {
            assert!(!is_cindy_avatar_host(host), "{host}");
        }
        assert!(Avatars::default().may_fetch("https://HOTFIX.Cindy.com.cn/a.png"), "主机名不分大小写");
    }
}
