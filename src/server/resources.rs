//! 资源与上传（protocol-v1 §9）。
//!
//! - 读：资源键里有文件编号与文件钥匙（`translate::resource_key`），按宿主要的那一段向服务器取盖住它的加密块、
//!   在本机逐块核对后解开。一段至多 1 MiB，断了宿主从断处接着读。
//! - 上传：Cindy IM 的文件要用会话的人才看得见的钥匙加密，上传时就得知道发到哪个会话，所以 `uploads/*` 只把字节
//!   暂存进宿主给的临时目录、核对长度与摘要，`messages/send` 带着这个键来时才加密上传（§9.2 允许的做法）。
//!   暂存至多 32 份、一小时，发出去就删。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use friend_im_client::core::file::FILE_NAME_MAX_CHARS;
use friend_im_client::core::ids::MsgId;
use friend_im_client::core::limits;
use hhh_im_protocol::method::{
    ResourceChunk, ResourcesReadParams, UploadsAbortParams, UploadsBeginParams, UploadsBeginResult,
    UploadsChunkParams, UploadsFinishParams, UploadsFinishResult,
};
use hhh_im_protocol::rpc::{ErrorKind, RpcError};
use hhh_im_protocol::types::ResourceKind;
use serde_json::Value;
use sha2::{Digest, Sha256};
#[cfg(not(target_os = "wasi"))]
use tokio::fs;
use tokio::io::AsyncWriteExt;

use super::{Server, errors, translate};

/// WASI 构建（wasm32-wasip2）的暂存文件读写：tokio 在 WASI 上没有后台线程，`tokio::fs` 用不了；这里给出本文件
/// 用到的那几样、名字与用法相同，内部直接做同步的 `std::fs`（都是宿主临时目录里的小操作）。
#[cfg(target_os = "wasi")]
mod fs {
    use std::io::Write as _;
    use std::path::Path;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    pub(super) async fn remove_file(path: impl AsRef<Path>) -> std::io::Result<()> {
        std::fs::remove_file(path)
    }

    pub(super) async fn create_dir_all(path: impl AsRef<Path>) -> std::io::Result<()> {
        std::fs::create_dir_all(path)
    }

    pub(super) struct File(std::fs::File);

    impl File {
        pub(super) async fn create(path: impl AsRef<Path>) -> std::io::Result<Self> {
            std::fs::File::create(path).map(Self)
        }
    }

    pub(super) struct OpenOptions(std::fs::OpenOptions);

    impl OpenOptions {
        pub(super) fn new() -> Self {
            Self(std::fs::OpenOptions::new())
        }

        pub(super) fn append(&mut self, append: bool) -> &mut Self {
            self.0.append(append);
            self
        }

        pub(super) async fn open(&self, path: impl AsRef<Path>) -> std::io::Result<File> {
            self.0.open(path).map(File)
        }
    }

    impl tokio::io::AsyncWrite for File {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(self.0.write(buf))
        }

        fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(self.0.flush())
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(self.0.flush())
        }
    }
}

/// 一段至多读多少（协议上限）。
const SEGMENT_MAX: u64 = 1024 * 1024;
/// 同时暂存几份上传。
const STAGED_MAX: usize = 32;
/// 暂存多久没发就删。
const STAGED_TTL: Duration = Duration::from_secs(3600);
/// 暂存键的前缀。
const KEY_PREFIX: &str = "u.";

/// 一份暂存的上传。
struct Staged {
    path: PathBuf,
    name: String,
    kind: ResourceKind,
    bytes: u64,
    written: u64,
    hasher: Sha256,
    finished: bool,
    created: Instant,
}

/// 暂存好、要发出去的附件。
pub(crate) struct Attachment {
    pub(crate) path: PathBuf,
    pub(crate) name: String,
    pub(crate) bytes: u64,
    pub(crate) image: bool,
}

/// 上传的暂存区。
#[derive(Default)]
pub(crate) struct Uploads {
    dir: OnceLock<PathBuf>,
    staged: tokio::sync::Mutex<HashMap<String, Staged>>,
}

impl Uploads {
    /// 用宿主给的临时目录（`initialize` 时给）。
    pub(crate) fn set_dir(&self, dir: &str) {
        let _ = self.dir.set(PathBuf::from(dir).join("friend-im-uploads"));
    }

    fn dir(&self) -> PathBuf {
        self.dir
            .get()
            .cloned()
            .unwrap_or_else(|| std::env::temp_dir().join("friend-im-uploads"))
    }

    /// 要发的一个附件（还在暂存区、已经传完）。
    pub(crate) async fn attachment(&self, key: &str) -> Option<Attachment> {
        let id = key.strip_prefix(KEY_PREFIX)?;
        let staged = self.staged.lock().await;
        let found = staged.get(id).filter(|s| s.finished)?;
        Some(Attachment {
            path: found.path.clone(),
            name: found.name.clone(),
            bytes: found.bytes,
            image: found.kind == ResourceKind::Image,
        })
    }

    /// 发出去了：删掉暂存。
    pub(crate) async fn done(&self, key: &str) {
        let Some(id) = key.strip_prefix(KEY_PREFIX) else {
            return;
        };
        if let Some(staged) = self.staged.lock().await.remove(id) {
            remove(&staged.path).await;
        }
    }
}

async fn remove(path: &Path) {
    if let Err(error) = fs::remove_file(path).await
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::info!(%error, "删暂存的上传没成");
    }
}

fn to_value(value: impl serde::Serialize) -> Value {
    serde_json::to_value(value).expect("结果总能写成 JSON")
}

impl Server {
    /// Cindy IM 只存一份加密附件，解密后的同一份字节用于显示和保存。
    pub(crate) async fn describe_resource(
        &self,
        params: hhh_im_protocol::method::ResourcesDescribeParams,
    ) -> Result<Value, RpcError> {
        self.live().await?;
        let file = translate::file_of_key(&params.key)
            .ok_or_else(|| errors::of(ErrorKind::NotFound, "这个附件的编号不对。"))?;
        Ok(to_value(hhh_im_protocol::ResourceVariants {
            variants: vec![hhh_im_protocol::ResourceVariant {
                id: "file".into(),
                preview: params.kind == ResourceKind::Image,
                original: true,
                bytes: Some(file.size),
                ..Default::default()
            }],
        }))
    }

    /// `resources/read`：读一段图片或文件。
    pub(crate) async fn read_resource(
        &self,
        params: ResourcesReadParams,
    ) -> Result<Value, RpcError> {
        if params.variant.as_deref().is_some_and(|id| id != "file") {
            return Err(errors::of(
                ErrorKind::NotFound,
                "Cindy IM 没有这个附件版本。",
            ));
        }
        let live = self.live().await?;
        let file = translate::file_of_key(&params.key)
            .ok_or_else(|| errors::of(ErrorKind::NotFound, "这个附件的编号不对。"))?;
        if params.offset > file.size {
            return Err(errors::of(
                ErrorKind::InvalidRequest,
                "读的位置超出了文件大小。",
            ));
        }
        let length = params.length.min(SEGMENT_MAX);
        let data = live
            .client
            .read_range(&file, params.offset, length)
            .await
            .map_err(|error| {
                tracing::info!(file = %file.id, offset = params.offset, %error, "读附件没成");
                errors::client(&error)
            })?;
        let eof = params.offset + data.len() as u64 >= file.size;
        Ok(to_value(ResourceChunk {
            data: BASE64.encode(&data),
            total: Some(file.size),
            sha256: None,
            eof,
        }))
    }

    /// `uploads/begin`：开一份暂存。
    pub(crate) async fn upload_begin(&self, params: UploadsBeginParams) -> Result<Value, RpcError> {
        if params.bytes > limits::FILE_PLAIN_MAX {
            return Err(errors::of(
                ErrorKind::LimitExceeded,
                "附件超过 100 MiB，Cindy IM 发不了。",
            ));
        }
        let name = params.name.trim();
        if name.is_empty()
            || name.chars().count() > FILE_NAME_MAX_CHARS
            || name.chars().any(char::is_control)
        {
            return Err(errors::of(
                ErrorKind::InvalidRequest,
                "附件的文件名不对（不能为空、不超过 255 个字）。",
            ));
        }
        let dir = self.uploads.dir();
        fs::create_dir_all(&dir).await.map_err(|error| {
            tracing::error!(%error, "建不了暂存目录");
            errors::of(ErrorKind::Disconnected, "插件的临时目录写不进去。")
        })?;
        let id = MsgId::random().to_string();
        let path = dir.join(&id);
        fs::File::create(&path).await.map_err(|error| {
            tracing::error!(%error, "建不了暂存文件");
            errors::of(ErrorKind::Disconnected, "插件的临时目录写不进去。")
        })?;
        let mut staged = self.uploads.staged.lock().await;
        let now = Instant::now();
        let mut expired: Vec<String> = staged
            .iter()
            .filter(|(_, s)| now.duration_since(s.created) > STAGED_TTL)
            .map(|(k, _)| k.clone())
            .collect();
        if staged.len() - expired.len() >= STAGED_MAX
            && let Some(oldest) = staged
                .iter()
                .filter(|(k, _)| !expired.contains(k))
                .min_by_key(|(_, s)| s.created)
                .map(|(k, _)| k.clone())
        {
            expired.push(oldest);
        }
        for key in expired {
            if let Some(old) = staged.remove(&key) {
                remove(&old.path).await;
            }
        }
        staged.insert(
            id.clone(),
            Staged {
                path,
                name: name.to_owned(),
                kind: params.kind,
                bytes: params.bytes,
                written: 0,
                hasher: Sha256::new(),
                finished: false,
                created: now,
            },
        );
        Ok(to_value(UploadsBeginResult { upload_id: id }))
    }

    /// `uploads/chunk`：按顺序写进暂存。
    pub(crate) async fn upload_chunk(&self, params: UploadsChunkParams) -> Result<Value, RpcError> {
        let data = BASE64.decode(&params.data).map_err(|_| {
            errors::of(ErrorKind::InvalidRequest, "上传的这一段不是合法的 base64。")
        })?;
        let mut staged = self.uploads.staged.lock().await;
        let entry = staged.get_mut(&params.upload_id).ok_or_else(|| {
            errors::of(
                ErrorKind::NotFound,
                "没有这次上传（可能已经过期），要重新上传。",
            )
        })?;
        if entry.finished || params.offset != entry.written {
            return Err(errors::of(
                ErrorKind::InvalidRequest,
                format!("上传的这一段位置不对：应该从 {} 开始。", entry.written),
            ));
        }
        if entry.written + data.len() as u64 > entry.bytes {
            return Err(errors::of(
                ErrorKind::InvalidRequest,
                "上传的内容比说好的大。",
            ));
        }
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&entry.path)
            .await
            .map_err(|error| {
                tracing::error!(%error, "打不开暂存文件");
                errors::of(ErrorKind::Disconnected, "插件的临时目录写不进去。")
            })?;
        file.write_all(&data).await.map_err(|error| {
            tracing::error!(%error, "写不进暂存文件");
            errors::of(ErrorKind::Disconnected, "插件的临时目录写不进去。")
        })?;
        entry.hasher.update(&data);
        entry.written += data.len() as u64;
        Ok(serde_json::json!({}))
    }

    /// `uploads/finish`：核对长度与摘要，给出发送时用的键。
    pub(crate) async fn upload_finish(
        &self,
        params: UploadsFinishParams,
    ) -> Result<Value, RpcError> {
        let mut staged = self.uploads.staged.lock().await;
        let entry = staged.get_mut(&params.upload_id).ok_or_else(|| {
            errors::of(
                ErrorKind::NotFound,
                "没有这次上传（可能已经过期），要重新上传。",
            )
        })?;
        if entry.written != entry.bytes {
            return Err(errors::of(
                ErrorKind::InvalidRequest,
                format!(
                    "上传不完整：收到 {} 字节，说好的是 {} 字节。",
                    entry.written, entry.bytes
                ),
            ));
        }
        let digest: String = entry
            .hasher
            .clone()
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if !digest.eq_ignore_ascii_case(params.sha256.trim()) {
            return Err(errors::of(
                ErrorKind::InvalidRequest,
                "上传的内容和摘要对不上。",
            ));
        }
        entry.finished = true;
        Ok(to_value(UploadsFinishResult {
            key: format!("{KEY_PREFIX}{}", params.upload_id),
        }))
    }

    /// `uploads/abort`：放弃，删掉暂存。
    pub(crate) async fn upload_abort(&self, params: UploadsAbortParams) -> Result<Value, RpcError> {
        if let Some(staged) = self.uploads.staged.lock().await.remove(&params.upload_id) {
            remove(&staged.path).await;
        }
        Ok(serde_json::json!({}))
    }
}
