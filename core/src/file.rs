//! 消息里对一个文件的引用。文件只在设备之间分段传：帧本身端到端加密，内容摘要随消息签名，
//! 所以任何一台设备提供的文件，收到的一方都能核对有没有被改过。

use serde::{Deserialize, Serialize};

use crate::bytes::Fixed;
use crate::error::{CoreError, Result};
use crate::ids::FileId;

/// 文件名最长多少个字符。
pub const FILE_NAME_MAX_CHARS: usize = 255;

/// 消息里对一个文件的引用（整个引用在加了密的消息正文里，服务器看不到）。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRef {
    /// 文件编号（发送设备取的）。
    pub id: FileId,
    /// 随机取的 32 字节：没拿到消息的人猜不出资源键，向别的设备要不到这个文件。
    pub key: Fixed<32>,
    /// 明文字节数。
    pub size: u64,
    /// 文件名。
    pub name: String,
    /// 类型（如 `image/png`）。
    pub mime: String,
    /// 明文的 SHA-256，随消息签名。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<Fixed<32>>,
}

impl std::fmt::Debug for FileRef {
    // 不输出钥匙和文件名：日志里只该有编号和大小。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FileRef({}, {} 字节)", self.id, self.size)
    }
}

impl FileRef {
    /// 校验文件名与类型的长度。
    pub fn check(&self) -> Result<()> {
        if self.name.chars().count() > FILE_NAME_MAX_CHARS || self.mime.len() > 255 || self.name.chars().any(char::is_control) {
            return Err(CoreError::format("文件名或类型不对"));
        }
        Ok(())
    }
}
