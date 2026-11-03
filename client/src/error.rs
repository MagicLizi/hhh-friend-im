//! 客户端库的错误：只说“哪一类不对”，不带任何钥匙、明文或密文内容，可以放心写进日志。

use friend_im_core::CoreError;
use friend_im_core::wire::{ErrorCode, WireError};

/// 客户端库里所有可能的失败。
#[derive(Debug, Clone, thiserror::Error)]
pub enum ClientError {
    /// 没连上服务器（断网、服务器停了、连接刚断开）。发送失败时拿不准服务器收没收到，由用户在失败记录里重试。
    #[error("没连上服务器")]
    Disconnected,
    /// 服务器没有及时回应。
    #[error("服务器没有及时回应")]
    Timeout,
    /// 服务器拒绝了请求。
    #[error("服务器拒绝：{0}")]
    Server(#[from] WireError),
    /// 格式、加解密、签名链在 core 里校验不过。
    #[error("{0}")]
    Core(#[from] CoreError),
    /// 服务器给的东西核对不通过（签名链、钥匙、身份指纹对不上）：服务器可能在作恶，提醒用户。
    #[error("核对不通过：{0}")]
    Verify(String),
    /// 服务器的回应和请求对不上。
    #[error("服务器回应不对：{0}")]
    Protocol(String),
    /// 这台电脑现在不能做这件事（还没批准、已在批准中等）。
    #[error("现在不能这样做：{0}")]
    State(String),
    /// 文件上传、下载失败。
    #[error("文件传输失败：{0}")]
    Transfer(String),
}

impl ClientError {
    /// 服务器的错误码（只有 [`ClientError::Server`] 有）。
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Server(error) => Some(error.code),
            _ => None,
        }
    }

    pub(crate) fn verify(message: impl Into<String>) -> Self {
        Self::Verify(message.into())
    }

    pub fn state(message: impl Into<String>) -> Self {
        Self::State(message.into())
    }

    pub(crate) fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }
}

/// 客户端库的结果类型。
pub type Result<T> = std::result::Result<T, ClientError>;
