//! Cindy IM 两边共用的部分：钥匙、签名链、封装、消息与文件加密、新电脑批准握手、恢复密钥编码、和服务器之间的格式。
//!
//! 这个包不碰网络和文件：插件（经 `friend-im-client`）和服务器都直接依赖它，保证两边的格式对得上；
//! 以后手机端也能原样复用。

pub mod account;
pub mod bytes;
pub mod conv;
pub mod crypto;
pub mod error;
pub mod file;
pub mod ids;
pub mod keys;
pub mod limits;
pub mod message;
pub mod pake;
pub mod reading;
pub mod wire;
pub mod words;

pub use error::{CoreError, Result};
