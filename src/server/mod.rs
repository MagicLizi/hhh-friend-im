//! 协议服务（HHH-IM-Protocol v1）：HHH 从标准输入一行一条发 JSON-RPC 请求，插件从标准输出一行一条回。
//!
//! 形状照官方飞书插件（hhh-im-feishu）：
//! - 读手：一行一条地读，宿主的请求各开一个任务并发处理（查询不被发送、上传堵住，§13），回复与插件发出的请求、
//!   通知都排进同一条队列，由写手按顺序写（一行一条，不会搅在一起）；
//! - 插件发给宿主的请求（`events/push`、`credential/save`）按编号等回复（[`peer`]）；`$/cancel` 停掉对应的任务；
//! - 每个方法交给对应的模块：握手 [`declare`]、会话 [`session`]、推送 [`push`]、读取与动作 [`methods`]、
//!   资源与上传 [`resources`]；两边格式的翻译在 [`translate`]。
//! - 第三阶段：用 Cindy 账号登录 [`login`]、插件操作 [`actions`]（同一时间只走一个流程，[`flow`]）、旧电脑批准与电脑增减的
//!   提醒 [`approvals`]、加密的个人资料与头像 [`profile`]。

mod actions;
mod approvals;
mod declare;
mod errors;
mod flow;
mod log;
mod login;
mod methods;
mod peer;
mod profile;
mod push;
mod resources;
mod session;
mod translate;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use hhh_im_protocol::Method;
use hhh_im_protocol::rpc::{ErrorKind, RpcId, RpcMessage, codec};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{RwLock, mpsc};
use tokio::task::AbortHandle;

use self::methods::params;
use self::peer::Peer;

/// 插件服务的设置（正式运行用默认值；测试调短等待）。
#[derive(Debug, Clone)]
pub struct Options {
    /// 推送没被宿主收下时，第一次隔多久重推（之后翻倍，至多 30 秒）。
    pub push_retry: Duration,
    /// 发消息至多等多久就先回“不确定”（宿主的发送超时是 60 秒）。
    pub send_wait: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            push_retry: Duration::from_secs(1),
            send_wait: Duration::from_secs(50),
        }
    }
}

/// 一个插件进程里的全部状态。
pub(crate) struct Server {
    pub(crate) peer: Peer,
    pub(crate) options: Options,
    /// 在线的账号（没上线为空）。
    pub(crate) state: RwLock<Option<Arc<session::Live>>>,
    pub(crate) uploads: resources::Uploads,
    pub(crate) sends: methods::Sends,
    /// 正在走的登录或操作流程（至多一个）。
    pub(crate) flows: flow::Flows,
    /// 最近一次 `session/open` 设置里的服务器地址（登录要连它）。
    pub(crate) server_url: std::sync::Mutex<Option<String>>,
    /// 取过的头像与允许取头像的主机。
    pub(crate) avatars: profile::Avatars,
    /// 宿主交来的本机用户头像（`account/avatar`，契约 provider-protocol v35）；只在内存里，上线的账号共用这一份。
    pub(crate) photo: Arc<std::sync::Mutex<Option<profile::HostPhoto>>>,
    /// 往各会话发头像一次只走一轮（宿主交头像与刚上线补发会同时来），后一轮等前一轮发完再看还要不要发。
    pub(crate) announcing: tokio::sync::Mutex<()>,
    /// 正在处理的宿主请求（编号 → 任务），`$/cancel` 用。
    tasks: std::sync::Mutex<HashMap<String, AbortHandle>>,
}

/// 现在的时间（Unix 毫秒）。
pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 用标准输入、标准输出跑协议服务，直到宿主关掉标准输入；日志交给宿主（`log/write`）。
pub async fn run_stdio() {
    let (server, writes) = Server::new(Options::default());
    log::install(server.peer.sender());
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "Cindy IM 插件已启动");
    #[cfg(not(target_os = "wasi"))]
    serve_with(server, tokio::io::stdin(), tokio::io::stdout(), writes).await;
    #[cfg(target_os = "wasi")]
    serve_with(
        server,
        crate::wasi_stdio::Stdin::new(),
        crate::wasi_stdio::Stdout,
        writes,
    )
    .await;
}

/// 在给定的输入、输出上跑协议服务（测试用进程内的管道），直到输入关掉。
pub async fn serve<R, W>(input: R, output: W, options: Options)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (server, writes) = Server::new(options);
    serve_with(server, input, output, writes).await;
}

async fn serve_with<R, W>(
    server: Arc<Server>,
    input: R,
    output: W,
    writes: mpsc::UnboundedReceiver<RpcMessage>,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(write_loop(output, writes));
    let mut lines = BufReader::new(input).lines();
    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(error) => {
                tracing::warn!(%error, "标准输入读不下去了，停下");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        match codec::decode_line(&line) {
            Ok(message) => server.receive(message),
            Err(error) => tracing::warn!(%error, "宿主发来一行不是 JSON-RPC，跳过"),
        }
    }
    // 宿主关了标准输入：停掉还在跑的请求，断开服务器。
    let handles: Vec<AbortHandle> = server
        .tasks
        .lock()
        .expect("任务表锁中毒")
        .drain()
        .map(|(_, handle)| handle)
        .collect();
    for handle in handles {
        handle.abort();
    }
    server.close_session().await;
    tracing::info!("宿主关了标准输入，Cindy IM 插件退出");
}

/// 写手：一条一行写到输出，每条都立刻送出去。
async fn write_loop<W: AsyncWrite + Unpin>(
    mut output: W,
    mut writes: mpsc::UnboundedReceiver<RpcMessage>,
) {
    while let Some(message) = writes.recv().await {
        let Ok(line) = codec::encode_line(&message) else {
            continue;
        };
        if output.write_all(line.as_bytes()).await.is_err() || output.flush().await.is_err() {
            break;
        }
    }
}

impl Server {
    fn new(options: Options) -> (Arc<Self>, mpsc::UnboundedReceiver<RpcMessage>) {
        let (peer, writes) = Peer::new();
        (
            Arc::new(Self {
                peer,
                options,
                state: RwLock::new(None),
                uploads: resources::Uploads::default(),
                sends: methods::Sends::default(),
                flows: flow::Flows::default(),
                server_url: std::sync::Mutex::new(None),
                avatars: profile::Avatars::default(),
                photo: Arc::default(),
                announcing: tokio::sync::Mutex::new(()),
                tasks: std::sync::Mutex::new(HashMap::new()),
            }),
            writes,
        )
    }

    /// 收到宿主的一条消息：回复交给在等的请求，通知当场处理，请求各开一个任务。
    fn receive(self: &Arc<Self>, message: RpcMessage) {
        if message.is_response() {
            self.peer.answer(message);
            return;
        }
        let (Some(method), params) = (message.method, message.params.unwrap_or(Value::Null)) else {
            return;
        };
        let Some(id) = message.id else {
            self.notified(&method, params);
            return;
        };
        let key = id.to_string();
        let server = self.clone();
        // 先拿着任务表再开任务：任务做完删自己那一项时，表里一定已经记上了。
        let mut tasks = self.tasks.lock().expect("任务表锁中毒");
        let task = tokio::spawn(async move {
            if let Some(result) = server.handle(&id, &method, params).await {
                server.peer.respond(id.clone(), result);
            }
            server
                .tasks
                .lock()
                .expect("任务表锁中毒")
                .remove(&id.to_string());
        });
        tasks.insert(key, task.abort_handle());
    }

    /// 宿主发来的通知。
    fn notified(&self, method: &str, params: Value) {
        match method {
            "$/cancel" => {
                let Ok(cancel) =
                    serde_json::from_value::<hhh_im_protocol::method::CancelParams>(params)
                else {
                    return;
                };
                let handle = self
                    .tasks
                    .lock()
                    .expect("任务表锁中毒")
                    .remove(&cancel.id.to_string());
                if let Some(handle) = handle {
                    handle.abort();
                    self.peer.respond(
                        cancel.id,
                        Err(errors::of(ErrorKind::Cancelled, "宿主取消了这个请求。")),
                    );
                }
            }
            "login/submit" | "login/cancel" | "action/submit" | "action/cancel" | "step/choose" => {
                self.flows.notified(method, params)
            }
            other => tracing::debug!(method = other, "不认识的通知，忽略"),
        }
    }

    /// 宿主发来的请求；回 `None` 表示已经自己回过了（`login/start`、`actions/start`：先回流程编号，再推第一步）。
    async fn handle(
        self: &Arc<Self>,
        id: &RpcId,
        method: &str,
        value: Value,
    ) -> Option<Result<Value, hhh_im_protocol::RpcError>> {
        let Some(known) = Method::from_name(method) else {
            return Some(Err(errors::method_not_found(method)));
        };
        Some(match known {
            Method::Initialize => {
                params(value).and_then(|p: hhh_im_protocol::method::InitializeParams| {
                    self.uploads.set_dir(&p.temp_dir);
                    declare::initialize(&p)
                })
            }
            Method::Ping => Ok(serde_json::json!({})),
            Method::Shutdown => {
                self.close_session().await;
                Ok(serde_json::json!({}))
            }
            Method::SessionOpen => match params(value) {
                Ok(p) => self.session_open(p).await,
                Err(error) => Err(error),
            },
            Method::SessionLogout => self.session_logout().await,
            Method::LoginStart => match params(value) {
                Ok(p) => return self.login_start(id, p),
                Err(error) => Err(error),
            },
            Method::ActionsStart => match params(value) {
                Ok(p) => return self.actions_start(id, p).await,
                Err(error) => Err(error),
            },
            Method::ConversationsList => match params(value) {
                Ok(p) => self.conversations_list(p).await,
                Err(error) => Err(error),
            },
            Method::ConversationsGet => match params(value) {
                Ok(p) => self.conversations_get(p).await,
                Err(error) => Err(error),
            },
            Method::ConversationsMembers => match params(value) {
                Ok(p) => self.conversations_members(p).await,
                Err(error) => Err(error),
            },
            Method::ConversationsRecentActivity => match params(value) {
                Ok(p) => self.conversations_recent_activity(p).await,
                Err(error) => Err(error),
            },
            Method::PeopleGet => match params(value) {
                Ok(p) => self.people_get(p).await,
                Err(error) => Err(error),
            },
            Method::MessagesList => match params(value) {
                Ok(p) => self.messages_list(p).await,
                Err(error) => Err(error),
            },
            Method::ResourcesDescribe => match params(value) {
                Ok(p) => self.describe_resource(p).await,
                Err(error) => Err(error),
            },
            Method::ResourcesRead => match params(value) {
                Ok(p) => self.read_resource(p).await,
                Err(error) => Err(error),
            },
            Method::AvatarsRead => match params(value) {
                Ok(p) => self.read_avatar(p).await,
                Err(error) => Err(error),
            },
            Method::AccountAvatar => match params(value) {
                Ok(p) => self.account_avatar(p).await,
                Err(error) => Err(error),
            },
            Method::UploadsBegin => match params(value) {
                Ok(p) => self.upload_begin(p).await,
                Err(error) => Err(error),
            },
            Method::UploadsChunk => match params(value) {
                Ok(p) => self.upload_chunk(p).await,
                Err(error) => Err(error),
            },
            Method::UploadsFinish => match params(value) {
                Ok(p) => self.upload_finish(p).await,
                Err(error) => Err(error),
            },
            Method::UploadsAbort => match params(value) {
                Ok(p) => self.upload_abort(p).await,
                Err(error) => Err(error),
            },
            Method::MessagesSend => match params(value) {
                Ok(p) => self.messages_send(p).await,
                Err(error) => Err(error),
            },
            Method::MessagesLookupSend => match params(value) {
                Ok(p) => self.messages_lookup_send(p).await,
                Err(error) => Err(error),
            },
            Method::MessagesRecall => match params(value) {
                Ok(p) => self.messages_recall(p).await,
                Err(error) => Err(error),
            },
            // 没声明的能力（搜索、定位私聊、读单条、表情、编辑、续期、重译）与插件发给宿主的方法。
            _ => Err(errors::method_not_found(method)),
        })
    }
}

/// 握手结果（测试用）。
#[doc(hidden)]
pub fn initialize_result() -> Value {
    serde_json::to_value(declare::result()).expect("握手结果总能写成 JSON")
}
