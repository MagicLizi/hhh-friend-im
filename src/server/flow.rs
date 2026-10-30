//! 登录与插件操作的流程（provider-protocol v13 §6.1、§6.7）：同一时间只走一个；每个流程是一个任务，从一条队列里收宿主的
//! 输入（表单提交、选择、取消）与客户端库的批准事件，一步步推给宿主（`login/step` / `action/step`），以完成或失败结束。
//!
//! 新的 `login/start` / `actions/start` 先叫旧流程停下（它收到 [`Input::Cancel`] 自己收拾），再开新的。

use std::collections::BTreeMap;
use std::sync::Mutex;

use friend_im_client::core::ids::RequestId;
use friend_im_client::core::wire::JoinCloseReason;
use hhh_im_protocol::method::StepChooseParams;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::peer::Peer;

/// 流程是登录还是插件操作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Login,
    Action,
}

/// 流程收到的东西。
#[derive(Debug)]
pub(crate) enum Input {
    /// 表单一步提交。
    Submit(BTreeMap<String, String>),
    /// 用户在一步里做了选择。
    Choose {
        choice: String,
        row: Option<String>,
        selected: Vec<String>,
    },
    /// 宿主关掉了对话框，或新的流程顶掉了它。
    Cancel,
    /// 客户端库的批准事件（新电脑这边由登录流程自己收，旧电脑这边由推送转来）。
    Join(JoinEvent),
}

/// 新电脑批准的事件。
#[derive(Debug, Clone)]
pub(crate) enum JoinEvent {
    /// 本机完成批准。
    Approved { request: RequestId },
    /// 补读后的完整请求列表，用于关掉断网期间已结束的操作框。
    Pending(Vec<RequestId>),
    /// 旧电脑输错了：还能再输（第几次尝试）。
    Retry { request: RequestId, attempt: u32 },
    /// 请求结束。
    Closed {
        request: RequestId,
        reason: JoinCloseReason,
    },
}

struct Running {
    flow_id: String,
    kind: Kind,
    tx: mpsc::UnboundedSender<Input>,
}

/// 正在走的流程（至多一个）。
#[derive(Default)]
pub(crate) struct Flows {
    current: Mutex<Option<Running>>,
    next: Mutex<u64>,
}

impl Flows {
    /// 开始一个新流程：旧的收到 `Cancel`。返回流程编号与它的输入队列。
    pub(crate) fn begin(&self, kind: Kind) -> (String, mpsc::UnboundedReceiver<Input>) {
        let flow_id = {
            let mut next = self.next.lock().expect("流程编号锁中毒");
            *next += 1;
            format!(
                "{}-{}",
                if kind == Kind::Login {
                    "login"
                } else {
                    "action"
                },
                *next
            )
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let old = self.current.lock().expect("流程锁中毒").replace(Running {
            flow_id: flow_id.clone(),
            kind,
            tx,
        });
        if let Some(old) = old {
            tracing::info!(old = %old.flow_id, "新的流程顶掉了还没结束的旧流程");
            let _ = old.tx.send(Input::Cancel);
        }
        (flow_id, rx)
    }

    /// 交给这个编号的流程；不是正在走的那个时返回 `false`（宿主发来的过时输入，忽略）。
    pub(crate) fn send(&self, flow_id: &str, input: Input) -> bool {
        let current = self.current.lock().expect("流程锁中毒");
        match current.as_ref().filter(|r| r.flow_id == flow_id) {
            Some(running) => running.tx.send(input).is_ok(),
            None => false,
        }
    }

    /// 交给正在走的操作流程（旧电脑批准的事件）；没有就丢掉。
    pub(crate) fn send_to_action(&self, input: Input) {
        if let Some(running) = self
            .current
            .lock()
            .expect("流程锁中毒")
            .as_ref()
            .filter(|r| r.kind == Kind::Action)
        {
            let _ = running.tx.send(input);
        }
    }

    /// 流程结束：只放下还是它自己的那个。
    pub(crate) fn end(&self, flow_id: &str) {
        let mut current = self.current.lock().expect("流程锁中毒");
        if current.as_ref().is_some_and(|r| r.flow_id == flow_id) {
            *current = None;
        }
    }

    /// 宿主的通知（`login/submit`、`login/cancel`、`action/submit`、`action/cancel`、`step/choose`）交给对应的流程。
    pub(crate) fn notified(&self, method: &str, params: Value) {
        let flow_id = params
            .get("flowId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let input = match method {
            "login/submit" | "action/submit" => {
                let values = params
                    .get("values")
                    .cloned()
                    .and_then(|v| serde_json::from_value(v).ok())
                    .unwrap_or_default();
                Input::Submit(values)
            }
            "login/cancel" | "action/cancel" => Input::Cancel,
            "step/choose" => match serde_json::from_value::<StepChooseParams>(params) {
                Ok(choose) => Input::Choose {
                    choice: choose.choice,
                    row: choose.row,
                    selected: choose.selected,
                },
                Err(error) => {
                    tracing::warn!(%error, "宿主发来的选择格式不对，忽略");
                    return;
                }
            },
            _ => return,
        };
        if !self.send(&flow_id, input) {
            tracing::debug!(method, %flow_id, "不是正在走的流程，忽略");
        }
    }
}

/// 往宿主推一个流程的步骤与结果。
pub(crate) struct Ui<'a> {
    pub(crate) peer: &'a Peer,
    pub(crate) flow_id: String,
    pub(crate) kind: Kind,
}

impl Ui<'_> {
    /// 推一步（`step` 是协议的步骤 JSON）。
    pub(crate) fn step(&self, step: Value) {
        let method = if self.kind == Kind::Login {
            "login/step"
        } else {
            "action/step"
        };
        self.peer
            .notify(method, json!({ "flowId": self.flow_id, "step": step }));
    }

    /// 操作做完（`title`、`message` 都没有时宿主直接关掉对话框）。
    pub(crate) fn done(&self, title: Option<&str>, message: Option<&str>) {
        self.peer.notify(
            "action/finished",
            json!({ "flowId": self.flow_id, "title": title, "message": message }),
        );
    }

    /// 操作完成并打开指定结果会话；旧宿主忽略可选字段，仍显示成功页。
    pub(crate) fn done_opening(
        &self,
        conversation: &friend_im_client::core::ids::ConvId,
        title: Option<&str>,
        message: Option<&str>,
    ) {
        self.peer.notify("action/finished", compact(json!({
            "flowId": self.flow_id, "title": title, "message": message, "openConversationId": conversation.as_str(),
        })));
    }

    /// 没做成。
    pub(crate) fn fail(&self, title: Option<&str>, message: &str, retry: Option<&str>) {
        let method = if self.kind == Kind::Login {
            "login/failed"
        } else {
            "action/failed"
        };
        self.peer.notify(
            method,
            json!({ "flowId": self.flow_id, "message": message, "retryable": retry.is_some(), "title": title, "retryLabel": retry }),
        );
    }
}

// ---------- 步骤（protocol-v1 §6.1 步骤表） ----------

/// 一段等待的说明（转圈）。
pub(crate) fn waiting(text: &str) -> Value {
    json!({ "kind": "message", "text": text, "tone": "info" })
}

/// 插件声明的提示。
pub(crate) fn note(text: &str, warn: bool) -> Value {
    json!({ "text": text, "tone": if warn { "warn" } else { "info" } })
}

/// 另一种做法。
pub(crate) fn link(id: &str, label: &str) -> Value {
    json!({ "id": id, "label": label })
}

/// 出示恢复密钥：12 个编号的词，复制，勾“我已保存”才能完成，不能跳过。
pub(crate) fn recovery_key(caption: &str, words: &str) -> Value {
    json!({
        "kind": "showText", "caption": caption, "text": words, "layout": "words", "copy": true,
        "ack": "我已保存恢复密钥", "confirmLabel": "完成", "noCancel": true,
        "note": note("别发给任何人：拿到它的人能读你的全部消息。服务器上没有它，丢了谁也找不回。", true),
    })
}

/// 等用户在出示恢复密钥那一步点“完成”。为假是被新流程顶掉了、或宿主断了。
pub(crate) async fn wait_confirm(rx: &mut mpsc::UnboundedReceiver<Input>) -> bool {
    while let Some(input) = rx.recv().await {
        match input {
            Input::Choose { choice, .. } if choice == "confirm" => return true,
            Input::Cancel => return false,
            _ => {}
        }
    }
    false
}

/// 去掉 JSON 里值为 null 的键（步骤里可选的项不给就不写）。
pub(crate) fn compact(mut value: Value) -> Value {
    if let Value::Object(map) = &mut value {
        map.retain(|_, v| !v.is_null());
        for v in map.values_mut() {
            *v = compact(std::mem::take(v));
        }
    } else if let Value::Array(items) = &mut value {
        for v in items.iter_mut() {
            *v = compact(std::mem::take(v));
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use hhh_im_protocol::method::{LoginStep, step_problem};

    // 新流程顶掉旧的：旧的收到取消；只有正在走的那个收得到输入；结束只放下自己。
    #[test]
    fn one_flow_at_a_time() {
        let flows = Flows::default();
        let (first, mut first_rx) = flows.begin(Kind::Login);
        assert!(flows.send(&first, Input::Submit(BTreeMap::new())));
        let (second, mut second_rx) = flows.begin(Kind::Action);
        assert!(matches!(first_rx.try_recv(), Ok(Input::Submit(_))));
        assert!(
            matches!(first_rx.try_recv(), Ok(Input::Cancel)),
            "旧的收到取消"
        );
        assert!(!flows.send(&first, Input::Cancel), "旧的编号不再收");
        flows.send_to_action(Input::Join(JoinEvent::Retry {
            request: RequestId::random(),
            attempt: 2,
        }));
        assert!(matches!(second_rx.try_recv(), Ok(Input::Join(_))));
        flows.end(&first);
        assert!(flows.send(&second, Input::Cancel), "结束旧的不影响新的");
        flows.end(&second);
        assert!(!flows.send(&second, Input::Cancel));
    }

    #[test]
    fn successful_creation_returns_its_exact_conversation_id() {
        let (peer, mut writes) = super::super::peer::Peer::new();
        let ui = Ui {
            peer: &peer,
            flow_id: "f-result".into(),
            kind: Kind::Action,
        };
        let id = friend_im_client::core::ids::ConvId::from_raw([7; 16]);
        ui.done_opening(&id, Some("已创建"), None);
        let sent = writes.try_recv().unwrap();
        assert_eq!(sent.method.as_deref(), Some("action/finished"));
        assert_eq!(
            sent.params,
            Some(
                json!({ "flowId": "f-result", "title": "已创建", "openConversationId": id.as_str() })
            )
        );
    }

    // 宿主的通知按流程编号分发；格式不对的选择忽略。
    #[test]
    fn host_notifications_reach_the_flow() {
        let flows = Flows::default();
        let (id, mut rx) = flows.begin(Kind::Action);
        flows.notified(
            "step/choose",
            json!({ "flowId": id, "choice": "remove", "row": "mac" }),
        );
        flows.notified(
            "action/submit",
            json!({ "flowId": id, "values": { "link": "x" } }),
        );
        flows.notified("step/choose", json!({ "flowId": id }));
        flows.notified("action/cancel", json!({ "flowId": "other" }));
        assert!(
            matches!(rx.try_recv(), Ok(Input::Choose { choice, row: Some(row), .. }) if choice == "remove" && row == "mac")
        );
        assert!(matches!(rx.try_recv(), Ok(Input::Submit(values)) if values["link"] == "x"));
        assert!(rx.try_recv().is_err(), "格式不对与别的编号都没交过来");
    }

    // 出示恢复密钥一步照协议、在上限以内；去掉 null 后宿主读得懂。
    #[test]
    fn the_recovery_key_step_is_a_valid_protocol_step() {
        let step: LoginStep = serde_json::from_value(recovery_key(
            "这是你的恢复密钥",
            "abandon ability able about above absent absorb abstract absurd abuse access accident",
        ))
        .unwrap();
        assert_eq!(step_problem(&step), None);
        assert_eq!(
            compact(json!({ "a": null, "b": [{ "c": null, "d": 1 }] })),
            json!({ "b": [{ "d": 1 }] })
        );
    }
}
