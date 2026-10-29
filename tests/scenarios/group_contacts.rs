// Run against the existing local-server test harness; never uses real user contacts.
use crate::{common::*, host::Host};
use friend_im::credential::Credential;
use friend_im_client::{Update, core::conv::GroupProfile};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn group_profile_reads_never_create_and_explicit_add_reuses_one_encrypted_chat() {
    let env = Env::start().await;
    let (owner, _) = env.account("owner", "owner device").await;
    let (alice, key) = env.account("alice", "alice device").await;
    let (bob, _) = env.account("bob", "bob device").await;
    let (outsider, _) = env.account("outsider", "outsider device").await;
    alice
        .client
        .add_friend(&owner.client.friend_link(false).await.unwrap())
        .await
        .unwrap();
    bob.client
        .add_friend(&owner.client.friend_link(false).await.unwrap())
        .await
        .unwrap();
    let group = owner
        .client
        .create_group(
            &GroupProfile {
                name: "名片测试群".into(),
                ..Default::default()
            },
            &[alice.client.uid().clone(), bob.client.uid().clone()],
        )
        .await
        .unwrap();
    let mut device = env.device("alice", "plugin device").await;
    device
        .client
        .join_with_recovery(&key.to_words())
        .await
        .unwrap();
    device
        .wait("active", |u| matches!(u, Update::Activated).then_some(()))
        .await;
    let credential = Credential::new(
        &env.server.url(),
        device.client.uid().as_str(),
        "plugin device",
        device.client.credentials().await,
    )
    .encode();
    device.client.close();
    let temp = tempfile::tempdir().unwrap();
    let (host, _) = Host::start(temp.path()).await;
    assert_eq!(
        host.open(&env.server.url(), Some(&credential), None).await["state"],
        "online"
    );
    let target = json!({"conversationId":group.to_string(),"userId":bob.client.uid().as_str()});
    let before = alice.client.convs().await.unwrap().len();
    for _ in 0..2 {
        let profile = host.call("contacts/profile", target.clone()).await.unwrap();
        assert_eq!(profile["relationship"], "notContact");
        assert_eq!(profile["canAdd"], true);
    }
    assert_eq!(alice.client.convs().await.unwrap().len(), before);
    let flow = host
        .call(
            "actions/start",
            json!({"actionId":"members","conversationId":group.to_string()}),
        )
        .await
        .unwrap()["flowId"]
        .clone();
    host.wait_note("action/step", |p| {
        p["flowId"] == flow && p["step"]["rows"].is_array()
    })
    .await;
    host.notify(
        "step/choose",
        json!({"flowId":flow,"choice":"profile","row":bob.client.uid().as_str()}),
    )
    .await;
    host.wait_note("action/step", |p| {
        p["flowId"] == flow && p["step"].to_string().contains("添加好友")
    })
    .await;
    assert_eq!(
        alice.client.convs().await.unwrap().len(),
        before,
        "群成员列表打开名片也只读"
    );
    host.notify("action/cancel", json!({"flowId":flow})).await;
    assert!(
        host.call(
            "contacts/add",
            json!({"conversationId":group.to_string(),"userId":alice.client.uid().as_str()})
        )
        .await
        .is_err()
    );
    assert!(
        host.call(
            "contacts/add",
            json!({"conversationId":group.to_string(),"userId":outsider.client.uid().as_str()})
        )
        .await
        .is_err()
    );
    let (first, second) = tokio::join!(
        host.call("contacts/add", target.clone()),
        host.call("contacts/add", target.clone())
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first["relationship"], "contact");
    assert_eq!(first["conversationId"], second["conversationId"]);
    assert_eq!(
        host.call("contacts/profile", target.clone()).await.unwrap()["conversationId"],
        first["conversationId"]
    );
    assert_eq!(
        host.call("contacts/add", target.clone()).await.unwrap()["conversationId"],
        first["conversationId"]
    );
    let flow = host
        .call(
            "actions/start",
            json!({"actionId":"members","conversationId":group.to_string()}),
        )
        .await
        .unwrap()["flowId"]
        .clone();
    host.wait_note("action/step", |p| {
        p["flowId"] == flow && p["step"]["rows"].is_array()
    })
    .await;
    host.notify(
        "step/choose",
        json!({"flowId":flow,"choice":"profile","row":bob.client.uid().as_str()}),
    )
    .await;
    host.wait_note("action/step", |p| {
        p["flowId"] == flow && p["step"].to_string().contains("发消息")
    })
    .await;
    host.notify(
        "step/choose",
        json!({"flowId":flow,"choice":"message","row":bob.client.uid().as_str()}),
    )
    .await;
    let opened = host
        .wait_note("action/finished", |p| p["flowId"] == flow)
        .await;
    assert!(
        opened
            .to_string()
            .contains(first["conversationId"].as_str().unwrap()),
        "复用已经添加的私聊"
    );
    let sent=host.call("messages/send",json!({"operationId":"contact-test-message","target":{"type":"conversation","conversationId":first["conversationId"]},"content":[{"type":"text","text":"名片私聊测试"}]})).await.unwrap();
    assert_eq!(sent["state"], "accepted");
    owner.client.kick(&group, bob.client.uid()).await.unwrap();
    assert!(host.call("contacts/profile", target).await.is_err());
    assert!(
        host.call(
            "contacts/add",
            json!({"conversationId":first["conversationId"],"userId":bob.client.uid().as_str()})
        )
        .await
        .is_err()
    );
    host.call("shutdown", json!({})).await.unwrap();
}
