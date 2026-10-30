use common::*;
use friend_im::credential::Credential;
use friend_im_client::{
    Client,
    core::{conv::GroupProfile, ids::MsgId},
};
use serde_json::json;
use std::{
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
};

fn seed(home: &Path, payload: &str) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("--seed")
        .arg(home)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
}
async fn prepare(home: &Path, client: &Client, server: &str) {
    let credential = Credential::new(
        server,
        client.uid().as_str(),
        "approval desktop",
        client.credentials().await,
    )
    .encode();
    seed(
        home,
        &json!({"credential":credential,"server":server}).to_string(),
    );
}
#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args[1] == "--seed" {
        let home = Path::new(&args[2]);
        let mut text = String::new();
        std::io::stdin().read_to_string(&mut text).unwrap();
        let payload: serde_json::Value = serde_json::from_str(&text).unwrap();
        let identity: serde_json::Value =
            serde_json::from_slice(&std::fs::read(home.join("isolated.json")).unwrap()).unwrap();
        let users = home.join("home/products/friend/store/users");
        let user = std::fs::read_dir(&users)
            .unwrap()
            .filter_map(Result::ok)
            .find(|e| e.path().join("friends/1").exists())
            .unwrap()
            .file_name()
            .into_string()
            .unwrap();
        credential_store::isolate(
            identity["id"].as_str().unwrap(),
            &home.join("credentials.json"),
        )
        .unwrap();
        credential_store::put(
            &format!("im-ext-friend-im-cred::{user}"),
            payload["credential"].as_str().unwrap(),
        )
        .unwrap();
        let parameters = json!({"version":1,"providers":{"ext-friend-im":{"fields":[{"id":"serverUrl","label":"服务器地址","type":"text"}],"values":{"serverUrl":{"kind":"text","value":payload["server"]}}}}});
        std::fs::write(
            users.join(user).join("im-parameters.json"),
            parameters.to_string(),
        )
        .unwrap();
        return;
    }
    let ready = Path::new(&args[3]);
    let mut env = Env::start().await;
    let (owner, _) = env.account("owner", "群主").await;
    let (alice, alice_recovery) = env.account("alice", "Alice").await;
    let (bob, bob_recovery) = env.account("bob", "Bob").await;
    approved_dm(&alice.client, &owner.client).await;
    approved_dm(&bob.client, &owner.client).await;
    let group = owner
        .client
        .create_group(
            &GroupProfile {
                name: "好友批准联调群".into(),
                ..Default::default()
            },
            &[alice.client.uid().clone(), bob.client.uid().clone()],
        )
        .await
        .unwrap();
    alice
        .client
        .send(
            &group,
            &MsgId::random(),
            text("我是 alice，点击头像查看名片"),
        )
        .await
        .unwrap();
    bob.client
        .send(&group, &MsgId::random(), text("我是 bob，点击头像查看名片"))
        .await
        .unwrap();
    // Each desktop owns a distinct device. Reusing a live fixture device lets LAN
    // delivery reach the fixture while websocket delivery skips that device ID.
    let alice_desktop = env.device("alice", "Alice desktop").await;
    alice_desktop
        .client
        .join_with_recovery(&alice_recovery.to_words())
        .await
        .unwrap();
    let bob_desktop = env.device("bob", "Bob desktop").await;
    bob_desktop
        .client
        .join_with_recovery(&bob_recovery.to_words())
        .await
        .unwrap();
    prepare(
        Path::new(&args[1]),
        &alice_desktop.client,
        &env.server.url(),
    )
    .await;
    prepare(Path::new(&args[2]), &bob_desktop.client, &env.server.url()).await;
    alice_desktop.client.close();
    bob_desktop.client.close();
    std::fs::write(ready,json!({"server":env.server.url(),"group":group.to_string(),"alice":alice.client.uid().as_str(),"bob":bob.client.uid().as_str(),"bobLink":bob.client.friend_link(false).await.unwrap().to_string()}).to_string()).unwrap();
    let mut completed = String::new();
    for _ in 0..3600 {
        if ready.with_extension("stop").exists() {
            break;
        }
        if let Ok(command) = std::fs::read_to_string(ready.with_extension("command")) {
            if command != completed {
                if command.starts_with("cooldown") {
                    let db = env.server.db();
                    let records:Vec<String>=db.prepare("SELECT record FROM friend_requests WHERE status IN ('rejected','withdrawn')").unwrap().query_map([],|r|r.get(0)).unwrap().collect::<Result<_,_>>().unwrap();
                    for json in records {
                        let mut r: friend_im_client::core::friends::StoredFriendRequest =
                            serde_json::from_str(&json).unwrap();
                        r.updated_ms -= 86_400_001;
                        db.execute(
                            "UPDATE friend_requests SET updated_ms=?1,record=?2 WHERE request=?3",
                            rusqlite::params![
                                r.updated_ms,
                                serde_json::to_string(&r).unwrap(),
                                r.envelope.body.id.as_str()
                            ],
                        )
                        .unwrap();
                    }
                } else if command.starts_with("restart") {
                    env.server.restart().await;
                } else if command.starts_with("expire") {
                    let db = env.server.db();
                    let records: Vec<String> = db
                        .prepare("SELECT record FROM friend_requests WHERE status='pending'")
                        .unwrap()
                        .query_map([], |r| r.get(0))
                        .unwrap()
                        .collect::<Result<_, _>>()
                        .unwrap();
                    for json in records {
                        let mut r: friend_im_client::core::friends::StoredFriendRequest =
                            serde_json::from_str(&json).unwrap();
                        r.expires_ms = friend_im_server::now_ms() - 1;
                        db.execute(
                            "UPDATE friend_requests SET expires_ms=?1,record=?2 WHERE request=?3",
                            rusqlite::params![
                                r.expires_ms,
                                serde_json::to_string(&r).unwrap(),
                                r.envelope.body.id.as_str()
                            ],
                        )
                        .unwrap();
                    }
                }
                std::fs::write(ready.with_extension("ack"), &command).unwrap();
                completed = command;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
