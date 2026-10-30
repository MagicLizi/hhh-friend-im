//! 局域网直连通道：发现只交换设备公钥与端口，消息仍是现有 E2EE 信封。

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use friend_im_core::bytes::Fixed;
use friend_im_core::crypto;
use friend_im_core::ids::{DeviceId, MsgId, Uid};
use friend_im_core::keys::{DevicePublic, DeviceSecret};
use friend_im_core::message::Envelope;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

const DISCOVERY_PORT: u16 = 39_071;
const DISCOVERY_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 77, 77);
const DISCOVERY_VERSION: u32 = 1;
const HELLO_LABEL: &str = "FRIEND_IM_LAN_HELLO";
const DISCOVERY_LABEL: &str = "FRIEND_IM_LAN_DISCOVERY";
const LAN_TIMEOUT: Duration = Duration::from_millis(700);
const PEER_TTL: Duration = Duration::from_secs(15);
const PENDING_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
struct Peer {
    uid: Uid,
    device: DeviceId,
    addr: SocketAddr,
    seen: Instant,
}

#[derive(Clone, Debug)]
pub(crate) struct DirectInbound {
    pub env: Envelope,
    pub log: u64,
    pub ts_ms: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Frame {
    Hello {
        uid: Uid,
        device: DeviceId,
        public: DevicePublic,
        port: u16,
        nonce: Fixed<32>,
        sig: Fixed<64>,
    },
    Offer {
        env: Envelope,
    },
    Ready {
        id: MsgId,
    },
    Commit {
        id: MsgId,
        log: u64,
        ts_ms: i64,
    },
    Delivered {
        id: MsgId,
    },
    Cancel {
        id: MsgId,
    },
    Error {
        message: String,
    },
}

#[derive(Serialize, Deserialize)]
struct Announcement {
    version: u32,
    uid: Uid,
    device: DeviceId,
    public: DevicePublic,
    port: u16,
    nonce: Fixed<32>,
    sig: Fixed<64>,
}

struct Pending {
    env: Envelope,
    created: Instant,
}

pub(crate) struct Lan {
    uid: Uid,
    device: DeviceId,
    public: DevicePublic,
    secret: DeviceSecret,
    port: u16,
    peers: Arc<Mutex<HashMap<DeviceId, Peer>>>,
    pending: Arc<Mutex<HashMap<MsgId, Pending>>>,
}

impl Lan {
    pub(crate) async fn start(
        uid: Uid,
        secret: DeviceSecret,
        inbound: mpsc::UnboundedSender<DirectInbound>,
    ) -> std::io::Result<Arc<Self>> {
        // WASI 构建（手机上由宿主解释执行）不做局域网直连：没有组播，也不在手机上开监听端口；调用方照原有设计改走服务器中转。
        if cfg!(target_os = "wasi") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "WASI 构建不做局域网直连",
            ));
        }
        let listener = TcpListener::bind(("0.0.0.0", 0)).await?;
        let port = listener.local_addr()?.port();
        let public = secret.public();
        let lan = Arc::new(Self {
            uid,
            device: secret.id(),
            public,
            secret,
            port,
            peers: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
        });
        let accepting = lan.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, addr)) = listener.accept().await else {
                    break;
                };
                let current = accepting.clone();
                let tx = inbound.clone();
                tokio::spawn(async move {
                    if let Err(error) = current.accept(stream, addr, tx).await {
                        tracing::debug!(%error, "局域网直连请求被拒绝");
                    }
                });
            }
        });
        match discovery_socket() {
            Ok(socket) => {
                let discovering = lan.clone();
                tokio::spawn(async move { discovering.discovery_loop(socket).await });
            }
            Err(error) => tracing::info!(%error, "局域网发现不可用，仍保留直连监听"),
        }
        Ok(lan)
    }

    pub(crate) fn disabled(uid: Uid, secret: DeviceSecret) -> Arc<Self> {
        Arc::new(Self {
            uid,
            device: secret.id(),
            public: secret.public(),
            secret,
            port: 0,
            peers: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn hello(&self) -> Frame {
        let nonce = Fixed(crypto::random());
        let data = hello_data(&self.uid, &self.device, &self.public, self.port, &nonce);
        Frame::Hello {
            uid: self.uid.clone(),
            device: self.device.clone(),
            public: self.public,
            port: self.port,
            nonce,
            sig: self.secret.sign(HELLO_LABEL, &data),
        }
    }

    fn candidates(&self, members: &[Uid], allowed_devices: &[DeviceId]) -> Vec<Peer> {
        let now = Instant::now();
        self.peers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .filter(|peer| {
                peer.device != self.device
                    && members.iter().any(|uid| uid == &peer.uid)
                    && allowed_devices.iter().any(|id| id == &peer.device)
                    && now.duration_since(peer.seen) <= PEER_TTL
            })
            .cloned()
            .collect()
    }

    pub(crate) async fn offer(
        &self,
        env: &Envelope,
        members: &[Uid],
        allowed_devices: &[DeviceId],
    ) -> Vec<DeviceId> {
        let hello = self.hello();
        let mut ready = Vec::new();
        for peer in self.candidates(members, allowed_devices) {
            if offer_one(peer.addr, &hello, env).await {
                ready.push(peer.device);
            }
        }
        ready
    }

    pub(crate) async fn commit(
        &self,
        id: &MsgId,
        log: u64,
        ts_ms: i64,
        devices: &[DeviceId],
    ) -> Vec<DeviceId> {
        let hello = self.hello();
        let now = Instant::now();
        let peers: Vec<_> = self
            .peers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .filter(|peer| {
                devices.iter().any(|want| want == &peer.device)
                    && now.duration_since(peer.seen) <= PEER_TTL
            })
            .cloned()
            .collect();
        let mut delivered = Vec::new();
        for peer in peers {
            if commit_one(peer.addr, &hello, id, log, ts_ms).await {
                delivered.push(peer.device);
            }
        }
        delivered
    }

    pub(crate) async fn cancel(&self, id: &MsgId, devices: &[DeviceId]) {
        let hello = self.hello();
        let now = Instant::now();
        let peers: Vec<_> = self
            .peers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .filter(|peer| {
                devices.iter().any(|want| want == &peer.device)
                    && now.duration_since(peer.seen) <= PEER_TTL
            })
            .cloned()
            .collect();
        for peer in peers {
            let _ = cancel_one(peer.addr, &hello, id).await;
        }
    }

    async fn accept(
        &self,
        stream: TcpStream,
        addr: SocketAddr,
        inbound: mpsc::UnboundedSender<DirectInbound>,
    ) -> std::io::Result<()> {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let Frame::Hello {
            uid,
            device,
            public,
            port,
            nonce,
            sig,
        } = serde_json::from_str(line.trim()).map_err(|error| invalid_data(error.to_string()))?
        else {
            return Err(invalid_data("局域网第一帧不是握手"));
        };
        let data = hello_data(&uid, &device, &public, port, &nonce);
        if public.id() != device || public.verify(HELLO_LABEL, &data, &sig).is_err() {
            return Err(invalid_data("局域网握手签名不对"));
        }
        if device != self.device {
            self.peers.lock().unwrap_or_else(|p| p.into_inner()).insert(
                device.clone(),
                Peer {
                    uid: uid.clone(),
                    device: device.clone(),
                    addr: SocketAddr::new(addr.ip(), port),
                    seen: Instant::now(),
                },
            );
        }
        line.clear();
        reader.read_line(&mut line).await?;
        match serde_json::from_str::<Frame>(line.trim())
            .map_err(|error| invalid_data(error.to_string()))?
        {
            Frame::Offer { env } => {
                if env.sender != uid || env.device != device || env.ct.is_empty() {
                    return Err(invalid_data("局域网信封发送方不一致"));
                }
                let id = env.id.clone();
                {
                    let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
                    let now = Instant::now();
                    pending.retain(|_, value| now.duration_since(value.created) <= PENDING_TTL);
                    if pending.len() >= 1024 {
                        return Err(invalid_data("局域网暂存已满"));
                    }
                    pending.insert(id.clone(), Pending { env, created: now });
                }
                write_frame(&mut writer, &Frame::Ready { id }).await?;
            }
            Frame::Commit { id, log, ts_ms } => {
                let pending = self
                    .pending
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&id);
                if let Some(pending) =
                    pending.filter(|p| Instant::now().duration_since(p.created) <= PENDING_TTL)
                {
                    inbound
                        .send(DirectInbound {
                            env: pending.env,
                            log,
                            ts_ms,
                        })
                        .map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::BrokenPipe,
                                "receiving client has stopped",
                            )
                        })?;
                    write_frame(&mut writer, &Frame::Delivered { id }).await?;
                } else {
                    write_frame(
                        &mut writer,
                        &Frame::Error {
                            message: "局域网暂存已过期".into(),
                        },
                    )
                    .await?;
                }
            }
            Frame::Cancel { id } => {
                self.pending
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&id);
            }
            _ => return Err(invalid_data("局域网请求顺序不对")),
        }
        Ok(())
    }

    async fn discovery_loop(&self, socket: UdpSocket) {
        let destination = SocketAddr::V4(SocketAddrV4::new(DISCOVERY_GROUP, DISCOVERY_PORT));
        let mut buf = vec![0u8; 16 * 1024];
        let mut tick = tokio::time::interval(Duration::from_secs(3));
        tick.tick().await;
        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    let Ok((len, addr)) = result else { break };
                    let Ok(announcement) = serde_json::from_slice::<Announcement>(&buf[..len]) else { continue };
                    if announcement.version != DISCOVERY_VERSION || announcement.device == self.device || announcement.public.id() != announcement.device { continue; }
                    if announcement.public.verify(DISCOVERY_LABEL, &announcement_data(&announcement), &announcement.sig).is_err() { continue; }
                    self.peers.lock().unwrap_or_else(|p| p.into_inner()).insert(announcement.device.clone(), Peer { uid: announcement.uid, device: announcement.device, addr: SocketAddr::new(addr.ip(), announcement.port), seen: Instant::now() });
                }
                _ = tick.tick() => {
                    let nonce = Fixed(crypto::random());
                    let mut announcement = Announcement { version: DISCOVERY_VERSION, uid: self.uid.clone(), device: self.device.clone(), public: self.public, port: self.port, nonce, sig: Fixed([0; 64]) };
                    announcement.sig = self.secret.sign(DISCOVERY_LABEL, &announcement_data(&announcement));
                    if let Ok(bytes) = serde_json::to_vec(&announcement) { let _ = socket.send_to(&bytes, destination).await; }
                    let now = Instant::now();
                    self.peers.lock().unwrap_or_else(|p| p.into_inner()).retain(|_, peer| now.duration_since(peer.seen) <= PEER_TTL);
                }
            }
        }
    }
}

async fn offer_one(addr: SocketAddr, hello: &Frame, env: &Envelope) -> bool {
    let Ok(stream) = tokio::time::timeout(LAN_TIMEOUT, TcpStream::connect(addr)).await else {
        return false;
    };
    let Ok(stream) = stream else { return false };
    let (reader, mut writer) = stream.into_split();
    if write_frame(&mut writer, hello).await.is_err()
        || write_frame(&mut writer, &Frame::Offer { env: env.clone() })
            .await
            .is_err()
    {
        return false;
    }
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let Ok(Ok(_)) = tokio::time::timeout(LAN_TIMEOUT, reader.read_line(&mut line)).await else {
        return false;
    };
    matches!(serde_json::from_str::<Frame>(line.trim()), Ok(Frame::Ready { id }) if id == env.id)
}

async fn commit_one(addr: SocketAddr, hello: &Frame, id: &MsgId, log: u64, ts_ms: i64) -> bool {
    let Ok(stream) = tokio::time::timeout(LAN_TIMEOUT, TcpStream::connect(addr)).await else {
        return false;
    };
    let Ok(stream) = stream else { return false };
    let (reader, mut writer) = stream.into_split();
    if write_frame(&mut writer, hello).await.is_err()
        || write_frame(
            &mut writer,
            &Frame::Commit {
                id: id.clone(),
                log,
                ts_ms,
            },
        )
        .await
        .is_err()
    {
        return false;
    }
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let Ok(Ok(_)) = tokio::time::timeout(LAN_TIMEOUT, reader.read_line(&mut line)).await else {
        return false;
    };
    matches!(serde_json::from_str::<Frame>(line.trim()), Ok(Frame::Delivered { id: received }) if received == *id)
}

async fn cancel_one(addr: SocketAddr, hello: &Frame, id: &MsgId) -> bool {
    let Ok(stream) = tokio::time::timeout(LAN_TIMEOUT, TcpStream::connect(addr)).await else {
        return false;
    };
    let Ok(stream) = stream else {
        return false;
    };
    let (_reader, mut writer) = stream.into_split();
    write_frame(&mut writer, hello).await.is_ok()
        && write_frame(&mut writer, &Frame::Cancel { id: id.clone() })
            .await
            .is_ok()
}

async fn write_frame(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    frame: &Frame,
) -> std::io::Result<()> {
    let text = serde_json::to_string(frame).map_err(|error| invalid_data(error.to_string()))?;
    writer.write_all(text.as_bytes()).await?;
    writer.write_all(b"\n").await
}

fn hello_data(
    uid: &Uid,
    device: &DeviceId,
    public: &DevicePublic,
    port: u16,
    nonce: &Fixed<32>,
) -> Vec<u8> {
    serde_json::to_vec(&(uid, device, public, port, nonce)).unwrap_or_default()
}

fn announcement_data(announcement: &Announcement) -> Vec<u8> {
    serde_json::to_vec(&(
        announcement.version,
        &announcement.uid,
        &announcement.device,
        &announcement.public,
        announcement.port,
        &announcement.nonce,
    ))
    .unwrap_or_default()
}

fn discovery_socket() -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DISCOVERY_PORT).into())?;
    socket.set_nonblocking(true)?;
    socket.set_multicast_loop_v4(true)?;
    socket.join_multicast_v4(&DISCOVERY_GROUP, &Ipv4Addr::UNSPECIFIED)?;
    UdpSocket::from_std(socket.into())
}

fn invalid_data(error: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn offer_then_commit_delivers_one_e2ee_envelope() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sender_uid = Uid::random();
        let receiver_uid = Uid::random();
        let sender_secret = DeviceSecret::generate();
        let receiver_secret = DeviceSecret::generate();
        let sender = Lan::start(
            sender_uid.clone(),
            sender_secret,
            mpsc::unbounded_channel().0,
        )
        .await
        .unwrap();
        let receiver = Lan::start(receiver_uid.clone(), receiver_secret, tx)
            .await
            .unwrap();
        sender.peers.lock().unwrap().insert(
            receiver.device.clone(),
            Peer {
                uid: receiver_uid.clone(),
                device: receiver.device.clone(),
                addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, receiver.port)),
                seen: Instant::now(),
            },
        );
        let env = Envelope {
            conv: friend_im_core::ids::ConvId::random(),
            id: MsgId::random(),
            generation: 1,
            sender: sender_uid.clone(),
            sender_eldest: Fixed([0; 32]),
            device: sender.device.clone(),
            recall: None,
            ct: friend_im_core::bytes::Bytes(vec![1, 2, 3]),
        };
        let ready = sender
            .offer(
                &env,
                std::slice::from_ref(&receiver_uid),
                std::slice::from_ref(&receiver.device),
            )
            .await;
        assert_eq!(ready, vec![receiver.device.clone()]);
        let delivered = sender.commit(&env.id, 42, 99, &ready).await;
        assert_eq!(delivered, ready);
        let incoming = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(incoming.env, env);
        assert_eq!((incoming.log, incoming.ts_ms), (42, 99));
        // A stopped client must not acknowledge delivery and suppress server fallback.
        drop(rx);
        let mut after_close = env;
        after_close.id = MsgId::random();
        let ready = sender
            .offer(
                &after_close,
                std::slice::from_ref(&receiver_uid),
                std::slice::from_ref(&receiver.device),
            )
            .await;
        assert!(
            sender
                .commit(&after_close.id, 43, 100, &ready)
                .await
                .is_empty()
        );
    }
}
