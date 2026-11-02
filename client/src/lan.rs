//! 局域网直连通道：发现只交换设备公钥与端口，传的是和服务器转交同一种端到端加密的帧。

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use friend_im_core::bytes::Fixed;
use friend_im_core::crypto;
use friend_im_core::ids::{DeviceId, Uid};
use friend_im_core::keys::{DevicePublic, DeviceSecret};
use friend_im_core::limits;
use friend_im_core::peer::SealedFrame;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

const DISCOVERY_PORT: u16 = 39_071;
const DISCOVERY_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 77, 77);
const DISCOVERY_VERSION: u32 = 2;
const HELLO_LABEL: &str = "FRIEND_IM_LAN_HELLO";
const DISCOVERY_LABEL: &str = "FRIEND_IM_LAN_DISCOVERY";
const LAN_TIMEOUT: Duration = Duration::from_millis(700);
const PEER_TTL: Duration = Duration::from_secs(15);

#[derive(Clone, Debug)]
struct Peer {
    addr: SocketAddr,
    seen: Instant,
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
    Deliver {
        frame: SealedFrame,
    },
    Delivered,
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

pub(crate) struct Lan {
    uid: Uid,
    device: DeviceId,
    public: DevicePublic,
    secret: DeviceSecret,
    port: u16,
    peers: Arc<Mutex<HashMap<DeviceId, Peer>>>,
}

impl Lan {
    pub(crate) async fn start(
        uid: Uid,
        secret: DeviceSecret,
        inbound: mpsc::UnboundedSender<SealedFrame>,
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

    /// 直接交给这台设备：发现过它、连得上、对方确认收下才算送到。
    pub(crate) async fn deliver(&self, to: &DeviceId, frame: &SealedFrame) -> bool {
        let now = Instant::now();
        let peer = self
            .peers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(to)
            .filter(|peer| now.duration_since(peer.seen) <= PEER_TTL)
            .cloned();
        match peer {
            Some(peer) => deliver_one(peer.addr, &self.hello(), frame).await,
            None => false,
        }
    }

    async fn accept(
        &self,
        stream: TcpStream,
        addr: SocketAddr,
        inbound: mpsc::UnboundedSender<SealedFrame>,
    ) -> std::io::Result<()> {
        let (reader, mut writer) = stream.into_split();
        // 一帧不超过连接帧上限的两倍：对方写什么也撑不爆内存。
        let mut reader = BufReader::new(reader.take(2 * limits::FRAME_MAX_BYTES as u64));
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
            Frame::Deliver { frame } => {
                if frame.uid != uid || frame.from != device || frame.to != self.device {
                    return Err(invalid_data("局域网帧的发送方或接收方不一致"));
                }
                inbound.send(frame).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "receiving client has stopped",
                    )
                })?;
                write_frame(&mut writer, &Frame::Delivered).await?;
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
                    self.peers.lock().unwrap_or_else(|p| p.into_inner()).insert(announcement.device.clone(), Peer { addr: SocketAddr::new(addr.ip(), announcement.port), seen: Instant::now() });
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

async fn deliver_one(addr: SocketAddr, hello: &Frame, frame: &SealedFrame) -> bool {
    let Ok(stream) = tokio::time::timeout(LAN_TIMEOUT, TcpStream::connect(addr)).await else {
        return false;
    };
    let Ok(stream) = stream else { return false };
    let (reader, mut writer) = stream.into_split();
    if write_frame(&mut writer, hello).await.is_err()
        || write_frame(&mut writer, &Frame::Deliver { frame: frame.clone() })
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
    matches!(serde_json::from_str::<Frame>(line.trim()), Ok(Frame::Delivered))
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
    async fn a_frame_is_delivered_once_and_only_to_a_running_client() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sender_uid = Uid::random();
        let sender_secret = DeviceSecret::generate();
        let receiver_secret = DeviceSecret::generate();
        let frame = SealedFrame::seal(&sender_uid, &sender_secret, &receiver_secret.public(), b"hi").unwrap();
        let sender = Lan::start(sender_uid.clone(), sender_secret, mpsc::unbounded_channel().0).await.unwrap();
        let receiver = Lan::start(Uid::random(), receiver_secret, tx).await.unwrap();
        assert!(!sender.deliver(&receiver.device, &frame).await, "没发现过的设备不直连");
        sender.peers.lock().unwrap().insert(
            receiver.device.clone(),
            Peer {
                addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, receiver.port)),
                seen: Instant::now(),
            },
        );
        assert!(sender.deliver(&receiver.device, &frame).await);
        let incoming = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await.unwrap().unwrap();
        assert_eq!(incoming, frame);
        // 收的一方停了：不算送到，发送方改走服务器转交。
        drop(rx);
        assert!(!sender.deliver(&receiver.device, &frame).await);
    }

    #[tokio::test]
    async fn a_frame_claiming_another_sender_is_refused() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (a, b, c) = (DeviceSecret::generate(), DeviceSecret::generate(), DeviceSecret::generate());
        let uid = Uid::random();
        // 帧是 c 的，握手却是 a：局域网这一层就拒绝。
        let frame = SealedFrame::seal(&uid, &c, &b.public(), b"hi").unwrap();
        let sender = Lan::start(uid.clone(), a, mpsc::unbounded_channel().0).await.unwrap();
        let receiver = Lan::start(Uid::random(), b, tx).await.unwrap();
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, receiver.port));
        assert!(!deliver_one(addr, &sender.hello(), &frame).await);
        assert!(rx.try_recv().is_err());
    }
}
