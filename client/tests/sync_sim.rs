//! 多设备对账的确定性模拟（契约 friend-im v10 第 2–4 项，方案 plan-v10 §13）。
//!
//! 内存网络 + 内存宿主（按设备分库，插件重启后照旧在）+ 多账号多设备，随机注入：离线、断网分区、丢帧、
//! 重复帧、乱序、电脑时间不准、插件重启（内存清空）、宿主清空某个会话、加人移人退群、伪造撤回。
//! 每个随机种子最后全部上线、对账到静止，再断言：
//! - 每个会话里，当前成员的所有设备宿主库逐条一致（编号、时间、是否撤回）——顺序由此一致；
//! - 不是当前成员的账号，拿不到它不在群期间发的任何消息；
//! - 诚实的撤回在所有人那里都是墓碑，伪造的撤回在所有人那里都还是原文；
//! - 回复排在被回复的消息之后。
//!
//! 常规跑 1000 个种子；`cargo test --test sync_sim -- --ignored` 跑 10 万个。失败会打印种子，修好后把种子加进 `REGRESSION`。
//!
//! 点名的难点场景在文件末尾的 `cases`：每个场景是写死的剧本，种子只决定帧到达的先后，同一个剧本换几百种先后跑。

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

use friend_im_client::core::ids::{ConvId, DeviceId, MsgId};
use friend_im_client::core::sync::{Key, next_at, raw_digest};
use friend_im_client::sync::{Authority, Engine, Kind, PeerFrame, Store, StoredItem, StoredRecord, SyncError, Verified, Write};
use serde::{Deserialize, Serialize};

/// 修过的失败种子（永久回归）。
const REGRESSION: &[u64] = &[];

// ---------- 确定性随机数 ----------

#[derive(Clone)]
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }

    fn id16(&mut self) -> [u8; 16] {
        let mut raw = [0u8; 16];
        raw[..8].copy_from_slice(&self.next().to_le_bytes());
        raw[8..].copy_from_slice(&self.next().to_le_bytes());
        raw
    }
}

// ---------- 世界的真相（成员、设备归属、签名钥匙）----------

#[derive(Default)]
struct Truth {
    /// 设备 → 账号。
    owner: HashMap<DeviceId, usize>,
    /// 设备 → 签名用的秘密（模拟签名）。
    secret: HashMap<DeviceId, u64>,
    /// 会话 → 当前成员账号。
    members: HashMap<ConvId, BTreeSet<usize>>,
    /// 会话 → 曾经是成员的账号（含当前）。
    ever: HashMap<ConvId, BTreeSet<usize>>,
}

/// 模拟的消息原件（真实实现是签名加密的信封）。
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SimRecord {
    conv: ConvId,
    id: MsgId,
    at: i64,
    account: usize,
    device: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reply_to: Option<MsgId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recall: Option<Key>,
    /// 把原件撑到真实信封的大小（量字节数时用）。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pad: String,
    sig: u64,
}

/// 模拟的墓碑。
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SimTomb {
    tomb: Key,
    sender: String,
    recall: String,
}

fn sign(secret: u64, r: &SimRecord) -> u64 {
    let text = format!("{}|{}|{}|{}|{}|{:?}|{:?}", r.conv.as_str(), r.id.as_str(), r.at, r.account, r.device.as_str(), r.reply_to, r.recall);
    let digest = raw_digest(&format!("{secret}|{text}"));
    u64::from_le_bytes(digest.0[..8].try_into().unwrap())
}

struct SimAuth {
    me: DeviceId,
    truth: Rc<RefCell<Truth>>,
}

impl SimAuth {
    fn verify_record(&self, conv: &ConvId, raw: &str) -> Option<SimRecord> {
        let record: SimRecord = serde_json::from_str(raw).ok()?;
        let truth = self.truth.borrow();
        if &record.conv != conv || truth.owner.get(&record.device) != Some(&record.account) {
            return None;
        }
        if sign(*truth.secret.get(&record.device)?, &record) != record.sig {
            return None;
        }
        // 发送者必须曾经是成员（真实实现按签名链核对“当时是成员”）。
        if !truth.ever.get(conv).is_some_and(|ever| ever.contains(&record.account)) {
            return None;
        }
        Some(record)
    }
}

impl Authority for SimAuth {
    async fn may_share(&mut self, conv: &ConvId, peer: &DeviceId) -> bool {
        let truth = self.truth.borrow();
        let (Some(mine), Some(theirs)) = (truth.owner.get(&self.me), truth.owner.get(peer)) else {
            return false;
        };
        if mine == theirs {
            return true;
        }
        truth.members.get(conv).is_some_and(|members| members.contains(mine) && members.contains(theirs))
    }

    fn id_of(&self, raw: &str) -> Option<MsgId> {
        serde_json::from_str::<SimRecord>(raw).ok().map(|record| record.id)
    }

    async fn verify(&mut self, conv: &ConvId, raw: &str) -> Result<Option<Verified>, SyncError> {
        Ok(self.check(conv, raw))
    }

    fn tombstone(&self, _conv: &ConvId, target: &Key, sender: &str, recall_raw: &str) -> String {
        serde_json::to_string(&SimTomb { tomb: target.clone(), sender: sender.to_owned(), recall: recall_raw.to_owned() }).unwrap()
    }
}

impl SimAuth {
    fn check(&self, conv: &ConvId, raw: &str) -> Option<Verified> {
        if let Ok(tomb) = serde_json::from_str::<SimTomb>(raw) {
            let recall = self.verify_record(conv, &tomb.recall)?;
            let target = recall.recall.clone()?;
            if target != tomb.tomb || recall.account.to_string() != tomb.sender {
                return None;
            }
            return Some(Verified {
                key: Key { at: recall.at, id: recall.id },
                sender: recall.account.to_string(),
                kind: Kind::Recall { target },
                recall_raw: Some(tomb.recall),
            });
        }
        let record = self.verify_record(conv, raw)?;
        let sender = record.account.to_string();
        let key = Key { at: record.at, id: record.id.clone() };
        match record.recall {
            Some(target) => Some(Verified { key, sender, kind: Kind::Recall { target }, recall_raw: Some(raw.to_owned()) }),
            None => Some(Verified { key, sender, kind: Kind::Post, recall_raw: None }),
        }
    }
}

// ---------- 内存宿主 ----------

#[derive(Clone, Debug, PartialEq, Eq)]
struct Row {
    at: i64,
    tomb: bool,
    raw: String,
}

type HostDb = Rc<RefCell<BTreeMap<ConvId, BTreeMap<MsgId, Row>>>>;

struct MemStore {
    db: HostDb,
    writes: Rc<RefCell<usize>>,
    /// 还能写几条；写完这些再写就是“写到一半进程没了”。为空是不限。
    budget: Rc<Cell<Option<usize>>>,
}

impl Store for MemStore {
    async fn conversations(&mut self) -> Result<Vec<ConvId>, String> {
        Ok(self.db.borrow().keys().cloned().collect())
    }

    async fn index(&mut self, conv: &ConvId) -> Result<Vec<StoredItem>, String> {
        Ok(self
            .db
            .borrow()
            .get(conv)
            .map(|rows| {
                rows.iter()
                    .map(|(id, row)| StoredItem { id: id.clone(), at: row.at, tomb: row.tomb, raw: (!row.tomb).then(|| raw_digest(&row.raw)) })
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn records(&mut self, conv: &ConvId, ids: &[MsgId]) -> Result<Vec<StoredRecord>, String> {
        let db = self.db.borrow();
        let Some(rows) = db.get(conv) else { return Ok(Vec::new()) };
        Ok(ids.iter().filter_map(|id| rows.get(id).map(|row| StoredRecord { id: id.clone(), raw: row.raw.clone() })).collect())
    }

    async fn write(&mut self, conv: &ConvId, writes: Vec<Write>) -> Result<(), String> {
        let mut db = self.db.borrow_mut();
        let rows = db.entry(conv.clone()).or_default();
        for write in writes {
            if let Some(left) = self.budget.get() {
                if left == 0 {
                    return Err("写到一半进程没了".into());
                }
                self.budget.set(Some(left - 1));
            }
            *self.writes.borrow_mut() += 1;
            match write {
                // 宿主按编号去重、同一条以最新为准。
                Write::Full { key, raw } => {
                    rows.insert(key.id, Row { at: key.at, tomb: false, raw });
                }
                Write::Tombstone { key, raw } => {
                    rows.insert(key.id, Row { at: key.at, tomb: true, raw });
                }
            }
        }
        Ok(())
    }
}

// ---------- 世界 ----------

struct Device {
    id: DeviceId,
    account: usize,
    online: bool,
    group: u8,
    skew: i64,
    db: HostDb,
    budget: Rc<Cell<Option<usize>>>,
    engine: Option<Engine<MemStore, SimAuth>>,
}

struct Conv {
    id: ConvId,
    dm: bool,
}

/// 一条消息发出时谁不是成员（他们之后若仍不是成员，就不能有这条）。
struct Sent {
    conv: ConvId,
    id: MsgId,
    outsiders: BTreeSet<usize>,
}

struct World {
    rng: Rng,
    now: i64,
    truth: Rc<RefCell<Truth>>,
    accounts: usize,
    devices: Vec<Device>,
    convs: Vec<Conv>,
    wire: Vec<(usize, usize, PeerFrame)>,
    sent: Vec<Sent>,
    honest_recalls: Vec<(ConvId, MsgId)>,
    forged_recalls: Vec<(ConvId, MsgId)>,
    writes: Rc<RefCell<usize>>,
    lossy: bool,
}

/// 内存宿主的读写从不挂起，所以直接轮询到完成即可（不用每次起一个运行时）。
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
}

impl World {
    /// 只有设备的世界：`counts[账号]` 是这个账号有几台设备。`skewed` 时一部分设备电脑时间不准。
    fn empty(mut rng: Rng, counts: &[usize], skewed: bool) -> Self {
        let truth = Rc::new(RefCell::new(Truth::default()));
        let mut devices = Vec::new();
        for (account, count) in counts.iter().enumerate() {
            for _ in 0..*count {
                let id = DeviceId::from_raw(rng.id16());
                truth.borrow_mut().owner.insert(id.clone(), account);
                truth.borrow_mut().secret.insert(id.clone(), rng.next());
                let skew = if skewed && rng.chance(25) { (rng.below(7_200_001) as i64) - 3_600_000 } else { 0 };
                devices.push(Device { id, account, online: true, group: 0, skew, db: Rc::default(), budget: Rc::default(), engine: None });
            }
        }
        Self {
            rng,
            now: 1_700_000_000_000,
            truth,
            accounts: counts.len(),
            devices,
            convs: Vec::new(),
            wire: Vec::new(),
            sent: Vec::new(),
            honest_recalls: Vec::new(),
            forged_recalls: Vec::new(),
            writes: Rc::new(RefCell::new(0)),
            lossy: true,
        }
    }

    fn add_conv(&mut self, members: BTreeSet<usize>, dm: bool) -> ConvId {
        let id = ConvId::from_raw(self.rng.id16());
        self.truth.borrow_mut().members.insert(id.clone(), members.clone());
        self.truth.borrow_mut().ever.insert(id.clone(), members);
        self.convs.push(Conv { id: id.clone(), dm });
        id
    }

    fn start(&mut self) {
        for d in 0..self.devices.len() {
            self.restart(d);
        }
    }

    fn new(seed: u64) -> Self {
        let mut rng = Rng::new(seed);
        let accounts = 2 + rng.below(3);
        let counts: Vec<usize> = (0..accounts).map(|_| 1 + rng.below(3)).collect();
        let mut world = Self::empty(rng, &counts, true);
        // 会话：一个全员群、一个私聊、可能再有一个部分成员的群。
        world.add_conv((0..accounts).collect(), false);
        world.add_conv([0, 1].into(), true);
        if accounts > 2 && world.rng.chance(70) {
            let members: BTreeSet<usize> = (0..accounts).filter(|_| world.rng.chance(60)).collect();
            if members.len() >= 2 {
                world.add_conv(members, false);
            }
        }
        world.start();
        world
    }

    fn restart(&mut self, d: usize) {
        let device = &mut self.devices[d];
        let store = MemStore { db: device.db.clone(), writes: self.writes.clone(), budget: device.budget.clone() };
        let auth = SimAuth { me: device.id.clone(), truth: self.truth.clone() };
        device.engine = Some(Engine::new(store, auth));
        // 重启后重新认识在线的设备。
        for other in 0..self.devices.len() {
            if other != d && self.reachable(d, other) {
                self.presence(d, other);
            }
        }
    }

    fn reachable(&self, a: usize, b: usize) -> bool {
        let (x, y) = (&self.devices[a], &self.devices[b]);
        x.online && y.online && x.group == y.group
    }

    fn presence(&mut self, d: usize, other: usize) {
        let peer = self.devices[other].id.clone();
        let engine = self.devices[d].engine.as_mut().unwrap();
        block_on(engine.peer_online(&peer)).unwrap();
        self.flush(d);
    }

    fn absence(&mut self, d: usize, other: usize) {
        let peer = self.devices[other].id.clone();
        self.devices[d].engine.as_mut().unwrap().peer_offline(&peer);
    }

    /// 把一台设备发件箱里的帧放到网上；对方不可达的直接丢（服务器回“不在线”，不排队）。
    fn flush(&mut self, d: usize) {
        let frames = self.devices[d].engine.as_mut().unwrap().drain();
        for (to, frame) in frames {
            let Some(t) = self.devices.iter().position(|x| x.id == to) else { continue };
            if self.reachable(d, t) {
                self.wire.push((d, t, frame));
            }
        }
    }

    fn deliver_one(&mut self) {
        if self.wire.is_empty() {
            return;
        }
        let i = self.rng.below(self.wire.len());
        let (from, to, frame) = self.wire.swap_remove(i);
        if !self.reachable(from, to) {
            return;
        }
        if self.lossy && self.rng.chance(2) {
            return;
        }
        if self.lossy && self.rng.chance(2) {
            self.wire.push((from, to, frame.clone()));
        }
        let peer = self.devices[from].id.clone();
        let engine = self.devices[to].engine.as_mut().unwrap();
        match block_on(engine.on_frame(&peer, frame)) {
            Ok(_) => self.flush(to),
            Err(error) => {
                assert_eq!(self.devices[to].budget.get(), Some(0), "只有约好的崩溃才写不进宿主：{error}");
                self.crash(to);
            }
        }
    }

    /// 插件崩了：内存清空、在途的帧都没了，宿主里已经写好的还在。之后重新上线。
    fn crash(&mut self, d: usize) {
        self.devices[d].budget.set(None);
        self.set_online(d, false);
        self.wire.retain(|(from, to, _)| *from != d && *to != d);
        self.devices[d].engine = None;
        self.devices[d].online = true;
        self.restart(d);
        self.devices[d].online = false;
        self.set_online(d, true);
    }

    /// 上线或下线：两边互相知道。
    fn set_online(&mut self, d: usize, online: bool) {
        let n = self.devices.len();
        if online {
            self.devices[d].online = true;
            for o in 0..n {
                if o != d && self.reachable(d, o) {
                    self.presence(d, o);
                    self.presence(o, d);
                }
            }
        } else {
            let before: Vec<usize> = (0..n).filter(|&o| o != d && self.reachable(d, o)).collect();
            self.devices[d].online = false;
            for o in before {
                self.absence(d, o);
                self.absence(o, d);
            }
        }
    }

    fn members(&self, conv: &ConvId) -> BTreeSet<usize> {
        self.truth.borrow().members[conv].clone()
    }

    fn rows(&self, d: usize, conv: &ConvId) -> BTreeMap<MsgId, Row> {
        self.devices[d].db.borrow().get(conv).cloned().unwrap_or_default()
    }

    fn post(&mut self, d: usize, conv: ConvId, recall: Option<Key>) -> MsgId {
        let rows = self.rows(d, &conv);
        let reply_to = if recall.is_none() && !rows.is_empty() && self.rng.chance(30) {
            rows.keys().nth(self.rng.below(rows.len())).cloned()
        } else {
            None
        };
        self.post_exactly(d, conv, recall, reply_to)
    }

    fn post_exactly(&mut self, d: usize, conv: ConvId, recall: Option<Key>, reply_to: Option<MsgId>) -> MsgId {
        let account = self.devices[d].account;
        let engine = self.devices[d].engine.as_mut().unwrap();
        let seen = block_on(engine.seen_max(&conv)).unwrap();
        let at = next_at(self.now + self.devices[d].skew, seen);
        let mut record = SimRecord { conv: conv.clone(), id: MsgId::from_raw(self.rng.id16()), at, account, device: self.devices[d].id.clone(), reply_to, recall, pad: String::new(), sig: 0 };
        record.sig = sign(self.truth.borrow().secret[&record.device], &record);
        let raw = serde_json::to_string(&record).unwrap();
        if record.recall.is_none() {
            let outsiders = (0..self.accounts).filter(|a| !self.members(&conv).contains(a)).collect();
            self.sent.push(Sent { conv: conv.clone(), id: record.id.clone(), outsiders });
        }
        let engine = self.devices[d].engine.as_mut().unwrap();
        block_on(engine.local(&conv, raw)).unwrap();
        self.flush(d);
        record.id
    }

    fn step(&mut self) {
        self.now += 500 + self.rng.below(5_000) as i64;
        let n = self.devices.len();
        match self.rng.below(100) {
            // 发消息（离线也能发：先存本机，之后对账送达）。
            0..=34 => {
                let d = self.rng.below(n);
                let account = self.devices[d].account;
                let candidates: Vec<ConvId> = self.convs.iter().filter(|c| self.members(&c.id).contains(&account)).map(|c| c.id.clone()).collect();
                if !candidates.is_empty() {
                    let conv = candidates[self.rng.below(candidates.len())].clone();
                    self.post(d, conv, None);
                }
            }
            // 撤回自己的一条（诚实），或偶尔伪造撤回别人的。
            35..=40 => {
                let d = self.rng.below(n);
                let account = self.devices[d].account;
                let forge = self.rng.chance(15);
                let convs: Vec<ConvId> = self.convs.iter().filter(|c| self.members(&c.id).contains(&account)).map(|c| c.id.clone()).collect();
                if convs.is_empty() {
                    return;
                }
                let conv = convs[self.rng.below(convs.len())].clone();
                let mine: Vec<(MsgId, i64)> = self
                    .rows(d, &conv)
                    .into_iter()
                    .filter(|(_, row)| !row.tomb)
                    .filter_map(|(id, row)| {
                        let record: SimRecord = serde_json::from_str(&row.raw).ok()?;
                        ((record.account == account) != forge).then_some((id, row.at))
                    })
                    .collect();
                if mine.is_empty() {
                    return;
                }
                let (target, at) = mine[self.rng.below(mine.len())].clone();
                if forge {
                    self.forged_recalls.push((conv.clone(), target.clone()));
                } else {
                    self.honest_recalls.push((conv.clone(), target.clone()));
                }
                self.post(d, conv, Some(Key { at, id: target }));
            }
            // 上线 / 下线。
            41..=52 => {
                let d = self.rng.below(n);
                self.set_online(d, !self.devices[d].online);
            }
            // 断网分区或恢复。
            53..=55 => {
                let old: Vec<u8> = self.devices.iter().map(|d| d.group).collect();
                let split = self.rng.chance(60);
                for i in 0..n {
                    self.devices[i].group = if split { self.rng.below(2) as u8 } else { 0 };
                }
                for a in 0..n {
                    for b in 0..n {
                        if a == b {
                            continue;
                        }
                        let was = self.devices[a].online && self.devices[b].online && old[a] == old[b];
                        let now = self.reachable(a, b);
                        if !was && now {
                            self.presence(a, b);
                        } else if was && !now {
                            self.absence(a, b);
                        }
                    }
                }
            }
            // 插件重启（内存清空，宿主还在）。
            56..=57 => {
                let d = self.rng.below(n);
                self.restart(d);
            }
            // 宿主清空本机的某个会话（之后定时刷新索引时会从别的设备补回）。
            58 => {
                let d = self.rng.below(n);
                let conv = self.convs[self.rng.below(self.convs.len())].id.clone();
                self.devices[d].db.borrow_mut().remove(&conv);
                self.devices[d].engine.as_mut().unwrap().invalidate(&conv);
            }
            // 群成员变化：加人、移人或退群（私聊不变，群至少留 2 人）。
            59..=61 => {
                let groups: Vec<usize> = (0..self.convs.len()).filter(|&i| !self.convs[i].dm).collect();
                let c = groups[self.rng.below(groups.len())];
                let conv = self.convs[c].id.clone();
                let members = self.members(&conv);
                let outsiders: Vec<usize> = (0..self.accounts).filter(|a| !members.contains(a)).collect();
                let mut truth = self.truth.borrow_mut();
                if !outsiders.is_empty() && self.rng.chance(50) {
                    let a = outsiders[self.rng.below(outsiders.len())];
                    truth.members.get_mut(&conv).unwrap().insert(a);
                    truth.ever.get_mut(&conv).unwrap().insert(a);
                    // 新成员看全部旧消息：以前发的对他不再算“不在群时的消息”。
                    for sent in self.sent.iter_mut().filter(|s| s.conv == conv) {
                        sent.outsiders.remove(&a);
                    }
                } else if members.len() > 2 {
                    let list: Vec<usize> = members.into_iter().collect();
                    let a = list[self.rng.below(list.len())];
                    truth.members.get_mut(&conv).unwrap().remove(&a);
                }
            }
            // 兜底对账。
            62..=66 => {
                let d = self.rng.below(n);
                if self.devices[d].online {
                    block_on(self.devices[d].engine.as_mut().unwrap().sync_all()).unwrap();
                    self.flush(d);
                }
            }
            // 送帧。
            _ => {
                for _ in 0..1 + self.rng.below(6) {
                    self.deliver_one();
                }
            }
        }
    }

    /// 把网上的帧送完；送了太多还停不下来说明两边在来回打转（不收敛），直接判失败而不是卡住。
    fn drain_wire(&mut self) {
        let mut delivered = 0usize;
        while !self.wire.is_empty() {
            self.deliver_one();
            delivered += 1;
            assert!(delivered < 200_000, "帧来回打转停不下来（{} 帧还在网上）", self.wire.len());
        }
    }

    /// 全部上线、不再分区丢帧，对账到静止。
    fn settle(&mut self) {
        self.lossy = false;
        let n = self.devices.len();
        for d in 0..n {
            self.devices[d].online = true;
            self.devices[d].group = 0;
        }
        for d in 0..n {
            // 收尾前各自刷新一次索引（真实插件定时刷新，宿主可能被清过）。
            self.devices[d].engine.as_mut().unwrap().invalidate_all();
            for o in 0..n {
                if o != d {
                    self.presence(d, o);
                }
            }
        }
        let mut quiet = 0;
        for round in 0..60 {
            let before = *self.writes.borrow();
            self.drain_wire();
            for d in 0..n {
                block_on(self.devices[d].engine.as_mut().unwrap().sync_all()).unwrap();
                self.flush(d);
            }
            self.drain_wire();
            if *self.writes.borrow() == before {
                quiet += 1;
                if quiet >= 2 {
                    return;
                }
            } else {
                quiet = 0;
            }
            assert!(round < 59, "对账 60 轮仍没静止");
        }
    }

    fn check(&self, seed: u64) {
        let truth = self.truth.borrow();
        for conv in &self.convs {
            let members = &truth.members[&conv.id];
            let views: Vec<(usize, BTreeMap<MsgId, (i64, bool)>)> = (0..self.devices.len())
                .filter(|&d| members.contains(&self.devices[d].account))
                .map(|d| (d, self.rows(d, &conv.id).into_iter().map(|(id, row)| (id, (row.at, row.tomb))).collect()))
                .collect();
            for pair in views.windows(2) {
                assert_eq!(pair[0].1, pair[1].1, "种子 {seed}：会话里设备 {} 和 {} 不一致", pair[0].0, pair[1].0);
            }
            // 回复排在被回复的之后。
            for d in 0..self.devices.len() {
                let rows = self.rows(d, &conv.id);
                for row in rows.values().filter(|row| !row.tomb) {
                    let record: SimRecord = serde_json::from_str(&row.raw).unwrap();
                    if let Some(target) = record.reply_to.as_ref().and_then(|t| rows.get(t)) {
                        assert!(target.at < row.at, "种子 {seed}：回复排在了原消息前面");
                    }
                }
            }
        }
        // 不是当前成员的账号，拿不到它不在群期间发的消息。
        for sent in &self.sent {
            let members = &truth.members[&sent.conv];
            for d in 0..self.devices.len() {
                let account = self.devices[d].account;
                if sent.outsiders.contains(&account) && !members.contains(&account) {
                    assert!(!self.rows(d, &sent.conv).contains_key(&sent.id), "种子 {seed}：设备 {d} 拿到了不在群时的消息");
                }
            }
        }
    }

    /// 收尾前：哪些撤回已经在某台当前成员的设备上是 `tomb` 状态（诚实撤回看墓碑，伪造撤回看原文）。
    fn recall_snapshot(&self, recalls: &[(ConvId, MsgId)], tomb: bool) -> Vec<(ConvId, MsgId)> {
        let truth = self.truth.borrow();
        recalls
            .iter()
            .filter(|(conv, id)| {
                (tomb || !self.honest_recalls.contains(&(conv.clone(), id.clone())))
                    && (0..self.devices.len())
                        .filter(|&d| truth.members[conv].contains(&self.devices[d].account))
                        .any(|d| self.rows(d, conv).get(id).is_some_and(|row| row.tomb == tomb))
            })
            .cloned()
            .collect()
    }

    /// 收尾后：收尾前已经到达当前成员的诚实撤回不复活；收尾前还有原文的伪造撤回最后都是原文。
    fn check_recalls(&self, seed: u64, honest: &[(ConvId, MsgId)], forged: &[(ConvId, MsgId)]) {
        let truth = self.truth.borrow();
        for (list, want_tomb, what) in [(honest, true, "诚实的撤回复活了"), (forged, false, "伪造的撤回删掉了别人的消息")] {
            for (conv, id) in list {
                for d in (0..self.devices.len()).filter(|&d| truth.members[conv].contains(&self.devices[d].account)) {
                    if let Some(row) = self.rows(d, conv).get(id) {
                        assert_eq!(row.tomb, want_tomb, "种子 {seed}：{what}（设备 {d}）");
                    }
                }
            }
        }
    }
}

fn run_seed(seed: u64) {
    let mut world = World::new(seed);
    let steps = 120 + world.rng.below(200);
    for _ in 0..steps {
        world.step();
    }
    let honest = world.recall_snapshot(&world.honest_recalls, true);
    let forged = world.recall_snapshot(&world.forged_recalls, false);
    world.settle();
    world.check(seed);
    world.check_recalls(seed, &honest, &forged);
}

fn run_seeds(range: impl Iterator<Item = u64>) {
    for seed in REGRESSION.iter().copied().chain(range) {
        let result = std::panic::catch_unwind(|| run_seed(seed));
        if let Err(panic) = result {
            eprintln!("失败的种子：{seed}");
            std::panic::resume_unwind(panic);
        }
    }
}

#[test]
fn a_thousand_random_worlds_converge() {
    // `SYNC_SIM_SEEDS` 可以临时改种子数（排查时用），默认 1000。
    let seeds = std::env::var("SYNC_SIM_SEEDS").ok().and_then(|v| v.parse().ok()).unwrap_or(1000);
    run_seeds(1..=seeds);
}

#[test]
#[ignore = "长跑：cargo test --test sync_sim -- --ignored"]
fn a_hundred_thousand_random_worlds_converge() {
    run_seeds(1..=100_000);
}

// ---------- 点名的难点场景（契约 friend-im v10 第 2–4 项）----------
//
// 这里不用“全部上线再兜底对账”的 `settle`：只靠上线通知和直接投递，和真实插件平时走的路一样。
mod cases {
    use super::*;

    /// 每个剧本换这么多种帧到达的先后。
    const ORDERS: u64 = 300;
    /// 要先攒上千条的剧本，换这么多种（每种都要几秒）。
    const LONG_ORDERS: u64 = 8;
    const HOUR: i64 = 3_600_000;

    /// 一个私聊（账号 0、1）和一个全员群。
    fn scripted(seed: u64, counts: &[usize]) -> (World, ConvId, ConvId) {
        let mut world = World::empty(Rng::new(seed), counts, false);
        world.lossy = false;
        let dm = world.add_conv([0, 1].into(), true);
        let group = world.add_conv((0..counts.len()).collect(), false);
        world.start();
        world.drain_wire();
        (world, dm, group)
    }

    fn each_order(script: impl Fn(u64)) {
        for seed in 1..=ORDERS {
            script(seed);
        }
    }

    impl World {
        fn say(&mut self, d: usize, conv: &ConvId) -> MsgId {
            self.now += 1_000;
            self.post_exactly(d, conv.clone(), None, None)
        }

        fn reply(&mut self, d: usize, conv: &ConvId, target: &MsgId) -> MsgId {
            self.now += 1_000;
            self.post_exactly(d, conv.clone(), None, Some(target.clone()))
        }

        fn recall(&mut self, d: usize, conv: &ConvId, target: &MsgId) {
            self.now += 1_000;
            let at = self.rows(d, conv)[target].at;
            self.post_exactly(d, conv.clone(), Some(Key { at, id: target.clone() }), None);
        }

        fn leave(&mut self, account: usize, conv: &ConvId) {
            self.truth.borrow_mut().members.get_mut(conv).unwrap().remove(&account);
        }

        fn join(&mut self, account: usize, conv: &ConvId) {
            let mut truth = self.truth.borrow_mut();
            truth.members.get_mut(conv).unwrap().insert(account);
            truth.ever.get_mut(conv).unwrap().insert(account);
        }

        /// 成员变了（真实插件收到签名链变化）：这台设备和在线的设备重新对这个会话。
        fn membership_changed(&mut self, d: usize, conv: &ConvId) {
            let engine = self.devices[d].engine.as_mut().unwrap();
            let peers: Vec<DeviceId> = engine.online().cloned().collect();
            for peer in peers {
                block_on(self.devices[d].engine.as_mut().unwrap().sync_with(&peer, conv)).unwrap();
            }
            self.flush(d);
        }

        /// 按排序键排好的编号。
        fn order(&self, d: usize, conv: &ConvId) -> Vec<MsgId> {
            let rows = self.rows(d, conv);
            let mut keys: Vec<Key> = rows.iter().map(|(id, row)| Key { at: row.at, id: id.clone() }).collect();
            keys.sort();
            keys.into_iter().map(|key| key.id).collect()
        }

        /// 这几台设备逐条一样（内容、撤回状态、顺序），一共 `count` 条。
        #[track_caller]
        fn agree(&self, conv: &ConvId, devices: &[usize], count: usize) {
            let first = self.rows(devices[0], conv);
            assert_eq!(first.len(), count, "设备 {} 的条数不对", devices[0]);
            for &d in &devices[1..] {
                assert_eq!(self.rows(d, conv), first, "设备 {} 和设备 {} 不一样", devices[0], d);
                assert_eq!(self.order(d, conv), self.order(devices[0], conv), "设备 {d} 的顺序不一样");
            }
        }

        /// 这些帧有没有一帧把这个会话的东西从 `from` 账号的设备带给 `to` 账号的设备。
        fn carries(&self, conv: &ConvId, from: usize, to: usize) -> bool {
            self.wire.iter().any(|(a, b, frame)| {
                self.devices[*a].account == from
                    && self.devices[*b].account == to
                    && matches!(frame, PeerFrame::Have { conv: c, .. } if c == conv)
            })
        }

        /// 一帧一帧送完，每送一帧都确认没有东西从 `from` 账号流向 `to` 账号。
        #[track_caller]
        fn drain_without(&mut self, conv: &ConvId, from: usize, to: usize) {
            while !self.wire.is_empty() {
                assert!(!self.carries(conv, from, to), "有东西流向了不该拿的账号");
                self.deliver_one();
            }
        }
    }

    // 两台同时离线各自发：同一毫秒发的也排得出同一个顺序，不丢不重。
    #[test]
    fn two_devices_offline_at_once_each_send_and_then_agree() {
        each_order(|seed| {
            let (mut w, dm, _) = scripted(seed, &[2, 1]);
            w.set_online(0, false);
            w.set_online(1, false);
            for _ in 0..5 {
                w.post_exactly(0, dm.clone(), None, None);
                w.post_exactly(1, dm.clone(), None, None);
                w.say(2, &dm);
            }
            assert_eq!(w.rows(2, &dm).len(), 5, "离线的两台还没交上来");
            w.set_online(0, true);
            w.set_online(1, true);
            w.drain_wire();
            w.agree(&dm, &[0, 1, 2], 15);
        });
    }

    // 时间快一小时的电脑：之后看到它的设备发的消息和回复都排在它后面；时间慢一小时的回复也排在原消息后面。
    #[test]
    fn a_clock_an_hour_off_keeps_replies_after_the_original() {
        each_order(|seed| {
            let (mut w, dm, _) = scripted(seed, &[2, 1]);
            w.devices[2].skew = HOUR;
            w.devices[1].skew = -HOUR;
            let fast = w.say(2, &dm);
            w.drain_wire();
            let answer = w.reply(0, &dm, &fast);
            w.drain_wire();
            let late = w.reply(1, &dm, &answer);
            w.drain_wire();
            w.agree(&dm, &[0, 1, 2], 3);
            assert_eq!(w.order(0, &dm), [fast, answer, late], "回复排在原消息之后");
        });
    }

    // 时间快一小时的电脑离线时发的：回来以后大家一致，它之后再发也接着往后排。
    #[test]
    fn a_fast_clock_offline_for_a_while_still_agrees() {
        each_order(|seed| {
            let (mut w, dm, _) = scripted(seed, &[2, 1]);
            w.devices[1].skew = HOUR;
            w.set_online(1, false);
            let ahead = w.say(1, &dm);
            let before = w.say(0, &dm);
            w.say(2, &dm);
            w.set_online(1, true);
            w.drain_wire();
            let after = w.reply(0, &dm, &ahead);
            w.drain_wire();
            w.agree(&dm, &[0, 1, 2], 4);
            let order = w.order(2, &dm);
            let at = |id: &MsgId| order.iter().position(|x| x == id).unwrap();
            assert!(at(&before) < at(&ahead) && at(&ahead) < at(&after));
        });
    }

    // 撤回比原消息先到：先记墓碑，原消息后到也不复活；重复送一遍原文也不复活。
    #[test]
    fn a_recall_arriving_before_the_original_wins() {
        each_order(|seed| {
            let (mut w, dm, _) = scripted(seed, &[1, 1]);
            let id = w.say(0, &dm);
            let original = w.wire.last().cloned().unwrap();
            w.recall(0, &dm, &id);
            let recall = w.wire.pop().unwrap();
            w.wire.clear();
            w.wire.push(recall);
            w.deliver_one();
            assert!(w.rows(1, &dm)[&id].tomb, "撤回先到就是墓碑");
            w.wire.push(original.clone());
            w.deliver_one();
            w.wire.push(original);
            w.deliver_one();
            w.drain_wire();
            assert!(w.rows(1, &dm)[&id].tomb, "原消息后到不复活");
            w.agree(&dm, &[0, 1], 1);
        });
    }

    // 长期离线的设备回来：补齐别处发的几百条，别处撤回的、它手里还有原文的那条不复活，它离线时发的也交出去。
    #[test]
    fn a_device_back_after_a_long_absence_catches_up_without_reviving_anything() {
        for seed in 1..=LONG_ORDERS {
            let (mut w, dm, _) = scripted(seed, &[2, 1]);
            let old: Vec<MsgId> = (0..10).map(|_| w.say(0, &dm)).collect();
            w.drain_wire();
            w.agree(&dm, &[0, 1, 2], 10);
            w.set_online(1, false);
            for i in 0..700 {
                w.say(if i % 3 == 0 { 2 } else { 0 }, &dm);
                if i % 50 == 0 {
                    w.drain_wire();
                }
            }
            w.recall(0, &dm, &old[3]);
            w.recall(2, &dm, &old[3]);
            w.drain_wire();
            let mine = w.say(1, &dm);
            assert!(!w.rows(1, &dm)[&old[3]].tomb, "离线那台手里还是原文");
            w.set_online(1, true);
            w.drain_wire();
            w.agree(&dm, &[0, 1, 2], 711);
            assert!(w.rows(0, &dm)[&old[3]].tomb && w.rows(1, &dm)[&old[3]].tomb, "撤回不复活");
            assert!(w.rows(2, &dm).contains_key(&mine), "它离线时发的也交出去了");
        }
    }

    // 发完立刻断网：对方这时收不到，发的人也不算丢；重新联网后送到，只有一条。
    #[test]
    fn a_message_sent_right_before_the_network_drops_arrives_later() {
        each_order(|seed| {
            let (mut w, dm, _) = scripted(seed, &[1, 1]);
            let id = w.say(0, &dm);
            w.set_online(0, false);
            w.drain_wire();
            assert!(w.rows(1, &dm).is_empty(), "断在路上了");
            assert!(w.rows(0, &dm).contains_key(&id), "本机已保存");
            w.set_online(0, true);
            w.drain_wire();
            w.agree(&dm, &[0, 1], 1);
        });
    }

    // 对账做到一半插件崩溃：写进宿主的留着，没写的重新补，不丢不重，也不用从头再来。
    #[test]
    fn a_crash_halfway_through_catching_up_loses_and_repeats_nothing() {
        for seed in 1..=LONG_ORDERS {
            let (mut w, dm, _) = scripted(seed, &[1, 1]);
            w.set_online(1, false);
            for _ in 0..1_200 {
                w.say(0, &dm);
            }
            w.drain_wire();
            let written = *w.writes.borrow();
            // 写到一批的中间崩掉（一批 500 条）。
            w.devices[1].budget.set(Some(100 + w.rng.below(900)));
            w.set_online(1, true);
            w.drain_wire();
            w.agree(&dm, &[0, 1], 1_200);
            assert_eq!(w.devices[1].budget.get(), None, "真的崩过一次");
            let wrote = *w.writes.borrow() - written;
            assert!(wrote <= 1_200 + 500, "崩溃后只补没写的，实际写了 {wrote} 条");
        }
    }

    // 插件重启时还有帧在路上：对方发来的那一段丢了，重新认识以后补上。
    #[test]
    fn a_restart_with_frames_in_flight_loses_nothing() {
        for seed in 1..=LONG_ORDERS {
            let (mut w, dm, _) = scripted(seed, &[1, 1]);
            w.set_online(1, false);
            for _ in 0..800 {
                w.say(0, &dm);
            }
            w.drain_wire();
            w.set_online(1, true);
            for _ in 0..1 + w.rng.below(8) {
                w.deliver_one();
            }
            w.crash(1);
            w.drain_wire();
            w.agree(&dm, &[0, 1], 800);
        }
    }

    // 两台同时给同一台补：不管怎么交错都不重复，也不会打转。
    #[test]
    fn two_devices_filling_in_the_same_device_at_once_agree() {
        each_order(|seed| {
            let (mut w, dm, _) = scripted(seed, &[2, 1]);
            w.set_online(2, false);
            let ids: Vec<MsgId> = (0..60).map(|i| w.say(i % 2, &dm)).collect();
            w.recall(0, &dm, &ids[0]);
            w.drain_wire();
            w.agree(&dm, &[0, 1], 60);
            let before = *w.writes.borrow();
            w.set_online(2, true);
            w.drain_wire();
            w.agree(&dm, &[0, 1, 2], 60);
            assert!(*w.writes.borrow() - before <= 2 * 60, "两台最多各给一遍");
        });
    }

    // 接收方全部离线时发送，然后发送的这台也关了：只开发送方的另一台，接收方上线照样收到。
    #[test]
    fn the_senders_other_device_delivers_when_the_sender_is_off() {
        each_order(|seed| {
            let (mut w, dm, _) = scripted(seed, &[2, 1]);
            w.set_online(2, false);
            w.say(0, &dm);
            w.drain_wire();
            w.set_online(0, false);
            w.set_online(2, true);
            w.drain_wire();
            w.agree(&dm, &[1, 2], 1);
        });
    }

    // 发送方全部离线：要等它有设备上线才送到。
    #[test]
    fn nothing_arrives_until_a_device_holding_the_message_is_online() {
        each_order(|seed| {
            let (mut w, dm, _) = scripted(seed, &[2, 1]);
            w.set_online(1, false);
            w.set_online(2, false);
            w.say(0, &dm);
            w.set_online(0, false);
            w.set_online(2, true);
            w.drain_wire();
            assert!(w.rows(2, &dm).is_empty());
            w.set_online(0, true);
            w.drain_wire();
            w.agree(&dm, &[0, 2], 1);
        });
    }

    // 群里已经收到的成员帮着补：发的人关机了，别的成员上线时从收到过的成员那里拿到。
    #[test]
    fn a_group_member_who_got_it_passes_it_on() {
        each_order(|seed| {
            let (mut w, _, group) = scripted(seed, &[1, 1, 1]);
            w.set_online(2, false);
            w.say(0, &group);
            w.drain_wire();
            w.set_online(0, false);
            w.set_online(2, true);
            w.drain_wire();
            w.agree(&group, &[1, 2], 1);
        });
    }

    // 退群的人（账号 2）：离开后别人不给他任何东西，他也交不出去；他自己的两台设备之间照样同步离开前的记录。
    #[test]
    fn someone_who_left_neither_gets_nor_gives_but_their_own_devices_still_sync() {
        each_order(|seed| {
            let (mut w, _, group) = scripted(seed, &[1, 1, 2]);
            let (alice, bob, leaver, second) = (0, 1, 2, 3);
            let early = w.say(alice, &group);
            w.drain_wire();
            w.agree(&group, &[alice, bob, leaver, second], 1);
            // 他的第二台设备关着；另外两个人也离线时，他发了一条，只有他自己手里有。
            w.set_online(second, false);
            w.set_online(alice, false);
            w.set_online(bob, false);
            let unsent = w.say(leaver, &group);
            w.leave(2, &group);
            w.set_online(alice, true);
            w.set_online(bob, true);
            let after = w.say(alice, &group);
            w.drain_without(&group, 0, 2);
            w.set_online(second, true);
            w.drain_without(&group, 1, 2);
            // 兜底对账也一样。
            for d in [alice, bob, leaver, second] {
                w.membership_changed(d, &group);
            }
            w.drain_without(&group, 0, 2);
            assert!(w.rows(bob, &group).contains_key(&after));
            assert!(!w.rows(bob, &group).contains_key(&unsent), "离开的人交不出来");
            assert!(!w.rows(alice, &group).contains_key(&unsent), "离开的人交不出来");
            for d in [leaver, second] {
                assert!(!w.rows(d, &group).contains_key(&after), "离开后的拿不到");
                assert!(w.rows(d, &group).contains_key(&early), "离开前的还在");
            }
            w.agree(&group, &[leaver, second], 2);
        });
    }

    // 新成员从群里在线的成员那里拿到全部旧消息，和大家一样。
    #[test]
    fn a_new_member_gets_the_whole_history_from_a_member() {
        each_order(|seed| {
            let mut w = World::empty(Rng::new(seed), &[1, 1, 1], false);
            w.lossy = false;
            let group = w.add_conv([0, 1].into(), false);
            w.start();
            let first = w.say(0, &group);
            w.say(1, &group);
            w.recall(0, &group, &first);
            w.drain_wire();
            assert!(w.rows(2, &group).is_empty(), "还不是成员");
            w.join(2, &group);
            w.membership_changed(0, &group);
            w.drain_wire();
            w.agree(&group, &[0, 1, 2], 2);
            assert!(w.rows(2, &group)[&first].tomb, "撤回的还是撤回");
        });
    }

    // 两边各 1 万条、相差 10 条：3 秒内对完，来回不超过 100 KB（量的是帧的 JSON 按线上的 base64 算，加上每帧的封装开销）。
    #[test]
    fn ten_thousand_differing_by_ten_cost_little() {
        const FRAME_OVERHEAD: usize = 300;
        // 一条文字消息的真实信封约 700 字节。
        let pad = "x".repeat(420);
        let (mut w, dm, _) = scripted(7, &[2, 0]);
        let record = |w: &mut World, device: usize, at: i64| {
            let mut record = SimRecord { conv: dm.clone(), id: MsgId::from_raw(w.rng.id16()), at, account: 0, device: w.devices[device].id.clone(), reply_to: None, recall: None, pad: pad.clone(), sig: 0 };
            record.sig = sign(w.truth.borrow().secret[&record.device], &record);
            (record.id.clone(), Row { at, tomb: false, raw: serde_json::to_string(&record).unwrap() })
        };
        let mut common = BTreeMap::new();
        for i in 0..10_000 {
            let (id, row) = record(&mut w, 0, 1_700_000_000_000 + i);
            common.insert(id, row);
        }
        let (left, right) = (w.devices[0].db.clone(), w.devices[1].db.clone());
        left.borrow_mut().insert(dm.clone(), common.clone());
        right.borrow_mut().insert(dm.clone(), common);
        for i in 0..5 {
            let (id, row) = record(&mut w, 0, 1_700_000_000_000 + i * 1_999);
            left.borrow_mut().get_mut(&dm).unwrap().insert(id, row);
            let (id, row) = record(&mut w, 1, 1_700_000_000_000 + i * 1_999 + 1);
            right.borrow_mut().get_mut(&dm).unwrap().insert(id, row);
        }
        w.set_online(1, false);
        w.start();
        let started = std::time::Instant::now();
        w.set_online(1, true);
        let (mut bytes, mut frames) = (0, 0);
        let mut guard = 0;
        while !w.wire.is_empty() {
            guard += 1;
            assert!(guard < 1_000, "不收敛");
            // 按到达顺序量：先取出来算大小，再送。
            let (from, to, frame) = w.wire.remove(0);
            bytes += serde_json::to_vec(&frame).unwrap().len() * 4 / 3 + FRAME_OVERHEAD;
            frames += 1;
            w.wire.push((from, to, frame));
            let last = w.wire.len() - 1;
            w.wire.swap(0, last);
            let frame = w.wire.remove(0);
            let peer = w.devices[frame.0].id.clone();
            block_on(w.devices[frame.1].engine.as_mut().unwrap().on_frame(&peer, frame.2)).unwrap();
            w.flush(frame.1);
        }
        let took = started.elapsed();
        w.agree(&dm, &[0, 1], 10_010);
        eprintln!("1 万条差 10 条：{took:?}，{frames} 帧，{bytes} 字节");
        assert!(bytes <= 100 * 1024, "来回 {bytes} 字节");
        assert!(took.as_secs() < 3, "用了 {took:?}");
    }
}
