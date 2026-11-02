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

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

use friend_im_client::core::ids::{ConvId, DeviceId, MsgId};
use friend_im_client::core::sync::{Key, next_at, raw_digest};
use friend_im_client::sync::{Authority, Engine, Kind, PeerFrame, Store, StoredItem, StoredRecord, Verified, Write};
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
    fn may_share(&self, conv: &ConvId, peer: &DeviceId) -> bool {
        let truth = self.truth.borrow();
        let (Some(mine), Some(theirs)) = (truth.owner.get(&self.me), truth.owner.get(peer)) else {
            return false;
        };
        if mine == theirs {
            return true;
        }
        truth.members.get(conv).is_some_and(|members| members.contains(mine) && members.contains(theirs))
    }

    fn verify(&self, conv: &ConvId, raw: &str) -> Option<Verified> {
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

    fn tombstone(&self, _conv: &ConvId, target: &Key, sender: &str, recall_raw: &str) -> String {
        serde_json::to_string(&SimTomb { tomb: target.clone(), sender: sender.to_owned(), recall: recall_raw.to_owned() }).unwrap()
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
    fn new(seed: u64) -> Self {
        let mut rng = Rng::new(seed);
        let truth = Rc::new(RefCell::new(Truth::default()));
        let accounts = 2 + rng.below(3);
        let writes = Rc::new(RefCell::new(0));
        let mut devices = Vec::new();
        for account in 0..accounts {
            for _ in 0..1 + rng.below(3) {
                let id = DeviceId::from_raw(rng.id16());
                truth.borrow_mut().owner.insert(id.clone(), account);
                truth.borrow_mut().secret.insert(id.clone(), rng.next());
                let skew = if rng.chance(25) { (rng.below(7_200_001) as i64) - 3_600_000 } else { 0 };
                devices.push(Device { id, account, online: true, group: 0, skew, db: Rc::default(), engine: None });
            }
        }
        // 会话：一个全员群、一个私聊、可能再有一个部分成员的群。
        let mut convs = Vec::new();
        let add_conv = |rng: &mut Rng, members: BTreeSet<usize>, dm: bool, convs: &mut Vec<Conv>| {
            let id = ConvId::from_raw(rng.id16());
            truth.borrow_mut().members.insert(id.clone(), members.clone());
            truth.borrow_mut().ever.insert(id.clone(), members);
            convs.push(Conv { id, dm });
        };
        add_conv(&mut rng, (0..accounts).collect(), false, &mut convs);
        add_conv(&mut rng, [0, 1].into(), true, &mut convs);
        if accounts > 2 && rng.chance(70) {
            let members: BTreeSet<usize> = (0..accounts).filter(|_| rng.chance(60)).collect();
            if members.len() >= 2 {
                add_conv(&mut rng, members, false, &mut convs);
            }
        }
        let mut world = Self {
            rng,
            now: 1_700_000_000_000,
            truth,
            accounts,
            devices,
            convs,
            wire: Vec::new(),
            sent: Vec::new(),
            honest_recalls: Vec::new(),
            forged_recalls: Vec::new(),
            writes,
            lossy: true,
        };
        for d in 0..world.devices.len() {
            world.restart(d);
        }
        world
    }

    fn restart(&mut self, d: usize) {
        let device = &mut self.devices[d];
        let store = MemStore { db: device.db.clone(), writes: self.writes.clone() };
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
        block_on(engine.on_frame(&peer, frame)).unwrap();
        self.flush(to);
    }

    fn members(&self, conv: &ConvId) -> BTreeSet<usize> {
        self.truth.borrow().members[conv].clone()
    }

    fn rows(&self, d: usize, conv: &ConvId) -> BTreeMap<MsgId, Row> {
        self.devices[d].db.borrow().get(conv).cloned().unwrap_or_default()
    }

    fn post(&mut self, d: usize, conv: ConvId, recall: Option<Key>) {
        let account = self.devices[d].account;
        let rows = self.rows(d, &conv);
        let engine = self.devices[d].engine.as_mut().unwrap();
        let seen = block_on(engine.seen_max(&conv)).unwrap();
        let at = next_at(self.now + self.devices[d].skew, seen);
        let reply_to = if recall.is_none() && !rows.is_empty() && self.rng.chance(30) {
            rows.keys().nth(self.rng.below(rows.len())).cloned()
        } else {
            None
        };
        let mut record = SimRecord { conv: conv.clone(), id: MsgId::from_raw(self.rng.id16()), at, account, device: self.devices[d].id.clone(), reply_to, recall, sig: 0 };
        record.sig = sign(self.truth.borrow().secret[&record.device], &record);
        let raw = serde_json::to_string(&record).unwrap();
        if record.recall.is_none() {
            let outsiders = (0..self.accounts).filter(|a| !self.members(&conv).contains(a)).collect();
            self.sent.push(Sent { conv: conv.clone(), id: record.id.clone(), outsiders });
        }
        let engine = self.devices[d].engine.as_mut().unwrap();
        block_on(engine.local(&conv, raw)).unwrap();
        self.flush(d);
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
                let before: Vec<usize> = (0..n).filter(|&o| o != d && self.reachable(d, o)).collect();
                self.devices[d].online = !self.devices[d].online;
                if self.devices[d].online {
                    for o in 0..n {
                        if o != d && self.reachable(d, o) {
                            self.presence(d, o);
                            self.presence(o, d);
                        }
                    }
                } else {
                    for o in before {
                        self.absence(d, o);
                        self.absence(o, d);
                    }
                }
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
