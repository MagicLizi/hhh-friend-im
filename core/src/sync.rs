//! 设备之间对账（契约 friend-im v10，方案 plan-v10 §2、§5）：按排序键的范围摘要。
//!
//! 一个会话里的消息是一个只增的集合：元素是“排序键 + 编号 + 状态”，同一编号的内容不变，唯一允许的变化是撤回
//! （原文变成墓碑，墓碑永远胜过原文）。两台设备交换按排序键分段的摘要，只细分不一样的段，段里元素够少就直接列清单；
//! 每一方由此算出“对方缺、我该给”的和“我缺、该要”的编号，原件另用 `Have` 帧传。
//!
//! - 排序键 `(at_ms, id)` 与宿主本地库的排序完全相同（时间，再按编号字节序），所以集合相同的设备显示顺序也相同。
//! - 段指纹 = 段内每个元素摘要（16 字节当 128 位小端整数）的环加和，加上元素个数（同 Negentropy 的做法）。
//! - 这个模块只做纯计算，不碰网络、不碰存储；谁有权拿什么由调用方先过滤再建索引。

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bytes::Fixed;
use crate::crypto;
use crate::error::{CoreError, Result};
use crate::ids::MsgId;

/// 一段至多列多少个元素就直接给清单（再多就细分）。
pub const LIST_MAX: usize = 32;
/// 不一样的段细分成几份。
pub const SPLIT: usize = 16;
/// 一条对账消息里至多几段（防止对方发来巨大的帧）。
pub const RANGES_MAX: usize = 4096;
/// 一段清单里至多几个元素（对方发来的；我们自己最多发 [`LIST_MAX`]，留余量给不同版本）。
pub const LIST_ITEMS_MAX: usize = 1024;

const ITEM_LABEL: &str = "friend-im/v2/sync/item";

/// 发送时间：比本机时间和本会话见过的最大时间都大（至少大 1 毫秒），所以回复和之后看到的消息一定排在后面。
pub fn next_at(now_ms: i64, seen_max_ms: Option<i64>) -> i64 {
    match seen_max_ms {
        Some(seen) => now_ms.max(seen.saturating_add(1)),
        None => now_ms,
    }
}

/// 原始数据的摘要：SHA-256 的前 16 字节，与宿主 `store/index` 给的 `rawDigest` 同一算法（不带标签，宿主不认识格式）。
pub fn raw_digest(data: &str) -> Fixed<16> {
    let full: [u8; 32] = Sha256::digest(data.as_bytes()).into();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    Fixed(out)
}

/// 排序键写成宿主要的阅读位置：只有数字、按长度再按字典序比，比出来的先后和排序键一样。
/// 时间照写；编号的每个字符换成它在 base64url 字符按字节排序里的名次（两位数字）。
pub fn read_position(key: &Key) -> String {
    const SORTED: &[u8] = b"-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";
    let mut out = key.at.max(0).to_string();
    for byte in key.id.as_str().bytes() {
        let rank = SORTED.iter().position(|c| *c == byte).unwrap_or(0);
        out.push_str(&format!("{rank:02}"));
    }
    out
}

/// 排序键：先比时间，再比编号（编号是固定长度的 base64url，按字节比与宿主 SQLite 的默认比较一致）。
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Key {
    /// 发送时间（毫秒，签在正文里）。
    pub at: i64,
    /// 消息编号。
    pub id: MsgId,
}

/// 段的上界（不含）。下界是上一段的上界，第一段从最小开始。
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Upper {
    /// 到这个键为止（不含）。
    Key(Key),
    /// 到最后。
    End,
}

impl Upper {
    fn admits(&self, key: &Key) -> bool {
        match self {
            Self::Key(upper) => key < upper,
            Self::End => true,
        }
    }
}

/// 元素的状态。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
    /// 原文：原始数据的摘要（[`raw_digest`]）。
    Full(Fixed<16>),
    /// 撤回后的墓碑。
    Tombstone,
}

/// 集合里的一个元素。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// 排序键。
    pub key: Key,
    /// 状态。
    pub state: State,
}

impl Item {
    /// 元素摘要：编号 + 状态。两边对同一条消息算出同一个值，状态不同就不同。
    pub fn digest(&self) -> Fixed<16> {
        let (tag, body): (&[u8], &[u8]) = match &self.state {
            State::Full(digest) => (b"full", &digest.0),
            State::Tombstone => (b"tomb", &[]),
        };
        let full = crypto::hash(ITEM_LABEL, &crypto::frame(&[self.key.id.as_str().as_bytes(), &self.key.at.to_be_bytes(), tag, body]));
        let mut out = [0u8; 16];
        out.copy_from_slice(&full[..16]);
        Fixed(out)
    }
}

/// 段指纹。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    /// 元素摘要的环加和（128 位小端）。
    pub sum: Fixed<16>,
    /// 元素个数。
    pub count: u64,
}

/// 清单里的一项：对方据此判断谁缺谁、谁的状态更新。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// 排序键。
    pub key: Key,
    /// 是不是墓碑。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tomb: bool,
    /// 原文的原始数据摘要（墓碑没有）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<Fixed<16>>,
}

impl Entry {
    fn of(item: &Item) -> Self {
        match item.state {
            State::Full(digest) => Self { key: item.key.clone(), tomb: false, raw: Some(digest) },
            State::Tombstone => Self { key: item.key.clone(), tomb: true, raw: None },
        }
    }

    fn state(&self) -> Result<State> {
        match (self.tomb, self.raw) {
            (true, None) => Ok(State::Tombstone),
            (false, Some(digest)) => Ok(State::Full(digest)),
            _ => Err(CoreError::format("对账清单的元素状态不对")),
        }
    }
}

/// 一段的内容。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum Body {
    /// 这段已经一致，不用再看。
    Skip,
    /// 这段的指纹。
    Fp {
        /// 指纹。
        fp: Fingerprint,
    },
    /// 这段的全部元素。
    List {
        /// 元素（按排序键从小到大）。
        items: Vec<Entry>,
    },
}

/// 一段：从上一段的上界到 `upper`。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range {
    /// 上界（不含）。
    pub upper: Upper,
    /// 内容。
    #[serde(flatten)]
    pub body: Body,
}

/// 一个会话在本机的对账索引：按排序键排好的元素，带前缀和以便快速算任意段的指纹。
#[derive(Clone, Debug)]
pub struct Index {
    items: Vec<Item>,
    /// `prefix[i]` = 前 `i` 个元素摘要的环加和。
    prefix: Vec<u128>,
    by_id: HashMap<MsgId, usize>,
}

impl Default for Index {
    fn default() -> Self {
        Self::new([])
    }
}

fn as_u128(digest: &Fixed<16>) -> u128 {
    u128::from_le_bytes(digest.0)
}

impl Index {
    /// 由元素建索引；同一编号出现多次时墓碑优先、否则保留后出现的。
    pub fn new(items: impl IntoIterator<Item = Item>) -> Self {
        let mut map: HashMap<MsgId, Item> = HashMap::new();
        for item in items {
            match map.get(&item.key.id) {
                Some(existing) if existing.state == State::Tombstone => {}
                _ => {
                    map.insert(item.key.id.clone(), item);
                }
            }
        }
        let mut items: Vec<Item> = map.into_values().collect();
        items.sort_by(|a, b| a.key.cmp(&b.key));
        let mut index = Self { items, prefix: Vec::new(), by_id: HashMap::new() };
        index.rebuild();
        index
    }

    fn rebuild(&mut self) {
        self.prefix.clear();
        self.prefix.reserve(self.items.len() + 1);
        self.prefix.push(0);
        let mut sum = 0u128;
        for item in &self.items {
            sum = sum.wrapping_add(as_u128(&item.digest()));
            self.prefix.push(sum);
        }
        self.by_id = self.items.iter().enumerate().map(|(i, item)| (item.key.id.clone(), i)).collect();
    }

    /// 元素个数。
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// 按编号查元素。
    pub fn get(&self, id: &MsgId) -> Option<&Item> {
        self.by_id.get(id).map(|&i| &self.items[i])
    }

    /// 全部元素（按排序键）。
    pub fn items(&self) -> &[Item] {
        &self.items
    }

    /// 并进一批元素：没有的加上，原文遇到墓碑变墓碑，其余不动。返回是否有变化。
    pub fn merge(&mut self, incoming: impl IntoIterator<Item = Item>) -> bool {
        let mut changed = false;
        for item in incoming {
            match self.by_id.get(&item.key.id) {
                None => {
                    self.items.push(item);
                    changed = true;
                    // 先不重建：批量并进后统一排序。
                    let i = self.items.len() - 1;
                    let id = self.items[i].key.id.clone();
                    self.by_id.insert(id, i);
                }
                Some(&i) => {
                    if self.items[i].state != State::Tombstone && item.state == State::Tombstone {
                        // 墓碑的排序键以原文为准（撤回里带的时间与原文核对过才会走到这里）。
                        self.items[i].state = State::Tombstone;
                        changed = true;
                    }
                }
            }
        }
        if changed {
            self.items.sort_by(|a, b| a.key.cmp(&b.key));
            self.rebuild();
        }
        changed
    }

    /// 不按合并规则、直接换掉一个元素（可以换排序键）：只给“先记成墓碑的撤回后来证明是伪造的、换回原文”用。
    pub fn replace(&mut self, item: Item) {
        match self.by_id.get(&item.key.id) {
            Some(&i) => self.items[i] = item,
            None => self.items.push(item),
        }
        self.items.sort_by(|a, b| a.key.cmp(&b.key));
        self.rebuild();
    }

    /// 去掉一个元素（宿主那边已经没有了时用）。
    pub fn remove(&mut self, id: &MsgId) {
        if let Some(&i) = self.by_id.get(id) {
            self.items.remove(i);
            self.rebuild();
        }
    }

    /// `[lower, upper)` 里第一个和最后一个之后的下标。
    fn span(&self, lower: Option<&Key>, upper: &Upper) -> (usize, usize) {
        let start = match lower {
            Some(lower) => self.items.partition_point(|item| &item.key < lower),
            None => 0,
        };
        let end = match upper {
            Upper::Key(upper) => self.items.partition_point(|item| &item.key < upper),
            Upper::End => self.items.len(),
        };
        (start, end.max(start))
    }

    fn fingerprint(&self, start: usize, end: usize) -> Fingerprint {
        let sum = self.prefix[end].wrapping_sub(self.prefix[start]);
        Fingerprint { sum: Fixed(sum.to_le_bytes()), count: (end - start) as u64 }
    }

    /// 把 `[start, end)` 这一段写成清单或细分后的指纹，接在 `out` 后面。`upper` 是整段的上界。
    fn describe(&self, start: usize, end: usize, upper: &Upper, out: &mut Vec<Range>) {
        let count = end - start;
        if count <= LIST_MAX {
            out.push(Range {
                upper: upper.clone(),
                body: Body::List { items: self.items[start..end].iter().map(Entry::of).collect() },
            });
            return;
        }
        let per = count.div_ceil(SPLIT);
        let mut from = start;
        while from < end {
            let to = (from + per).min(end);
            let bucket_upper = if to < end { Upper::Key(self.items[to].key.clone()) } else { upper.clone() };
            out.push(Range { upper: bucket_upper, body: Body::Fp { fp: self.fingerprint(from, to) } });
            from = to;
        }
    }

    /// 发起对账：整个集合的第一条消息。
    pub fn initiate(&self) -> Vec<Range> {
        let mut out = Vec::new();
        self.describe(0, self.items.len(), &Upper::End, &mut out);
        if out.is_empty() {
            out.push(Range { upper: Upper::End, body: Body::List { items: Vec::new() } });
        }
        out
    }

    /// 处理对方的一条对账消息，算出要回的消息、我该给对方的编号、我该向对方要的编号。
    pub fn respond(&self, ranges: &[Range]) -> Result<Outcome> {
        if ranges.is_empty() || ranges.len() > RANGES_MAX {
            return Err(CoreError::format("对账消息的段数不对"));
        }
        let mut outcome = Outcome::default();
        let mut lower: Option<Key> = None;
        let mut previous: Option<&Upper> = None;
        for (i, range) in ranges.iter().enumerate() {
            // 上界必须严格递增，最后一段到最后：不然两边看的不是同一片键空间。
            if let Some(previous) = previous
                && *previous >= range.upper
            {
                return Err(CoreError::format("对账消息的段没有按顺序"));
            }
            if i + 1 == ranges.len() && range.upper != Upper::End {
                return Err(CoreError::format("对账消息没有覆盖到最后"));
            }
            let (start, end) = self.span(lower.as_ref(), &range.upper);
            match &range.body {
                Body::Skip => push_skip(&mut outcome.reply, &range.upper),
                Body::Fp { fp } => {
                    if self.fingerprint(start, end) == *fp {
                        push_skip(&mut outcome.reply, &range.upper);
                    } else {
                        self.describe(start, end, &range.upper, &mut outcome.reply);
                    }
                }
                Body::List { items } => {
                    if items.len() > LIST_ITEMS_MAX {
                        return Err(CoreError::format("对账清单太长"));
                    }
                    self.compare(lower.as_ref(), &range.upper, start, end, items, &mut outcome)?;
                    push_skip(&mut outcome.reply, &range.upper);
                }
            }
            lower = match &range.upper {
                Upper::Key(key) => Some(key.clone()),
                Upper::End => None,
            };
            previous = Some(&range.upper);
        }
        outcome.done = outcome.reply.iter().all(|range| range.body == Body::Skip);
        Ok(outcome)
    }

    fn compare(&self, lower: Option<&Key>, upper: &Upper, start: usize, end: usize, theirs: &[Entry], outcome: &mut Outcome) -> Result<()> {
        let mut seen: HashMap<&MsgId, State> = HashMap::with_capacity(theirs.len());
        for entry in theirs {
            if lower.is_some_and(|lower| &entry.key < lower) || !upper.admits(&entry.key) {
                return Err(CoreError::format("对账清单的元素不在这一段里"));
            }
            seen.insert(&entry.key.id, entry.state()?);
        }
        for entry in theirs {
            let state = seen[&entry.key.id];
            match self.get(&entry.key.id) {
                // 我没有（或者我的在别的段里——排序键不同，按缺处理，由验签时的核对拒绝伪造）。
                None => outcome.need.push(entry.key.id.clone()),
                Some(mine) => match (mine.state, state) {
                    (State::Full(_), State::Tombstone) => outcome.need.push(entry.key.id.clone()),
                    (State::Tombstone, State::Full(_)) => outcome.have.push(entry.key.id.clone()),
                    (State::Full(a), State::Full(b)) if a != b => outcome.conflicts.push(entry.key.id.clone()),
                    _ => {}
                },
            }
        }
        for item in &self.items[start..end] {
            if !seen.contains_key(&item.key.id) {
                outcome.have.push(item.key.id.clone());
            }
        }
        Ok(())
    }
}

fn push_skip(reply: &mut Vec<Range>, upper: &Upper) {
    // 连着的几段都一致时合成一段，回的消息更短。
    if let Some(last) = reply.last_mut()
        && last.body == Body::Skip
    {
        last.upper = upper.clone();
        return;
    }
    reply.push(Range { upper: upper.clone(), body: Body::Skip });
}

/// 处理一条对账消息的结果。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// 要回给对方的消息；`done` 为真时不用再回。
    pub reply: Vec<Range>,
    /// 对方缺、我该给的（原文或墓碑）。
    pub have: Vec<MsgId>,
    /// 我缺、该向对方要的。
    pub need: Vec<MsgId>,
    /// 同一编号两边原文不同：不该出现（编号签在密文里），只记日志、不交换。
    pub conflicts: Vec<MsgId>,
    /// 这一轮没有要细看的段了。
    pub done: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用的确定性随机数（xorshift），不引新依赖。
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn id(rng: &mut Rng) -> MsgId {
        let mut raw = [0u8; 16];
        raw[..8].copy_from_slice(&rng.next().to_le_bytes());
        raw[8..].copy_from_slice(&rng.next().to_le_bytes());
        MsgId::from_raw(raw)
    }

    fn full(at: i64, id: MsgId) -> Item {
        let digest = raw_digest(id.as_str());
        Item { key: Key { at, id }, state: State::Full(digest) }
    }

    /// 两边跑到静止，返回（A 给 B 的，B 给 A 的，往返轮数，传的字节数）。
    fn run(a: &Index, b: &Index) -> (Vec<MsgId>, Vec<MsgId>, usize, usize) {
        let mut a_gives = Vec::new();
        let mut b_gives = Vec::new();
        let mut message = a.initiate();
        let mut bytes = serde_json::to_vec(&message).unwrap().len();
        let mut rounds = 0;
        // b 先回，然后轮流。
        let mut turn_b = true;
        loop {
            rounds += 1;
            assert!(rounds < 64, "对账没有收敛");
            let side = if turn_b { b } else { a };
            let outcome = side.respond(&message).unwrap();
            assert!(outcome.conflicts.is_empty());
            if turn_b {
                b_gives.extend(outcome.have);
                a_gives.extend(outcome.need);
            } else {
                a_gives.extend(outcome.have);
                b_gives.extend(outcome.need);
            }
            if outcome.done {
                break;
            }
            bytes += serde_json::to_vec(&outcome.reply).unwrap().len();
            message = outcome.reply;
            turn_b = !turn_b;
        }
        a_gives.sort();
        a_gives.dedup();
        b_gives.sort();
        b_gives.dedup();
        (a_gives, b_gives, rounds, bytes)
    }

    #[test]
    fn read_positions_sort_like_keys_and_fit_the_protocol() {
        let key = |at, raw| Key { at, id: MsgId::from_raw([raw; 16]) };
        let mut keys = [key(1_700_000_000_000, 0), key(1_700_000_000_000, 255), key(1_700_000_000_000, 7), key(999, 3), key(1_700_000_000_001, 1)];
        keys.sort();
        let positions: Vec<String> = keys.iter().map(read_position).collect();
        for pair in positions.windows(2) {
            assert!(pair[0].len() < pair[1].len() || (pair[0].len() == pair[1].len() && pair[0] < pair[1]), "{pair:?}");
        }
        for position in &positions {
            assert!(position.len() <= 64 && position.bytes().all(|c| c.is_ascii_digit()) && !position.starts_with('0'));
        }
    }

    #[test]
    fn next_at_is_later_than_everything_seen() {
        assert_eq!(next_at(100, None), 100);
        assert_eq!(next_at(100, Some(50)), 100);
        assert_eq!(next_at(100, Some(100)), 101);
        // 本机时间慢了一小时：仍排在见过的之后。
        assert_eq!(next_at(1_000, Some(3_600_000)), 3_600_001);
    }

    #[test]
    fn raw_digest_matches_plain_sha256() {
        // 宿主按同一算法算 rawDigest：SHA-256("abc") 的前 16 字节。
        assert_eq!(raw_digest("abc").0, [0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23]);
    }

    #[test]
    fn keys_order_by_time_then_id_bytes() {
        let mut rng = Rng(7);
        let (x, y) = (id(&mut rng), id(&mut rng));
        let (lo, hi) = if x.as_str() < y.as_str() { (x, y) } else { (y, x) };
        assert!(Key { at: 1, id: hi.clone() } < Key { at: 2, id: lo.clone() });
        assert!(Key { at: 5, id: lo } < Key { at: 5, id: hi });
    }

    #[test]
    fn identical_sets_finish_in_one_round() {
        let mut rng = Rng(1);
        let items: Vec<Item> = (0..1000).map(|i| full(i, id(&mut rng))).collect();
        let a = Index::new(items.clone());
        let b = Index::new(items);
        let (ag, bg, rounds, _) = run(&a, &b);
        assert!(ag.is_empty() && bg.is_empty());
        assert_eq!(rounds, 1);
    }

    #[test]
    fn empty_sides_exchange_everything() {
        let mut rng = Rng(2);
        let items: Vec<Item> = (0..300).map(|i| full(i, id(&mut rng))).collect();
        let a = Index::new(items.clone());
        let b = Index::default();
        let (ag, bg, _, _) = run(&a, &b);
        assert_eq!(ag.len(), 300);
        assert!(bg.is_empty());
        let (ag, bg, _, _) = run(&b, &a);
        assert!(ag.is_empty());
        assert_eq!(bg.len(), 300);
    }

    #[test]
    fn tombstone_beats_original_in_both_directions() {
        let mut rng = Rng(3);
        let items: Vec<Item> = (0..200).map(|i| full(i, id(&mut rng))).collect();
        let target = items[100].key.clone();
        let mut b_items = items.clone();
        b_items[100].state = State::Tombstone;
        let a = Index::new(items);
        let b = Index::new(b_items);
        let (ag, bg, _, _) = run(&a, &b);
        assert!(ag.is_empty(), "有原文的一方不该把原文给有墓碑的一方");
        assert_eq!(bg, vec![target.id.clone()]);
        let (ag, bg, _, _) = run(&b, &a);
        assert_eq!(ag, vec![target.id]);
        assert!(bg.is_empty());
    }

    #[test]
    fn merge_keeps_tombstones_and_is_order_independent() {
        let mut rng = Rng(4);
        let x = full(10, id(&mut rng));
        let tomb = Item { key: x.key.clone(), state: State::Tombstone };
        let mut one = Index::default();
        one.merge([x.clone()]);
        one.merge([tomb.clone()]);
        let mut two = Index::default();
        two.merge([tomb.clone()]);
        two.merge([x]);
        assert_eq!(one.items(), two.items());
        assert_eq!(one.get(&tomb.key.id).unwrap().state, State::Tombstone);
    }

    #[test]
    fn random_sets_find_exactly_the_differences() {
        for seed in 1..=300u64 {
            let mut rng = Rng(seed * 2654435761 + 1);
            let shared = rng.below(2000) as usize;
            let mut a_items = Vec::new();
            let mut b_items = Vec::new();
            for _ in 0..shared {
                // 时间有大量重复，考验同一毫秒按编号排序。
                let item = full(rng.below(500) as i64, id(&mut rng));
                a_items.push(item.clone());
                b_items.push(item);
            }
            let only_a: Vec<Item> = (0..rng.below(40)).map(|_| full(rng.below(500) as i64, id(&mut rng))).collect();
            let only_b: Vec<Item> = (0..rng.below(40)).map(|_| full(rng.below(500) as i64, id(&mut rng))).collect();
            // 一部分共有的在某一边变成墓碑。
            let mut tomb_a = Vec::new();
            let mut tomb_b = Vec::new();
            for i in 0..shared {
                match rng.below(50) {
                    0 => {
                        a_items[i].state = State::Tombstone;
                        tomb_a.push(a_items[i].key.id.clone());
                    }
                    1 => {
                        b_items[i].state = State::Tombstone;
                        tomb_b.push(b_items[i].key.id.clone());
                    }
                    _ => {}
                }
            }
            a_items.extend(only_a.clone());
            b_items.extend(only_b.clone());
            let a = Index::new(a_items);
            let b = Index::new(b_items);
            let (ag, bg, rounds, _) = run(&a, &b);
            let mut want_ag: Vec<MsgId> = only_a.iter().map(|i| i.key.id.clone()).chain(tomb_a).collect();
            let mut want_bg: Vec<MsgId> = only_b.iter().map(|i| i.key.id.clone()).chain(tomb_b).collect();
            want_ag.sort();
            want_bg.sort();
            assert_eq!(ag, want_ag, "种子 {seed}：A 该给的不对");
            assert_eq!(bg, want_bg, "种子 {seed}：B 该给的不对");
            assert!(rounds <= 12, "种子 {seed}：轮数 {rounds} 太多");
        }
    }

    #[test]
    fn ten_thousand_with_ten_differences_is_small() {
        let mut rng = Rng(99);
        let shared: Vec<Item> = (0..10_000).map(|i| full(1_700_000_000_000 + i * 37, id(&mut rng))).collect();
        let mut a_items = shared.clone();
        let mut b_items = shared;
        for _ in 0..5 {
            a_items.push(full(1_700_000_000_000 + rng.below(370_000) as i64, id(&mut rng)));
            b_items.push(full(1_700_000_000_000 + rng.below(370_000) as i64, id(&mut rng)));
        }
        let a = Index::new(a_items);
        let b = Index::new(b_items);
        let (ag, bg, rounds, bytes) = run(&a, &b);
        assert_eq!(ag.len(), 5);
        assert_eq!(bg.len(), 5);
        // 契约：相差 10 条时来回不超过 100 KB（这里只算摘要，原件另计）。
        eprintln!("1 万条、相差 10 条：{rounds} 轮，摘要 {bytes} 字节");
        assert!(bytes < 100 * 1024, "摘要传了 {bytes} 字节");
        assert!(rounds <= 8, "轮数 {rounds}");
    }

    #[test]
    fn malformed_messages_are_refused() {
        let a = Index::default();
        assert!(a.respond(&[]).is_err());
        let not_to_end = vec![Range { upper: Upper::Key(Key { at: 5, id: MsgId::from_raw([1; 16]) }), body: Body::Skip }];
        assert!(a.respond(&not_to_end).is_err());
        let unordered = vec![
            Range { upper: Upper::Key(Key { at: 5, id: MsgId::from_raw([1; 16]) }), body: Body::Skip },
            Range { upper: Upper::Key(Key { at: 4, id: MsgId::from_raw([1; 16]) }), body: Body::Skip },
            Range { upper: Upper::End, body: Body::Skip },
        ];
        assert!(a.respond(&unordered).is_err());
        let outside = vec![
            Range { upper: Upper::Key(Key { at: 5, id: MsgId::from_raw([1; 16]) }), body: Body::Skip },
            Range {
                upper: Upper::End,
                body: Body::List {
                    items: vec![Entry { key: Key { at: 1, id: MsgId::from_raw([2; 16]) }, tomb: false, raw: Some(Fixed([0; 16])) }],
                },
            },
        ];
        assert!(a.respond(&outside).is_err());
        let bad_state = vec![Range {
            upper: Upper::End,
            body: Body::List { items: vec![Entry { key: Key { at: 1, id: MsgId::from_raw([2; 16]) }, tomb: true, raw: Some(Fixed([0; 16])) }] },
        }];
        assert!(a.respond(&bad_state).is_err());
    }
}
