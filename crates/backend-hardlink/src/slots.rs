//! The slot pool: numbered directories a morph diffs into, and the bookkeeping that decides which
//! one a create gets.
//!
//! A slot's value is entirely its last tree. Handing a create the slot whose tree is closest to the
//! one it wants is what turns a projection into a diff, so the claim order is cheapest-diff-first
//! and a released slot keeps everything it holds.

use backend::tree::Dir;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Free slots kept before the coldest are retired. Each holds a whole tree's dirents, and a stale
/// tree only gets colder, so an unbounded pool trades disk metadata for reuse that never comes.
const MAX_FREE: usize = 128;

/// What the next morph into a slot needs to know about the last one: the tree to diff against, and
/// the scratch the prior occupant left to clear.
#[derive(Default, Clone)]
pub struct Prior {
    pub tree: Option<Arc<Dir>>,
    pub outputs: BTreeMap<String, String>,
    pub writable: BTreeMap<String, String>,
}

#[derive(PartialEq)]
enum State {
    Free,
    Busy,
    /// The number survives its directory so a later claim can rebuild at the same path.
    Retired,
}

struct Slot {
    state: State,
    root_digest: String,
    /// The action this slot last served, as `Manifest::first_output`. Unlike the root digest it
    /// survives an edit to the action's inputs, which is exactly the case where the slot's tree is
    /// still the best available diff base.
    identity: String,
    prior: Prior,
    lru: u64,
}

#[derive(Default)]
pub struct SlotTable {
    slots: Vec<Slot>,
    tick: u64,
    reuse_count: u64,
}

impl SlotTable {
    /// Take a slot for a create, and the prior occupant it must reconcile away.
    pub fn claim(&mut self, root_digest: &str, identity: &str) -> (usize, Prior) {
        let (n, reused) = self.pick(root_digest, identity);
        if reused {
            self.reuse_count += 1;
        }
        self.slots[n].state = State::Busy;
        (n, std::mem::take(&mut self.slots[n].prior))
    }

    pub fn total_allocated(&self) -> usize {
        self.slots.len()
    }

    pub fn reuse_count(&self) -> u64 {
        self.reuse_count
    }

    /// Cheapest diff first: the same tree (no placement at all), then the same action (its tree is
    /// one edit away), then the warmest free slot, then a retired number, then growth.
    fn pick(&mut self, root_digest: &str, identity: &str) -> (usize, bool) {
        let free = |s: &Slot| s.state == State::Free;
        if !root_digest.is_empty() {
            if let Some(n) = self.slots.iter().position(|s| free(s) && s.root_digest == root_digest)
            {
                return (n, true);
            }
        }
        if !identity.is_empty() {
            if let Some(n) = self.slots.iter().position(|s| free(s) && s.identity == identity) {
                return (n, true);
            }
        }
        if let Some((n, _)) =
            self.slots.iter().enumerate().filter(|(_, s)| free(s)).max_by_key(|(_, s)| s.lru)
        {
            return (n, true);
        }
        if let Some(n) = self.slots.iter().position(|s| s.state == State::Retired) {
            self.slots[n].prior = Prior::default();
            self.slots[n].root_digest.clear();
            self.slots[n].identity.clear();
            return (n, false);
        }
        self.slots.push(Slot {
            state: State::Free,
            root_digest: String::new(),
            identity: String::new(),
            prior: Prior::default(),
            lru: 0,
        });
        (self.slots.len() - 1, false)
    }

    /// Record what the slot now holds. A `None` tree means the morph did not finish and the
    /// contents are unknown, so the next reconcile clears defensively instead of trusting a
    /// listing that never matched disk.
    pub fn occupy(&mut self, n: usize, root_digest: &str, identity: &str, prior: Prior) {
        let s = &mut self.slots[n];
        s.root_digest = if prior.tree.is_some() { root_digest.to_string() } else { String::new() };
        s.identity = identity.to_string();
        s.prior = prior;
    }

    /// Hand the slot back, and name the slots whose directories the caller should now delete.
    pub fn release(&mut self, n: usize) -> Vec<usize> {
        self.tick += 1;
        let tick = self.tick;
        let s = &mut self.slots[n];
        s.state = State::Free;
        s.lru = tick;

        let mut free: Vec<(u64, usize)> = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.state == State::Free)
            .map(|(i, s)| (s.lru, i))
            .collect();
        if free.len() <= MAX_FREE {
            return Vec::new();
        }
        free.sort_unstable();
        free.truncate(free.len() - MAX_FREE);
        for (_, i) in &free {
            let s = &mut self.slots[*i];
            s.state = State::Retired;
            s.prior = Prior::default();
            s.root_digest.clear();
            s.identity.clear();
        }
        free.into_iter().map(|(_, i)| i).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(digest: &str) -> Prior {
        Prior { tree: Some(Arc::new(Dir { digest: digest.into(), ..Default::default() })), ..Default::default() }
    }

    /// Fill the table with distinct occupied slots, then hand them all back.
    fn stocked(entries: &[(&str, &str)]) -> SlotTable {
        let mut t = SlotTable::default();
        let mut held = Vec::new();
        for (dg, id) in entries {
            let (n, _) = t.claim(dg, id);
            t.occupy(n, dg, id, tree(dg));
            held.push(n);
        }
        for n in held {
            t.release(n);
        }
        t
    }

    #[test]
    fn an_exact_tree_wins_over_the_action_and_over_warmth() {
        let mut t = stocked(&[("A", "//x"), ("B", "//y"), ("C", "//z")]);
        // "//x" would match slot 0 by identity, and slot 2 is the warmest; the exact digest is
        // still the cheapest diff, so it outranks both.
        let (n, prior) = t.claim("C", "//x");
        assert_eq!(n, 2);
        assert_eq!(prior.tree.unwrap().digest, "C");
    }

    /// A free slot is never grown past: the pool only widens when every slot is busy.
    #[test]
    fn a_free_slot_is_reused_rather_than_growing_the_pool() {
        let mut t = stocked(&[("A", "//x")]);
        let (n, _) = t.claim("unrelated", "//unrelated");
        assert_eq!(n, 0);
        assert_eq!(t.slots.len(), 1);
    }

    /// The action's own slot is the base when its inputs changed, so the digest no longer matches.
    #[test]
    fn the_actions_own_slot_is_the_fallback_base() {
        let mut t = stocked(&[("A", "//x"), ("B", "//y")]);
        let (n, prior) = t.claim("EDITED", "//x");
        assert_eq!(n, 0);
        assert_eq!(prior.tree.unwrap().digest, "A");
    }

    /// Two live sandboxes never share a slot.
    #[test]
    fn a_busy_slot_is_never_handed_out_twice() {
        let mut t = SlotTable::default();
        let (a, _) = t.claim("A", "//x");
        t.occupy(a, "A", "//x", tree("A"));
        let (b, _) = t.claim("A", "//x");
        assert_ne!(a, b, "an exact digest match must not steal a busy slot");
    }

    /// An unfinished morph forfeits the slot's identity as a diff base.
    #[test]
    fn an_unfinished_morph_leaves_no_digest_to_match() {
        let mut t = SlotTable::default();
        let (n, _) = t.claim("A", "//x");
        t.occupy(n, "A", "//x", Prior::default());
        t.release(n);
        let (again, prior) = t.claim("A", "//x");
        assert_eq!(again, n, "still reachable by identity");
        assert!(prior.tree.is_none(), "but not trusted as a listing of what is on disk");
    }

    /// The pool is bounded, and it retires the coldest slots rather than the newest.
    #[test]
    fn the_pool_retires_the_coldest_free_slots() {
        let mut t = SlotTable::default();
        let mut claimed = Vec::new();
        for i in 0..MAX_FREE + 3 {
            let dg = format!("d{i}");
            let (n, _) = t.claim(&dg, &dg);
            t.occupy(n, &dg, &dg, tree(&dg));
            claimed.push(n);
        }
        let mut retired = Vec::new();
        for n in claimed {
            retired.extend(t.release(n));
        }
        assert_eq!(retired, vec![0, 1, 2], "the three released earliest are the ones retired");

        // A retired number is only for growth: with slots still free, one of those is warmer and
        // wins. The pool does not widen either way.
        let before = t.slots.len();
        let mut held = Vec::new();
        for i in 0..MAX_FREE {
            let (n, _) = t.claim(&format!("x{i}"), &format!("x{i}"));
            assert!(!retired.contains(&n), "a free slot outranks a retired number");
            held.push(n);
        }
        let (n, _) = t.claim("fresh", "//fresh");
        assert!(retired.contains(&n), "with nothing free, a retired number is rebuilt at");
        assert_eq!(t.slots.len(), before, "and the pool does not widen");
    }
}
