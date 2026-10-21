//! Experimental bounded alternatives to the encoder's full-window finder.
//!
//! Both policies keep an ordinary dense chain for the most recent 64 KiB and
//! sample positions as they leave that chain, at 256-byte intervals. Older
//! samples occupy 256 four-byte-prefix buckets with 16 entries each. Cyclic
//! replacement follows a bucket's cursor; useful replacement keeps entries
//! whose verified matches have earned a larger, periodically aged score.
//! That score estimates literal bits saved minus distance bits, not Huffman
//! prices or the parser's eventual decisions. Neither policy changes the RAR dictionary
//! or its legal matches: every candidate is checked against the actual input.

use super::match_finder::{MatchFinder, NO_POSITION};
use super::workspace::{Allowance, Budget, Buffer};
use super::Result;

const RECENT_LIMIT: usize = 64 * 1024;
const ADMISSION_STRIDE: usize = 256;
const BUCKETS: usize = 256;
const WAYS: usize = 16;
const ENTRIES: usize = BUCKETS * WAYS;
const AGE_INTERVAL: u8 = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AnchorPolicy {
    Cyclic,
    Useful,
}

#[derive(Clone, Copy, Debug)]
struct Anchor {
    position: usize,
    score: u32,
}

impl Anchor {
    const EMPTY: Self = Self {
        position: NO_POSITION,
        score: 0,
    };
}

#[derive(Clone, Copy, Debug, Default)]
struct Bucket {
    cursor: u8,
    admissions: u8,
}

#[derive(Debug)]
pub(crate) struct AnchorMatchFinder<B: Budget = Allowance> {
    recent: MatchFinder<4, B>,
    anchors: Buffer<Anchor, B>,
    buckets: Buffer<Bucket, B>,
    policy: AnchorPolicy,
    window: usize,
    recent_span: usize,
    newest: Option<usize>,
    last_admitted: Option<usize>,
}

impl<B: Budget> AnchorMatchFinder<B> {
    pub(crate) fn with_allowance(
        window: usize,
        allowance: &B,
        policy: AnchorPolicy,
    ) -> Result<Self> {
        let recent_span = window.clamp(1, RECENT_LIMIT).next_power_of_two();
        Ok(Self {
            recent: MatchFinder::with_allowance(recent_span, allowance)?,
            anchors: Buffer::filled(ENTRIES, Anchor::EMPTY, allowance)?,
            buckets: Buffer::filled(BUCKETS, Bucket::default(), allowance)?,
            policy,
            window,
            recent_span,
            newest: None,
            last_admitted: None,
        })
    }

    pub(crate) fn allowance(&self) -> B {
        self.anchors.allowance()
    }

    fn hash(input: &[u8], pos: usize) -> usize {
        let prefix = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap());
        (prefix.wrapping_mul(0x9E37_79B1) >> 24) as usize
    }

    /// Inserts monotonically increasing positions in the same combined input
    /// coordinate system. Duplicate or older insertions are harmless no-ops.
    /// No input is borrowed or copied. A skipped interval is not rescanned: at
    /// most one aged-out sample is admitted by an insertion.
    pub(crate) fn insert(&mut self, input: &[u8], pos: usize) {
        if pos.checked_add(4).is_none_or(|end| end > input.len())
            || self.newest.is_some_and(|newest| pos <= newest)
        {
            return;
        }
        if let Some(aged_out) = pos.checked_sub(self.recent_span) {
            let sample = aged_out / ADMISSION_STRIDE * ADMISSION_STRIDE;
            if self.last_admitted.is_none_or(|previous| sample > previous) {
                self.remember(Self::hash(input, sample), sample, pos);
                self.last_admitted = Some(sample);
            }
        }
        self.recent.insert(input, pos);
        self.newest = Some(pos);
    }

    fn remember(&mut self, hash: usize, position: usize, current: usize) {
        let bucket = &mut self.buckets[hash];
        let entries = &mut self.anchors[hash * WAYS..(hash + 1) * WAYS];
        bucket.admissions += 1;
        if bucket.admissions == AGE_INTERVAL {
            for entry in entries.iter_mut() {
                entry.score >>= 1;
            }
            bucket.admissions = 0;
        }
        let cursor = usize::from(bucket.cursor);
        let mut replacement = cursor;
        // Empty/expired storage takes priority for both policies. Walking from
        // the cursor makes all score ties deterministic and prevents one way
        // from receiving every equal-score admission.
        let mut reusable = false;
        for offset in 0..WAYS {
            let index = (cursor + offset) % WAYS;
            let entry = &entries[index];
            if entry.position == NO_POSITION || current.saturating_sub(entry.position) > self.window
            {
                replacement = index;
                reusable = true;
                break;
            }
        }
        if !reusable && self.policy == AnchorPolicy::Useful {
            for offset in 1..WAYS {
                let index = (cursor + offset) % WAYS;
                if entries[index].score < entries[replacement].score {
                    replacement = index;
                }
            }
        }
        entries[replacement] = Anchor { position, score: 1 };
        bucket.cursor = ((replacement + 1) % WAYS) as u8;
    }

    /// Lists the bucket's reachable older candidates, nearest first. Keeping
    /// full-width source offsets avoids a second wraparound scheme for anchors.
    fn ordered_anchors(
        &self,
        hash: usize,
        pos: usize,
        max_distance: usize,
    ) -> ([usize; WAYS], usize) {
        // Optimal BlockMatches stores distances in u32. Source coordinates can
        // exceed four GiB, but admitting a wider distance would truncate it in
        // that representation before the parser emits the match.
        let max_distance = max_distance.min(u32::MAX as usize);
        let mut ordered = [0usize; WAYS];
        let mut count = 0;
        for way in 0..WAYS {
            let index = hash * WAYS + way;
            let candidate = self.anchors[index].position;
            if candidate >= pos {
                continue;
            }
            let distance = pos - candidate;
            if distance < self.recent_span || distance > max_distance {
                continue;
            }
            let mut insertion = count;
            while insertion > 0 && self.anchors[ordered[insertion - 1]].position < candidate {
                ordered[insertion] = ordered[insertion - 1];
                insertion -= 1;
            }
            ordered[insertion] = index;
            count += 1;
        }
        (ordered, count)
    }

    fn verified_length(input: &[u8], pos: usize, candidate: usize, limit: usize) -> usize {
        if input[candidate..candidate + 4] != input[pos..pos + 4] {
            return 0;
        }
        // Share the existing word-at-a-time verifier with the baseline finder;
        // replacing the index should not introduce a slower comparison loop.
        super::fast::match_length(input, pos, pos - candidate, limit)
    }

    /// Visits verified matches nearest first. `false` stops immediately. The
    /// original candidate allowance is split between the two indexes: when
    /// older anchors exist, up to one quarter (at least one, at most 16) is
    /// reserved for them, so collisions in the recent chain cannot starve
    /// the cache. Unused recent visits can also be spent on anchors.
    pub(crate) fn search(
        &mut self,
        input: &[u8],
        pos: usize,
        max_length: usize,
        max_distance: usize,
        cut: usize,
        mut visit: impl FnMut(usize, usize) -> bool,
    ) {
        let Some(available) = input.len().checked_sub(pos) else {
            return;
        };
        let limit = max_length.min(available);
        let max_distance = max_distance.min(self.window).min(pos);
        if limit < 4 || max_distance == 0 || cut == 0 {
            return;
        }
        let (ordered, count) = self.ordered_anchors(Self::hash(input, pos), pos, max_distance);
        let anchor_quota = count.min((cut / 4).max(1)).min(WAYS);
        let recent_quota = cut - anchor_quota;
        let mut checked = 0;
        let mut candidate = self.recent.first(input, pos);
        while candidate != NO_POSITION && checked < recent_quota {
            if candidate >= pos {
                candidate = self.recent.previous(candidate);
                continue;
            }
            let distance = pos - candidate;
            if distance >= self.recent_span || distance > max_distance {
                break;
            }
            checked += 1;
            let length = Self::verified_length(input, pos, candidate, limit);
            if length >= 4 && !visit(length, distance) {
                return;
            }
            candidate = self.recent.previous(candidate);
        }
        for &index in ordered.iter().take(count.min(cut - checked)) {
            let candidate = self.anchors[index].position;
            let distance = pos - candidate;
            let length = Self::verified_length(input, pos, candidate, limit);
            if length < 4 {
                continue;
            }
            if self.policy == AnchorPolicy::Useful {
                let distance_bits = usize::BITS - distance.leading_zeros();
                let literal_bits = (length as u64).saturating_mul(8);
                let benefit = literal_bits.saturating_sub(u64::from(distance_bits) + 8);
                self.anchors[index].score = self.anchors[index]
                    .score
                    .saturating_add(benefit.min(u64::from(u32::MAX)) as u32);
            }
            if !visit(length, distance) {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::workspace::RefusingBudget;

    fn finder(window: usize, policy: AnchorPolicy) -> AnchorMatchFinder {
        AnchorMatchFinder::with_allowance(window, &Allowance::default(), policy).unwrap()
    }

    fn matches(
        finder: &mut AnchorMatchFinder,
        input: &[u8],
        pos: usize,
        max_length: usize,
        max_distance: usize,
        cut: usize,
    ) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        finder.search(
            input,
            pos,
            max_length,
            max_distance,
            cut,
            |length, distance| {
                out.push((length, distance));
                true
            },
        );
        out
    }

    #[test]
    fn recent_matches_are_verified_bounded_and_nearest_first() {
        let input = b"abcdabcdabcdabcd";
        for policy in [AnchorPolicy::Cyclic, AnchorPolicy::Useful] {
            let mut finder = finder(32, policy);
            for pos in 0..=8 {
                finder.insert(input, pos);
            }
            finder.insert(input, 8);
            finder.insert(input, 4);
            assert_eq!(matches(&mut finder, input, 8, 6, 7, 20), vec![(6, 4)]);
            assert!(matches(&mut finder, input, 8, 3, 32, 20).is_empty());
            assert!(matches(&mut finder, input, input.len(), 8, 32, 20).is_empty());
            assert!(matches(&mut finder, input, usize::MAX, 8, 32, 20).is_empty());
            assert!(matches(&mut finder, input, 8, 8, 32, 0).is_empty());
        }
    }

    #[test]
    fn aged_samples_find_far_repeats_and_obey_dictionary_expiry() {
        let mut input = vec![0u8; RECENT_LIMIT + 1024];
        input[..8].copy_from_slice(b"abcdefgh");
        input[RECENT_LIMIT + 256..RECENT_LIMIT + 264].copy_from_slice(b"abcdefgh");
        let pos = RECENT_LIMIT + 256;
        for policy in [AnchorPolicy::Cyclic, AnchorPolicy::Useful] {
            let mut finder = finder(2 * RECENT_LIMIT, policy);
            for at in 0..=pos {
                finder.insert(&input, at);
            }
            assert_eq!(
                matches(&mut finder, &input, pos, 8, pos, 20),
                vec![(8, pos)]
            );
            assert!(matches(&mut finder, &input, pos, 8, pos - 1, 20).is_empty());
            finder.window = pos - 1;
            assert!(matches(&mut finder, &input, pos, 8, pos, 20).is_empty());
        }
    }

    #[test]
    fn admission_is_sparse_and_does_not_rescan_skipped_input() {
        let input = vec![0u8; RECENT_LIMIT + 1028];
        let mut finder = finder(4 * RECENT_LIMIT, AnchorPolicy::Cyclic);
        finder.insert(&input, RECENT_LIMIT);
        finder.insert(&input, RECENT_LIMIT + 255);
        finder.insert(&input, RECENT_LIMIT + 256);
        finder.insert(&input, RECENT_LIMIT + 1024);
        let positions: Vec<_> = finder
            .anchors
            .iter()
            .filter(|anchor| anchor.position != NO_POSITION)
            .map(|anchor| anchor.position)
            .collect();
        assert_eq!(positions, vec![0, 256, 1024]);
    }

    #[test]
    fn cyclic_replacement_rotates_and_useful_retains_rewarded_anchor() {
        for policy in [AnchorPolicy::Cyclic, AnchorPolicy::Useful] {
            let mut finder = finder(usize::MAX, policy);
            for position in 0..WAYS {
                finder.remember(0, position, RECENT_LIMIT);
            }
            finder.anchors[0].score = 1000;
            finder.remember(0, 100, RECENT_LIMIT);
            if policy == AnchorPolicy::Cyclic {
                assert_eq!(finder.anchors[0].position, 100);
            } else {
                assert_eq!(finder.anchors[0].position, 0);
                assert_eq!(finder.anchors[1].position, 100);
                // A useful entry is not immortal: deterministic admissions age it.
                for position in 101..1200 {
                    finder.remember(0, position, RECENT_LIMIT);
                }
                assert!(finder.anchors[..WAYS]
                    .iter()
                    .all(|entry| entry.position != 0));
            }
        }
    }

    #[test]
    fn usefulness_is_earned_only_by_verified_matches_and_saturates() {
        let mut input = vec![0u8; RECENT_LIMIT + 12];
        input[..8].copy_from_slice(b"abcdefgh");
        input[RECENT_LIMIT..RECENT_LIMIT + 8].copy_from_slice(b"abcdefgh");
        let hash = AnchorMatchFinder::<Allowance>::hash(&input, 0);
        let mut finder = finder(2 * RECENT_LIMIT, AnchorPolicy::Useful);
        finder.remember(hash, 0, RECENT_LIMIT);
        let index = hash * WAYS;
        assert_eq!(
            matches(&mut finder, &input, RECENT_LIMIT, 8, RECENT_LIMIT, 1),
            vec![(8, RECENT_LIMIT)]
        );
        assert!(finder.anchors[index].score > 1);
        finder.anchors[index].score = u32::MAX;
        matches(&mut finder, &input, RECENT_LIMIT, 8, RECENT_LIMIT, 1);
        assert_eq!(finder.anchors[index].score, u32::MAX);
        input[RECENT_LIMIT] = b'x';
        // Force a hash collision to check the full prefix rather than trusting it.
        let collision_hash = AnchorMatchFinder::<Allowance>::hash(&input, RECENT_LIMIT);
        finder.remember(collision_hash, 0, RECENT_LIMIT);
        assert!(matches(&mut finder, &input, RECENT_LIMIT, 8, RECENT_LIMIT, 1).is_empty());
        assert_eq!(finder.anchors[collision_hash * WAYS].score, 1);
    }

    #[test]
    fn older_anchor_is_not_starved_by_recent_collisions() {
        let mut input = vec![b'a'; RECENT_LIMIT + 1024];
        input[..8].copy_from_slice(b"abcdGOOD");
        input[RECENT_LIMIT + 256..RECENT_LIMIT + 264].copy_from_slice(b"abcdGOOD");
        // Populate many recent candidates with the same four-byte prefix but
        // no long match. The one reserved anchor visit must still find zero.
        for pos in (RECENT_LIMIT - 4096..RECENT_LIMIT).step_by(8) {
            input[pos..pos + 8].copy_from_slice(b"abcdBAD!");
        }
        let pos = RECENT_LIMIT + 256;
        for policy in [AnchorPolicy::Cyclic, AnchorPolicy::Useful] {
            let mut finder = finder(2 * RECENT_LIMIT, policy);
            for at in 0..=pos {
                finder.insert(&input, at);
            }
            let found = matches(&mut finder, &input, pos, 8, pos, 4);
            assert!(found.contains(&(8, pos)));
            assert!(found.len() <= 4);
            assert!(found.windows(2).all(|pair| pair[0].1 < pair[1].1));
        }
    }

    #[test]
    fn early_stop_and_overlapping_matches_are_supported() {
        let input = vec![b'a'; 128];
        for policy in [AnchorPolicy::Cyclic, AnchorPolicy::Useful] {
            let mut finder = finder(64, policy);
            for pos in 0..=64 {
                finder.insert(&input, pos);
            }
            let mut calls = 0;
            finder.search(&input, 64, 64, 64, 100, |length, distance| {
                calls += 1;
                assert_eq!((length, distance), (64, 1));
                false
            });
            assert_eq!(calls, 1);
        }
    }

    #[test]
    fn anchor_offsets_retain_high_bits() {
        if usize::BITS <= 32 {
            return;
        }
        let Some(position) = (u32::MAX as usize).checked_add(123) else {
            return;
        };
        let mut finder = finder(usize::MAX, AnchorPolicy::Cyclic);
        finder.remember(0, 0, position + RECENT_LIMIT);
        finder.remember(0, position, position + RECENT_LIMIT);
        let (ordered, count) = finder.ordered_anchors(0, position + RECENT_LIMIT, usize::MAX);
        assert_eq!(count, 1);
        assert_eq!(finder.anchors[ordered[0]].position, position);
    }

    #[test]
    fn allocation_refusals_release_all_cache_and_chain_charges() {
        for fail_at in 0..4 {
            let allowance = RefusingBudget::new(fail_at);
            assert!(AnchorMatchFinder::with_allowance(
                RECENT_LIMIT,
                &allowance,
                AnchorPolicy::Useful
            )
            .is_err());
            assert_eq!(allowance.used(), 0, "allocation {fail_at}");
        }
        let allowance = Allowance::limited(1024 * 1024);
        {
            let finder =
                AnchorMatchFinder::with_allowance(RECENT_LIMIT, &allowance, AnchorPolicy::Useful)
                    .unwrap();
            assert!(finder.allowance().used() > 0);
            assert!(allowance.used() < 1024 * 1024);
        }
        assert_eq!(allowance.used(), 0);
        let allowance = Allowance::limited(1);
        assert!(
            AnchorMatchFinder::with_allowance(RECENT_LIMIT, &allowance, AnchorPolicy::Cyclic)
                .is_err()
        );
        assert_eq!(allowance.used(), 0);
    }

    #[test]
    fn policies_are_deterministic_over_the_same_operation_stream() {
        let input: Vec<_> = (0..RECENT_LIMIT + 4096)
            .map(|pos| ((pos / 17) % 251) as u8)
            .collect();
        for policy in [AnchorPolicy::Cyclic, AnchorPolicy::Useful] {
            let mut left = finder(2 * RECENT_LIMIT, policy);
            let mut right = finder(2 * RECENT_LIMIT, policy);
            for pos in 0..input.len() - 4 {
                left.insert(&input, pos);
                right.insert(&input, pos);
                if pos % 257 == 0 {
                    assert_eq!(
                        matches(&mut left, &input, pos, 64, pos, 16),
                        matches(&mut right, &input, pos, 64, pos, 16)
                    );
                }
            }
            let snapshot = |finder: &AnchorMatchFinder| {
                finder
                    .anchors
                    .iter()
                    .map(|entry| (entry.position, entry.score))
                    .collect::<Vec<_>>()
            };
            assert_eq!(snapshot(&left), snapshot(&right));
        }
    }
}
