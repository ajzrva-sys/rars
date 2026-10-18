//! Persistent hash-chain history plus immutable, representation-specific overlays.
//! Only committed bytes mutate the base; speculative hashes never enter its tail.
use super::*;

const ABSENT: u64 = u64::MAX;
const HASH_BITS: u32 = 17;

fn hash(bytes: [u8; 4]) -> usize {
    (u32::from_le_bytes(bytes).wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize
}

#[derive(Debug)]
pub(crate) struct CommittedChain<B: Budget = Allowance> {
    heads: Buffer<u64, B>,
    // Zero is no predecessor. Every nonzero entry is an exact backward distance
    // from its absolute origin, so there is no low-32-bit position sentinel.
    previous: Buffer<u32, B>,
    mask: usize,
    dictionary: usize,
    end: u64,
    indexed_until: u64,
    tail: [u8; 3],
    tail_len: usize,
    #[cfg(test)]
    seeded: u64,
}

impl<B: Budget> CommittedChain<B> {
    pub(crate) fn new_from_history(
        history: &[u8],
        dictionary: usize,
        stream_offset: u64,
        allowance: &B,
    ) -> Result<Self> {
        if dictionary == 0 || dictionary > u32::MAX as usize || history.len() > dictionary {
            return Err(Error::InvalidData(
                "hybrid committed chain dictionary is invalid",
            ));
        }
        let start = stream_offset
            .checked_sub(history.len() as u64)
            .ok_or(Error::InvalidData("hybrid chain history offset underflows"))?;
        let capacity = dictionary
            .checked_next_power_of_two()
            .ok_or(Error::InvalidData("hybrid chain capacity overflows"))?;
        let mut chain = Self {
            heads: Buffer::filled(1 << HASH_BITS, ABSENT, allowance)?,
            previous: Buffer::filled(capacity, 0, allowance)?,
            mask: capacity - 1,
            dictionary,
            end: stream_offset,
            indexed_until: start,
            tail: [0; 3],
            tail_len: 0,
            #[cfg(test)]
            seeded: 0,
        };
        for pos in 0..history.len().saturating_sub(3) {
            let origin = start + pos as u64;
            chain.insert(
                origin,
                hash(history[pos..pos + 4].try_into().expect("four-byte origin")),
            );
        }
        #[cfg(test)]
        {
            chain.seeded = history.len().saturating_sub(3) as u64;
        }
        chain.indexed_until = stream_offset.saturating_sub(3).max(start);
        chain.set_tail(history);
        Ok(chain)
    }

    #[cfg(test)]
    pub(crate) fn seeded_positions(&self) -> u64 {
        self.seeded
    }

    fn insert(&mut self, origin: u64, bucket: usize) {
        let head = self.heads[bucket];
        let distance = origin
            .checked_sub(head)
            .filter(|&distance| distance != 0 && distance <= self.dictionary as u64)
            .unwrap_or(0);
        self.previous[origin as usize & self.mask] = distance as u32;
        self.heads[bucket] = origin;
    }

    fn older(&self, origin: u64) -> u64 {
        if origin >= self.indexed_until || origin < self.end.saturating_sub(self.dictionary as u64)
        {
            return ABSENT;
        }
        let distance = self.previous[origin as usize & self.mask] as u64;
        if distance == 0 {
            ABSENT
        } else {
            origin.checked_sub(distance).unwrap_or(ABSENT)
        }
    }

    fn set_tail(&mut self, bytes: &[u8]) {
        self.tail_len = bytes.len().min(3);
        self.tail[..self.tail_len].copy_from_slice(&bytes[bytes.len() - self.tail_len..]);
    }

    fn validate_tail(&self, combined: &[u8], start: u64) -> Result<()> {
        let tail_start = self.end - self.tail_len as u64;
        let end = start
            .checked_add(combined.len() as u64)
            .ok_or(Error::InvalidData("hybrid chain combined offset overflows"))?;
        for at in 0..self.tail_len {
            let absolute = tail_start + at as u64;
            if absolute >= start
                && absolute < end
                && combined[(absolute - start) as usize] != self.tail[at]
            {
                return Err(Error::InvalidData("hybrid chain history domain changed"));
            }
        }
        Ok(())
    }

    /// The caller owns the actual transformed history generation. Validate all
    /// fallible bounds before touching heads/ring slots; then commit cannot fail
    /// after partly advancing history and performs no allocation or I/O.
    pub(crate) fn commit(
        &mut self,
        history: &[u8],
        append: &[u8],
        stream_offset: u64,
    ) -> Result<()> {
        if stream_offset != self.end || history.len() > self.dictionary {
            return Err(Error::InvalidData(
                "hybrid chain commit starts from another state",
            ));
        }
        let start = stream_offset
            .checked_sub(history.len() as u64)
            .ok_or(Error::InvalidData("hybrid chain history offset underflows"))?;
        let end = stream_offset
            .checked_add(append.len() as u64)
            .ok_or(Error::InvalidData("hybrid chain commit offset overflows"))?;
        self.validate_tail(history, start)?;
        let until = end.saturating_sub(3).max(start);
        let first = self.indexed_until.max(start);
        let byte = |absolute: u64| {
            if absolute < stream_offset {
                history[(absolute - start) as usize]
            } else {
                append[(absolute - stream_offset) as usize]
            }
        };
        let mut tail = [0u8; 3];
        let tail_len = (end - start).min(3) as usize;
        for (at, out) in tail[..tail_len].iter_mut().enumerate() {
            *out = byte(end - tail_len as u64 + at as u64);
        }
        for origin in first..until {
            self.insert(
                origin,
                hash([
                    byte(origin),
                    byte(origin + 1),
                    byte(origin + 2),
                    byte(origin + 3),
                ]),
            );
        }
        self.indexed_until = until;
        self.end = end;
        self.tail = tail;
        self.tail_len = tail_len;
        Ok(())
    }
}

/// Predecessors are captured while each origin is inserted in ascending order.
/// Querying a fully built overlay never uses its final (future-containing) heads.
#[derive(Debug)]
pub(crate) struct Overlay<'a, B: Budget = Allowance> {
    base: &'a CommittedChain<B>,
    previous: Buffer<u64, B>,
    first: u64,
    start: u64,
    end: u64,
}
impl<'a, B: Budget> Overlay<'a, B> {
    pub(crate) fn new(
        base: &'a CommittedChain<B>,
        combined: &[u8],
        stream_offset: u64,
        history_len: usize,
        allowance: &B,
    ) -> Result<Self> {
        if history_len > combined.len() || history_len > base.dictionary || stream_offset < base.end
        {
            return Err(Error::InvalidData(
                "hybrid chain overlay starts from another state",
            ));
        }
        let start = stream_offset
            .checked_sub(history_len as u64)
            .ok_or(Error::InvalidData("hybrid chain overlay offset underflows"))?;
        let end = start
            .checked_add(combined.len() as u64)
            .ok_or(Error::InvalidData("hybrid chain overlay offset overflows"))?;
        base.validate_tail(combined, start)?;
        let first = base.indexed_until.max(start);
        let until = end.saturating_sub(3).max(start);
        let length = usize::try_from(until.saturating_sub(first))
            .map_err(|_| Error::InvalidData("hybrid chain overlay length overflows"))?;
        let mut heads = Buffer::copied(&base.heads, allowance)?;
        let mut previous = Buffer::with_capacity(length, allowance)?;
        for origin in first..until {
            let at = (origin - start) as usize;
            let bucket = hash(combined[at..at + 4].try_into().expect("four-byte origin"));
            let head = heads[bucket];
            let valid = head >= start && head < origin && origin - head <= base.dictionary as u64;
            previous.push_admitted(if valid { head } else { ABSENT });
            heads[bucket] = origin;
        }
        Ok(Self {
            base,
            previous,
            first,
            start,
            end,
        })
    }

    pub(crate) fn inserted_positions(&self) -> u64 {
        self.previous.len() as u64
    }

    fn older(&self, origin: u64) -> u64 {
        if origin >= self.first {
            self.previous
                .get((origin - self.first) as usize)
                .copied()
                .unwrap_or(ABSENT)
        } else {
            self.base.older(origin)
        }
    }
    fn local(&self, absolute: u64, origin: u64) -> usize {
        if absolute >= self.start
            && absolute < origin
            && origin - absolute <= self.base.dictionary as u64
        {
            (absolute - self.start) as usize
        } else {
            match_finder::NO_POSITION
        }
    }
    pub(crate) fn first(&self, origin: usize) -> usize {
        let Some(absolute) = self.start.checked_add(origin as u64) else {
            return match_finder::NO_POSITION;
        };
        if absolute >= self.end {
            return match_finder::NO_POSITION;
        }
        self.local(self.older(absolute), absolute)
    }
    pub(crate) fn previous(&self, candidate: usize) -> usize {
        self.first(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_overlay(overlay: &Overlay<'_>, combined: &[u8], start: usize, dictionary: usize) {
        let mut finder = Rar50MatchFinder::new(dictionary);
        for at in 0..start {
            finder.insert(combined, at);
        }
        for origin in start..combined.len().saturating_sub(3) {
            let mut expected = finder.first(combined, origin);
            let mut actual = overlay.first(origin);
            loop {
                if expected != match_finder::NO_POSITION && origin - expected > dictionary {
                    expected = match_finder::NO_POSITION;
                }
                if actual != match_finder::NO_POSITION && origin - actual > dictionary {
                    actual = match_finder::NO_POSITION;
                }
                assert_eq!(actual, expected, "origin={origin} dictionary={dictionary}");
                if expected == match_finder::NO_POSITION {
                    break;
                }
                assert!(actual < origin);
                actual = overlay.previous(actual);
                expected = finder.previous(expected);
            }
            finder.insert(combined, origin);
        }
    }

    fn data(len: usize) -> Vec<u8> {
        (0..len)
            .map(|at| b'a' + ((at * 17 + at / 11) % 7) as u8)
            .collect()
    }

    #[test]
    fn prebuilt_overlay_matches_fresh_sequential_chains_without_future_heads() {
        let allowance = Allowance::default();
        let bytes = data(1300);
        for dictionary in [1, 2, 3, 8, 31, 64, 511] {
            for history_len in [0, 1, 2, 3, 7, 31] {
                if history_len > dictionary {
                    continue;
                }
                let history = &bytes[..history_len];
                let base = CommittedChain::new_from_history(
                    history,
                    dictionary,
                    history_len as u64,
                    &allowance,
                )
                .unwrap();
                let overlay = Overlay::new(
                    &base,
                    &bytes[..history_len + 197],
                    history_len as u64,
                    history_len,
                    &allowance,
                )
                .unwrap();
                assert_overlay(
                    &overlay,
                    &bytes[..history_len + 197],
                    history_len,
                    dictionary,
                );
                assert!(overlay.inserted_positions() <= 197 + 3);
            }
        }
    }

    #[test]
    fn rolling_commits_match_fresh_dictionary_chain_and_seed_history_once() {
        let allowance = Allowance::default();
        let bytes = data(4000);
        for dictionary in [8, 32, 257] {
            let mut base =
                CommittedChain::new_from_history(&bytes[..7], dictionary, 7, &allowance).unwrap();
            assert_eq!(base.seeded_positions(), 4);
            let mut offset: usize = 7;
            for length in [1, 2, 3, 17, 67, 500, 3, 600, 701] {
                let history = &bytes[offset.saturating_sub(dictionary)..offset];
                let append = &bytes[offset..offset + length];
                let combined = [history, append].concat();
                {
                    let overlay =
                        Overlay::new(&base, &combined, offset as u64, history.len(), &allowance)
                            .unwrap();
                    assert_overlay(&overlay, &combined, history.len(), dictionary);
                }
                base.commit(history, append, offset as u64).unwrap();
                offset += length;
                assert_eq!(base.end, offset as u64);
                assert_eq!(base.seeded_positions(), 4);
            }
        }
    }

    #[test]
    fn unchosen_overlay_and_lookahead_do_not_contaminate_committed_join_tail() {
        let allowance = Allowance::default();
        let history = b"prefix-ABCD-ABC";
        let dictionary = 128;
        let mut base =
            CommittedChain::new_from_history(history, dictionary, history.len() as u64, &allowance)
                .unwrap();
        let original_heads = base.heads.to_vec();
        let original_previous = base.previous.to_vec();
        let original_until = base.indexed_until;
        let wrong = [history.as_slice(), b"XABCD-ABCXABCD"].concat();
        let unchosen = Overlay::new(
            &base,
            &wrong,
            history.len() as u64,
            history.len(),
            &allowance,
        )
        .unwrap();
        assert_eq!(&*base.heads, original_heads);
        assert_eq!(&*base.previous, original_previous);
        assert_eq!(base.indexed_until, original_until);
        drop(unchosen);
        let selected = b"D-ABCD-ABCD";
        let current = [history.as_slice(), selected].concat();
        let future = [current.as_slice(), b"-ABCD-ABCD"].concat();
        let lookahead = Overlay::new(
            &base,
            &future,
            current.len() as u64,
            current.len(),
            &allowance,
        )
        .unwrap();
        assert_overlay(&lookahead, &future, current.len(), dictionary);
        drop(lookahead);
        base.commit(history, selected, history.len() as u64)
            .unwrap();
        let next = [current.as_slice(), b"Y-ABCY-ABC"].concat();
        let actual = Overlay::new(
            &base,
            &next,
            current.len() as u64,
            current.len(),
            &allowance,
        )
        .unwrap();
        assert_overlay(&actual, &next, current.len(), dictionary);
    }

    #[test]
    fn lookahead_can_skip_unreachable_prefix_without_inserting_missing_history() {
        let allowance = Allowance::default();
        let dictionary = 16;
        let bytes = data(200);
        let base =
            CommittedChain::new_from_history(&bytes[..16], dictionary, 16, &allowance).unwrap();
        let stream_offset = 140;
        let history = &bytes[stream_offset - dictionary..stream_offset];
        let combined = [history, &bytes[stream_offset..]].concat();
        let overlay = Overlay::new(
            &base,
            &combined,
            stream_offset as u64,
            history.len(),
            &allowance,
        )
        .unwrap();
        assert_overlay(&overlay, &combined, history.len(), dictionary);
    }

    #[test]
    fn join_hash_uses_selected_next_bytes_and_trailing_origins_remain_deferred() {
        let allowance = Allowance::default();
        let history = b"ABCDABCDABC";
        let base = CommittedChain::new_from_history(history, 64, history.len() as u64, &allowance)
            .unwrap();
        let matching = [history.as_slice(), b"DABCD"].concat();
        let changed = [history.as_slice(), b"XABCD"].concat();
        let first = Overlay::new(
            &base,
            &matching,
            history.len() as u64,
            history.len(),
            &allowance,
        )
        .unwrap();
        let second = Overlay::new(
            &base,
            &changed,
            history.len() as u64,
            history.len(),
            &allowance,
        )
        .unwrap();
        assert_overlay(&first, &matching, history.len(), 64);
        assert_overlay(&second, &changed, history.len(), 64);
        assert_eq!(base.indexed_until, (history.len() - 3) as u64);
        for pos in matching.len() - 3..matching.len() {
            assert_eq!(first.first(pos), match_finder::NO_POSITION);
        }
    }

    #[test]
    fn admission_and_invalid_commit_leave_no_live_allocations_or_partial_state() {
        let allowance = Allowance::limited(1024);
        assert!(CommittedChain::new_from_history(b"abc", 64, 3, &allowance).is_err());
        assert_eq!(allowance.used(), 0);
        let allowance = Allowance::default();
        let mut base = CommittedChain::new_from_history(b"abcdefgh", 64, 8, &allowance).unwrap();
        let original_heads = base.heads.to_vec();
        let original_previous = base.previous.to_vec();
        assert!(base.commit(b"abcdefgX", b"next", 8).is_err());
        assert!(base.commit(b"abcdefgh", b"next", 9).is_err());
        assert_eq!(&*base.heads, original_heads);
        assert_eq!(&*base.previous, original_previous);
        assert_eq!(base.end, 8);
        let mut at_end =
            CommittedChain::new_from_history(b"abcdefgh", 64, u64::MAX - 1, &allowance).unwrap();
        assert!(at_end.commit(b"abcdefgh", b"xy", u64::MAX - 1).is_err());
        assert_eq!(at_end.end, u64::MAX - 1);
    }
}
