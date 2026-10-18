//! Opt-in, bounded decision windows. Speculation never mutates committed state.
use super::*;
use crate::read_control::ReadControl;
#[path = "hybrid_chain.rs"]
mod hybrid_chain;
pub(crate) use hybrid_chain::CommittedChain;
use hybrid_chain::Overlay;

pub(crate) const HYBRID_WINDOW: usize = 256 * 1024;
const FILTER_UNIT: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
pub(crate) struct HybridCodecOptions {
    pub beam_width: usize,
    pub finalists: usize,
    pub full_partitions: bool,
    pub deeper_search: bool,
    pub auto_filters: bool,
    pub max_match_candidates: usize,
    pub max_endpoints_per_run: usize,
    pub pricing_passes: usize,
}
impl Default for HybridCodecOptions {
    fn default() -> Self {
        Self {
            beam_width: 2,
            finalists: 2,
            full_partitions: true,
            deeper_search: true,
            auto_filters: false,
            max_match_candidates: 64,
            max_endpoints_per_run: 16,
            pricing_passes: 2,
        }
    }
}

/// The byte domain is owned, not authorized by a collision-prone fingerprint.
#[derive(Debug)]
pub(crate) struct HybridCodecState<B: Budget = Allowance> {
    history: Buffer<u8, B>,
    pub dictionary_size: usize,
    pub algorithm_version: u8,
    pub stream_offset: u64,
    pub member_offset: u64,
    pub reps: [usize; 4],
    pub last_length: usize,
}
impl<B: Budget> HybridCodecState<B> {
    pub(crate) fn new(
        history: &[u8],
        dictionary_size: usize,
        algorithm_version: u8,
        allowance: &B,
    ) -> Result<Self> {
        distance_size(algorithm_version)?;
        if dictionary_size == 0 || dictionary_size > u32::MAX as usize {
            return Err(Error::InvalidData("hybrid dictionary is zero"));
        }
        Ok(Self {
            history: Buffer::copied(
                &history[history.len().saturating_sub(dictionary_size)..],
                allowance,
            )?,
            dictionary_size,
            algorithm_version,
            stream_offset: history.len() as u64,
            member_offset: 0,
            reps: [0; 4],
            last_length: 0,
        })
    }
    pub(crate) fn history(&self) -> &[u8] {
        &self.history
    }
    pub(crate) fn begin_member(&mut self) {
        self.member_offset = 0;
    }
    fn matches(&self) -> EncoderMatchState {
        EncoderMatchState {
            reps: self.reps,
            last_length: self.last_length,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HybridWork {
    pub screened: u64,
    pub finalists: u64,
    pub cache_builds: u64,
    pub price_passes: u64,
    pub endpoint_prices: u64,
    pub lookahead_bytes: u64,
    pub blocks: u64,
    pub collector_searches: u64,
    pub greedy_searches: u64,
    pub chain_candidates: u64,
    pub seeded_positions: u64,
    pub truncated_caches: u64,
    pub compared_bytes: u64,
    pub hint_matches: u64,
    pub overlay_positions: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MatchCacheQuality {
    pub block_start: usize,
    pub block_end: usize,
    pub dictionary_size: usize,
    pub max_visits: usize,
    pub nice_threshold: usize,
    pub seeded_chain: bool,
    /// NICE-covered origins are absent, not certified match-free.
    pub every_position: bool,
    pub run_cap: usize,
    pub truncated: bool,
    pub nearest_prefix_then_longest: bool,
}
#[derive(Debug)]
pub(crate) struct HybridPartition<B: Budget = Allowance> {
    pub bytes: Buffer<u8, B>,
    pub end_state: HybridCodecState<B>,
    pub history_append: Buffer<u8, B>,
    pub work: HybridWork,
    pub partition_id: usize,
    pub representation_id: usize,
    pub next_cost: usize,
    pub cache_quality: Buffer<MatchCacheQuality, B>,
}

fn check(control: &ReadControl, cancelled: &dyn Fn() -> bool) -> Result<()> {
    if cancelled() {
        return Err(Error::Cancelled);
    }
    control.check_codec()
}
/// A hint is evidence in source coordinates projected by the writer into this
/// decision's actual stream. The codec always verifies the actual byte domain.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HybridMatchHint {
    pub offset: usize,
    pub distance: usize,
    pub maxlen: usize,
}

#[derive(Clone, Copy, Debug)]
struct EqualInterval {
    distance: usize,
    start: usize,
    end: usize,
    mismatch: bool,
}
impl EqualInterval {
    const EMPTY: Self = Self {
        distance: 0,
        start: 0,
        end: 0,
        mismatch: false,
    };
}

/// Exact equality evidence belongs to one immutable combined byte allocation.
/// It is deliberately not transferable by filter kind or a content hash. A
/// collision/eviction only causes recomparison; it cannot remove match edges.
struct EqualityCache<B: Budget> {
    intervals: Buffer<EqualInterval, B>,
    compared: u64,
}
impl<B: Budget> EqualityCache<B> {
    fn new(allowance: &B) -> Result<Self> {
        Ok(Self {
            intervals: Buffer::filled(8192, EqualInterval::EMPTY, allowance)?,
            compared: 0,
        })
    }
    fn length(&mut self, bytes: &[u8], pos: usize, distance: usize, limit: usize) -> usize {
        if distance == 0 || distance > pos || pos >= bytes.len() {
            return 0;
        }
        let limit = limit.min(bytes.len() - pos).min(MAX_ENCODER_MATCH_LENGTH);
        let slot = distance.wrapping_mul(0x9e37_79b1) & (self.intervals.len() - 1);
        let old = self.intervals[slot];
        let mut length = 0;
        let mut start = pos;
        if old.distance == distance && pos >= old.start && pos <= old.end {
            length = (old.end - pos).min(limit);
            start = old.start;
            if length == limit || old.mismatch {
                return length;
            }
        }
        let mut mismatch = false;
        while length < limit {
            self.compared += 1;
            if bytes[pos + length] != bytes[pos + length - distance] {
                mismatch = true;
                break;
            }
            length += 1;
        }
        self.intervals[slot] = EqualInterval {
            distance,
            start,
            end: pos + length,
            mismatch,
        };
        length
    }
}

/// A tape is collected at every origin once. Partitions only clip its lengths;
/// parsing states/repricing never change this representation's byte evidence.
struct SharedEvidence<B: Budget> {
    combined: Buffer<u8, B>,
    start: usize,
    matches: BlockMatches<B>,
    equality: EqualityCache<B>,
    quality: MatchCacheQuality,
}
#[allow(clippy::too_many_arguments)]
fn shared_evidence_with_chain<B: Budget>(
    history: &[u8],
    domain: &Domain<B>,
    dictionary: usize,
    chain: &CommittedChain<B>,
    stream_offset: u64,
    config: HybridCodecOptions,
    hints: &[HybridMatchHint],
    allowance: &B,
    control: &ReadControl,
    cancelled: &dyn Fn() -> bool,
    work: &mut HybridWork,
) -> Result<SharedEvidence<B>> {
    let combined = Buffer::from_slices(&[history, &domain.bytes], allowance)?;
    let start = history.len();
    let visits = if config.deeper_search {
        config.max_match_candidates
    } else {
        config.max_match_candidates.min(16)
    };
    let cap = if config.finalists == 4 { 64 } else { 16 };
    let overlay = Overlay::new(chain, &combined, stream_offset, start, allowance)?;
    work.overlay_positions += overlay.inserted_positions();
    let mut equality = EqualityCache::new(allowance)?;
    let span = domain.bytes.len();
    let mut matches = BlockMatches {
        runs: Buffer::with_capacity(
            span.checked_mul(cap)
                .and_then(|bytes| {
                    bytes.checked_add(if span == 0 { 0 } else { visits + hints.len() })
                })
                .ok_or(Error::InvalidData("hybrid tape capacity overflows"))?,
            allowance,
        )?,
        starts: Buffer::with_capacity(span + 1, allowance)?,
    };
    let mut hints = Buffer::copied(hints, allowance)?;
    hints.sort_unstable_by_key(|hint| (hint.offset, hint.distance, hint.maxlen));
    let mut hint_cursor = 0;
    let mut truncated = false;
    for pos in start..combined.len() {
        if pos.is_multiple_of(64) {
            check(control, cancelled)?;
        }
        matches.starts.push_admitted(matches.runs.len() as u32);
        let before = matches.runs.len();
        let max_length = (combined.len() - pos).min(MAX_ENCODER_MATCH_LENGTH);
        let max_distance = pos.min(dictionary);
        let mut longest = 0;
        if visits != 0 && max_length >= 4 && max_distance != 0 {
            work.collector_searches += 1;
            let mut candidate = overlay.first(pos);
            let mut checked = 0;
            while candidate != match_finder::NO_POSITION {
                debug_assert!(candidate < pos);
                let distance = pos - candidate;
                if distance > max_distance {
                    break;
                }
                checked += 1;
                work.chain_candidates += 1;
                let length = equality.length(&combined, pos, distance, max_length);
                if length > longest && length >= 4 {
                    matches
                        .runs
                        .push((length as u32, distance as u32))
                        .map_err(Into::into)?;
                    longest = length;
                }
                if checked >= visits || longest >= NICE_MATCH_LENGTH || longest == max_length {
                    break;
                }
                candidate = overlay.previous(candidate);
            }
        }
        while hint_cursor < hints.len() && hints[hint_cursor].offset < pos - start {
            hint_cursor += 1;
        }
        while hint_cursor < hints.len() && hints[hint_cursor].offset == pos - start {
            let hint = hints[hint_cursor];
            hint_cursor += 1;
            if visits != 0 && hint.distance != 0 && hint.distance <= max_distance {
                let length =
                    equality.length(&combined, pos, hint.distance, max_length.min(hint.maxlen));
                if length >= 4 {
                    matches
                        .runs
                        .push((length as u32, hint.distance as u32))
                        .map_err(Into::into)?;
                    work.hint_matches += 1;
                }
            }
        }
        // Hints can be nearer than chain results. Rebuild the nearest-first
        // envelope explicitly; equality evidence, not heuristic provenance,
        // authorizes every retained run.
        matches.runs[before..]
            .sort_unstable_by_key(|&(length, distance)| (distance, std::cmp::Reverse(length)));
        let mut out = before;
        let mut reach = 3;
        for at in before..matches.runs.len() {
            let run = matches.runs[at];
            if run.0 > reach {
                reach = run.0;
                matches.runs[out] = run;
                out += 1;
            }
        }
        matches.runs.truncate(out);
        if out - before > cap {
            let last = matches.runs[out - 1];
            matches.runs.truncate(before + cap - 1);
            matches.runs.push(last).map_err(Into::into)?;
            truncated = true;
        }
        // The immutable overlay stores each origin's predecessor, never its
        // final hash head, so future positions cannot enter this chain.
    }
    matches.starts.push_admitted(matches.runs.len() as u32);
    work.cache_builds += 1;
    work.truncated_caches += u64::from(truncated);
    Ok(SharedEvidence {
        combined,
        start,
        matches,
        equality,
        quality: MatchCacheQuality {
            block_start: start,
            block_end: start + span,
            dictionary_size: dictionary,
            max_visits: visits,
            nice_threshold: NICE_MATCH_LENGTH,
            seeded_chain: true,
            every_position: true,
            run_cap: cap,
            truncated,
            nearest_prefix_then_longest: true,
        },
    })
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn shared_evidence<B: Budget>(
    history: &[u8],
    domain: &Domain<B>,
    dictionary: usize,
    config: HybridCodecOptions,
    hints: &[HybridMatchHint],
    allowance: &B,
    control: &ReadControl,
    cancelled: &dyn Fn() -> bool,
    work: &mut HybridWork,
) -> Result<SharedEvidence<B>> {
    let chain =
        CommittedChain::new_from_history(history, dictionary, history.len() as u64, allowance)?;
    work.seeded_positions += chain.seeded_positions();
    shared_evidence_with_chain(
        history,
        domain,
        dictionary,
        &chain,
        history.len() as u64,
        config,
        hints,
        allowance,
        control,
        cancelled,
        work,
    )
}

fn distance_size(version: u8) -> Result<usize> {
    match version {
        0 => Ok(DISTANCE_TABLE_SIZE_50),
        1 => Ok(DISTANCE_TABLE_SIZE_70),
        _ => Err(Error::InvalidData(
            "RAR 5 unknown compression algorithm version",
        )),
    }
}
fn validate(config: HybridCodecOptions) -> Result<()> {
    if !matches!(config.beam_width, 1 | 2 | 8)
        || !matches!(config.finalists, 1 | 2 | 4)
        || !(1..=16).contains(&config.max_endpoints_per_run)
        || !(1..=3).contains(&config.pricing_passes)
        || config.max_match_candidates > 1024
    {
        return Err(Error::InvalidData("invalid hybrid codec options"));
    }
    Ok(())
}

/// Partition IDs are stable: 256;128+128;64x4;192+64 (server only).
fn boundaries(length: usize, id: usize) -> ([usize; 4], usize) {
    let nominal: &[usize] = match id {
        0 => &[HYBRID_WINDOW],
        1 => &[128 * 1024, HYBRID_WINDOW],
        2 => &[64 * 1024, 128 * 1024, 192 * 1024, HYBRID_WINDOW],
        _ => &[192 * 1024, HYBRID_WINDOW],
    };
    let mut out = [0; 4];
    let mut count = 0;
    for &end in nominal {
        let end = end.min(length);
        if count == 0 || out[count - 1] != end {
            out[count] = end;
            count += 1;
        }
        if end == length {
            break;
        }
    }
    (out, count)
}
fn representation(id: usize) -> Option<crate::FilterKind> {
    match id {
        0 => None,
        1 => Some(crate::FilterKind::E8E9),
        2 => Some(crate::FilterKind::Arm),
        3 => Some(crate::FilterKind::Delta { channels: 1 }),
        4 => Some(crate::FilterKind::Delta { channels: 2 }),
        _ => Some(crate::FilterKind::Delta { channels: 4 }),
    }
}

struct Domain<B: Budget> {
    bytes: Buffer<u8, B>,
    records: Buffer<EncodeFilter, B>,
}
fn make_domain<B: Budget>(
    input: &[u8],
    member_offset: u64,
    mandatory: &[crate::FilterSpec],
    auto: Option<crate::FilterKind>,
    allowance: &B,
    control: &ReadControl,
    cancelled: &dyn Fn() -> bool,
) -> Result<Domain<B>> {
    check(control, cancelled)?;
    let mut bytes = Buffer::copied(input, allowance)?;
    let mut records = Buffer::new(allowance);
    if member_offset > usize::MAX as u64 {
        return Err(Error::InvalidData("hybrid member offset overflows"));
    }
    let base = member_offset as usize;
    let limit = base
        .checked_add(input.len())
        .ok_or(Error::InvalidData("hybrid member range overflows"))?;
    let apply = |spec: &crate::FilterSpec,
                 bytes: &mut Buffer<u8, B>,
                 records: &mut Buffer<EncodeFilter, B>|
     -> Result<()> {
        let kind = rar50_filter(spec.kind)?;
        let absolute = spec.range.clone().unwrap_or(base..limit);
        if absolute.start >= absolute.end {
            return Err(Error::InvalidData("RAR 5 filter range is invalid"));
        }
        for unit in (0..input.len()).step_by(FILTER_UNIT) {
            check(control, cancelled)?;
            let lo = absolute.start.max(base + unit);
            let hi = absolute
                .end
                .min(base + (unit + FILTER_UNIT).min(input.len()));
            if lo >= hi {
                continue;
            }
            let (filter_type, channels) =
                encode_filter_data(kind, &mut bytes[lo - base..hi - base], lo, allowance)?;
            records
                .push(EncodeFilter {
                    offset: lo - base,
                    length: hi - lo,
                    filter_type,
                    channels,
                })
                .map_err(Into::into)?;
        }
        Ok(())
    };
    if let Some(kind) = auto {
        apply(&crate::FilterSpec::whole(kind), &mut bytes, &mut records)?;
    }
    // The decoder executes announced filters in order. Compose their inverse
    // transforms in reverse order while preserving the original commands.
    for spec in mandatory.iter().rev() {
        let mut current_records = Buffer::new(allowance);
        apply(spec, &mut bytes, &mut current_records)?;
        records.prepend(current_records.iter().copied())?;
    }
    Ok(Domain { bytes, records })
}

fn history_after<B: Budget>(
    history: &[u8],
    append: &[u8],
    dictionary: usize,
    allowance: &B,
) -> Result<Buffer<u8, B>> {
    let incoming = &append[append.len().saturating_sub(dictionary)..];
    let keep = history.len().min(dictionary - incoming.len());
    Buffer::from_slices(&[&history[history.len() - keep..], incoming], allowance)
}

#[derive(Clone, Copy, Debug)]
struct Node {
    price: u32,
    previous: u32,
    length: u32,
    distance: u32,
    reps: [u32; 4],
    last: u32,
}
impl Node {
    const EMPTY: Self = Self {
        price: u32::MAX,
        previous: 0,
        length: 0,
        distance: 0,
        reps: [0; 4],
        last: 0,
    };
    fn state(self) -> EncoderMatchState {
        EncoderMatchState {
            reps: self.reps.map(|x| x as usize),
            last_length: self.last as usize,
        }
    }
}
/// Conservative admission for all live stream allocations, independent of
/// allocator spare capacity or worker concurrency. Tape/token allocations have
/// exact preadmitted capacities; rejected plans cannot trigger hidden doubling.
pub(crate) fn hybrid_workspace_required(dictionary: u64, config: HybridCodecOptions) -> u64 {
    let ring = dictionary
        .checked_next_power_of_two()
        .and_then(|bytes| bytes.checked_mul(4));
    let cap = if config.finalists == 4 { 64u64 } else { 16u64 };
    let per_window = cap * std::mem::size_of::<(u32, u32)>() as u64
        + std::mem::size_of::<u32>() as u64
        + (config.beam_width as u64) * std::mem::size_of::<Node>() as u64
        + (config.finalists as u64 + 2) * std::mem::size_of::<EncodeToken>() as u64
        + config.finalists as u64 + 5 // input/lookahead/domains/retained append
        + 16 // largest current+lookahead immutable overlay links
        + 6; // complete winning output, payload and packed-block overlap
    ring.and_then(|ring| {
        dictionary
            .checked_mul(4)
            .and_then(|bytes| ring.checked_add(bytes))
    })
    .and_then(|bytes| {
        per_window
            .checked_mul(HYBRID_WINDOW as u64)
            .and_then(|stream| bytes.checked_add(stream))
    })
    // Hash heads, equality cache, capped hint/collector scratch, all small
    // block-table/filter/quality metadata and fixed allocator rounding.
    .and_then(|bytes| bytes.checked_add(4 * 1024 * 1024))
    .unwrap_or(u64::MAX)
}

fn offer(nodes: &mut [Node], width: usize, target: usize, candidate: Node) {
    let slots = &mut nodes[target * width..(target + 1) * width];
    if let Some(at) = slots.iter().position(|old| {
        old.price != u32::MAX && old.reps == candidate.reps && old.last == candidate.last
    }) {
        if candidate.price >= slots[at].price {
            return;
        }
        slots[at] = candidate;
    } else {
        if candidate.price >= slots[width - 1].price {
            return;
        }
        slots[width - 1] = candidate;
    }
    // Stable insertion order is the deterministic tie rule.
    for at in (1..width).rev() {
        if slots[at].price < slots[at - 1].price {
            slots.swap(at, at - 1);
        }
    }
}
fn endpoints(start: usize, end: usize, last: usize, limit: usize) -> ([usize; 16], usize) {
    let mut out = [0; 16];
    let mut count = 0;
    // The full reach and an exact last-length token always get a chance.
    for length in [
        end, last, 4, 5, 6, 7, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096,
    ] {
        if length >= start && length <= end && !out[..count].contains(&length) && count < limit {
            out[count] = length;
            count += 1;
        }
    }
    out[..count].sort_unstable();
    (out, count)
}

#[allow(clippy::too_many_arguments)]
fn beam_tokens<B: Budget>(
    combined: &[u8],
    block: Range<usize>,
    matches: &BlockMatches<B>,
    match_start: usize,
    equality: &mut EqualityCache<B>,
    initial: EncoderMatchState,
    config: HybridCodecOptions,
    size: usize,
    prices: Option<&TokenPrices<'_>>,
    allowance: &B,
    control: &ReadControl,
    cancelled: &dyn Fn() -> bool,
    work: &mut HybridWork,
) -> Result<Buffer<EncodeToken, B>> {
    let span = block.len();
    let width = config.beam_width;
    let count = (span + 1)
        .checked_mul(width)
        .ok_or(Error::InvalidData("hybrid beam size overflows"))?;
    let mut nodes = Buffer::filled(count, Node::EMPTY, allowance)?;
    nodes[0] = Node {
        price: 0,
        reps: initial.reps.map(|x| x as u32),
        last: initial.last_length as u32,
        ..Node::EMPTY
    };
    let match_prices = OptimalMatchPrices::new(prices);
    for pos in 0..span {
        if pos % 1024 == 0 {
            check(control, cancelled)?;
        }
        for lane in 0..width {
            let index = pos * width + lane;
            let origin = nodes[index];
            if origin.price == u32::MAX {
                continue;
            }
            let state = origin.state();
            let literal = prices.map_or(ESTIMATED_LITERAL_COST, |p| {
                p.literal(combined[block.start + pos]) as u32
            });
            offer(
                &mut nodes,
                width,
                pos + 1,
                Node {
                    price: origin.price.saturating_add(literal),
                    previous: index as u32,
                    length: 0,
                    distance: 0,
                    ..origin
                },
            );
            if config.max_match_candidates == 0 {
                continue;
            }
            let at = block.start + pos;
            let max = (span - pos).min(MAX_ENCODER_MATCH_LENGTH);
            let mut price_run =
                |run_start: usize, run_end: usize, distance: usize, nodes: &mut [Node]| {
                    let (lengths, n) = endpoints(
                        run_start.max(4),
                        run_end,
                        state.last_length,
                        config.max_endpoints_per_run,
                    );
                    let Ok(run_price) = match_prices.run(&state, distance, size, prices) else {
                        return;
                    };
                    for &length in &lengths[..n] {
                        work.endpoint_prices += 1;
                        if let Some(cost) = run_price.cost(length) {
                            let mut next = state;
                            next.remember(length, distance);
                            offer(
                                nodes,
                                width,
                                pos + length,
                                Node {
                                    price: origin.price.saturating_add(cost),
                                    previous: index as u32,
                                    length: length as u32,
                                    distance: distance as u32,
                                    reps: next.reps.map(|x| x as u32),
                                    last: next.last_length as u32,
                                },
                            );
                        }
                    }
                };
            for distance in state.reps {
                if distance > 0 && distance <= at && distance <= combined.len() {
                    let len = equality.length(combined, at, distance, max);
                    if len >= 4 {
                        price_run(4, len, distance, &mut nodes);
                    }
                }
            }
            let mut longest = 0;
            let tape_pos = block.start - match_start + pos;
            for &(length, distance) in &matches.runs
                [matches.starts[tape_pos] as usize..matches.starts[tape_pos + 1] as usize]
            {
                let length = (length as usize).min(max);
                if length > longest {
                    price_run(longest + 1, length, distance as usize, &mut nodes);
                    longest = length;
                }
            }
        }
    }
    let mut out = Buffer::with_capacity(span, allowance)?;
    let mut at = span * width;
    if nodes[at].price == u32::MAX {
        return Err(Error::InvalidData("hybrid beam has no complete path"));
    }
    while at != 0 {
        let node = nodes[at];
        let target = at / width;
        let token = if node.length == 0 {
            EncodeToken::Literal(combined[block.start + target - 1])
        } else {
            EncodeToken::Match {
                length: node.length as usize,
                distance: node.distance as usize,
            }
        };
        out.push(token).map_err(Into::into)?;
        at = node.previous as usize;
    }
    out.reverse();
    Ok(out)
}
#[allow(clippy::too_many_arguments)]
fn greedy_tokens<B: Budget>(
    evidence: &mut SharedEvidence<B>,
    block: Range<usize>,
    initial: EncoderMatchState,
    enabled: bool,
    size: usize,
    allowance: &B,
    control: &ReadControl,
    cancelled: &dyn Fn() -> bool,
    work: &mut HybridWork,
) -> Result<Buffer<EncodeToken, B>> {
    let mut tokens = Buffer::with_capacity(block.len(), allowance)?;
    let mut state = initial;
    let mut pos = block.start;
    while pos < block.end {
        if pos.is_multiple_of(64) {
            check(control, cancelled)?;
        }
        work.greedy_searches += 1;
        let max = (block.end - pos).min(MAX_ENCODER_MATCH_LENGTH);
        let mut best = None;
        if enabled && max >= 4 {
            for distance in state.reps {
                if distance > 0 && distance <= pos && distance <= evidence.quality.dictionary_size {
                    let length = evidence
                        .equality
                        .length(&evidence.combined, pos, distance, max);
                    consider_match_candidate(&mut best, &state, size, length, distance);
                }
            }
            let offset = pos - evidence.start;
            for &(length, distance) in &evidence.matches.runs[evidence.matches.starts[offset]
                as usize
                ..evidence.matches.starts[offset + 1] as usize]
            {
                consider_match_candidate(
                    &mut best,
                    &state,
                    size,
                    (length as usize).min(max),
                    distance as usize,
                );
            }
        }
        if let Some(found) = best {
            tokens
                .push(EncodeToken::Match {
                    length: found.length,
                    distance: found.distance,
                })
                .map_err(Into::into)?;
            state.remember(found.length, found.distance);
            pos += found.length;
        } else {
            tokens
                .push(EncodeToken::Literal(evidence.combined[pos]))
                .map_err(Into::into)?;
            pos += 1;
        }
    }
    Ok(tokens)
}

/// The ordinary greedy strategy is independently collected, preserving its
/// search effort and nearest-first score/tie policy rather than relabelling
/// the shared optimal tape as the old collector.
#[allow(clippy::too_many_arguments)]
fn protected_tokens<B: Budget>(
    evidence: &mut SharedEvidence<B>,
    initial: EncoderMatchState,
    chain: &CommittedChain<B>,
    stream_offset: u64,
    options: EncodeOptions,
    size: usize,
    allowance: &B,
    control: &ReadControl,
    cancelled: &dyn Fn() -> bool,
    work: &mut HybridWork,
) -> Result<Buffer<EncodeToken, B>> {
    let combined = &evidence.combined;
    let start = evidence.start;
    let overlay = Overlay::new(chain, combined, stream_offset, start, allowance)?;
    work.overlay_positions += overlay.inserted_positions();
    let mut tokens = Buffer::with_capacity(combined.len() - start, allowance)?;
    let mut state = initial;
    let mut pos = start;
    while pos < combined.len() {
        check(control, cancelled)?;
        work.greedy_searches += 1;
        let max = (combined.len() - pos).min(MAX_ENCODER_MATCH_LENGTH);
        let mut best = None;
        if options.max_match_candidates != 0 && max >= 4 {
            for distance in state.reps {
                if distance > 0 && distance <= pos && distance <= options.max_match_distance {
                    let length = evidence.equality.length(combined, pos, distance, max);
                    consider_match_candidate(&mut best, &state, size, length, distance);
                }
            }
            if !best.is_some_and(|candidate: MatchCandidate| {
                candidate.length >= NICE_MATCH_LENGTH || candidate.length == max
            }) {
                let mut candidate = overlay.first(pos);
                let mut checked = 0;
                while candidate != match_finder::NO_POSITION {
                    let distance = pos - candidate;
                    if distance > options.max_match_distance {
                        break;
                    }
                    let length = evidence.equality.length(combined, pos, distance, max);
                    consider_match_candidate(&mut best, &state, size, length, distance);
                    checked += 1;
                    work.chain_candidates += 1;
                    if checked >= options.max_match_candidates
                        || best.is_some_and(|found| {
                            found.length >= NICE_MATCH_LENGTH || found.length == max
                        })
                    {
                        break;
                    }
                    candidate = overlay.previous(candidate);
                }
            }
        }
        let length = if let Some(found) = best {
            tokens
                .push(EncodeToken::Match {
                    length: found.length,
                    distance: found.distance,
                })
                .map_err(Into::into)?;
            state.remember(found.length, found.distance);
            found.length
        } else {
            tokens
                .push(EncodeToken::Literal(combined[pos]))
                .map_err(Into::into)?;
            1
        };
        pos += length;
    }
    Ok(tokens)
}

struct Planned<B: Budget> {
    blocks: Buffer<BlockPlan<B>, B>,
    state: EncoderMatchState,
    cost: usize,
    quality: Buffer<MatchCacheQuality, B>,
}
impl<B: Budget> Planned<B> {
    fn emit(&self, allowance: &B) -> Result<Buffer<u8, B>> {
        let mut bytes = Buffer::with_capacity(self.cost, allowance)?;
        for block in self.blocks.iter() {
            let packed = emit_token_block_plan(block)?;
            bytes.extend_from_slice(&packed).map_err(Into::into)?;
        }
        debug_assert_eq!(bytes.len(), self.cost);
        Ok(bytes)
    }
}

fn filter_records<B: Budget>(
    domain: &Domain<B>,
    begin: usize,
    end: usize,
    allowance: &B,
) -> Result<Buffer<EncodeFilter, B>> {
    let mut records = Buffer::new(allowance);
    for record in domain.records.iter() {
        if record.offset >= begin && record.offset < end {
            if record.offset + record.length > end {
                return Err(Error::InvalidData(
                    "hybrid partition splits a mandatory filter unit",
                ));
            }
            records
                .push(EncodeFilter {
                    offset: record.offset - begin,
                    ..*record
                })
                .map_err(Into::into)?;
        }
    }
    Ok(records)
}

#[allow(clippy::too_many_arguments)]
fn plan_domain<B: Budget>(
    domain: &Domain<B>,
    evidence: &mut SharedEvidence<B>,
    initial: EncoderMatchState,
    version: u8,
    partition: usize,
    config: HybridCodecOptions,
    cheap: bool,
    is_last: bool,
    allowance: &B,
    control: &ReadControl,
    cancelled: &dyn Fn() -> bool,
    work: &mut HybridWork,
) -> Result<Planned<B>> {
    let size = distance_size(version)?;
    let (ends, count) = boundaries(domain.bytes.len(), partition);
    let mut begin = 0;
    let mut state = initial;
    let mut blocks = Buffer::with_capacity(count, allowance)?;
    let mut quality = Buffer::with_capacity(count, allowance)?;
    let mut cost = 0usize;
    for (number, &end) in ends[..count].iter().enumerate() {
        check(control, cancelled)?;
        let block = evidence.start + begin..evidence.start + end;
        // These records are part of every table and complete-cost decision,
        // including trial parses which are later rejected.
        let records = filter_records(domain, begin, end, allowance)?;
        let terminal = is_last && number + 1 == count;
        let tokens = if cheap {
            greedy_tokens(
                evidence,
                block.clone(),
                state,
                config.max_match_candidates != 0,
                size,
                allowance,
                control,
                cancelled,
                work,
            )?
        } else {
            beam_tokens(
                &evidence.combined,
                block.clone(),
                &evidence.matches,
                evidence.start,
                &mut evidence.equality,
                state,
                config,
                size,
                None,
                allowance,
                control,
                cancelled,
                work,
            )?
        };
        let mut best = plan_token_block_with_state(
            tokens, &records, version, size, terminal, allowance, state,
        )?;
        if !cheap {
            work.price_passes += 1;
            for _ in 1..config.pricing_passes {
                let prices = TokenPrices {
                    lengths: best.lengths(),
                };
                let next = beam_tokens(
                    &evidence.combined,
                    block.clone(),
                    &evidence.matches,
                    evidence.start,
                    &mut evidence.equality,
                    state,
                    config,
                    size,
                    Some(&prices),
                    allowance,
                    control,
                    cancelled,
                    work,
                )?;
                work.price_passes += 1;
                let next = plan_token_block_with_state(
                    next, &records, version, size, terminal, allowance, state,
                )?;
                if next.len() < best.len() {
                    best = next;
                } else {
                    break;
                }
            }
        }
        cost = cost
            .checked_add(best.len())
            .ok_or(Error::InvalidData("hybrid candidate size overflows"))?;
        state = best.state();
        blocks.push_admitted(best);
        quality.push_admitted(MatchCacheQuality {
            block_start: block.start,
            block_end: block.end,
            ..evidence.quality
        });
        work.blocks += 1;
        begin = end;
    }
    Ok(Planned {
        blocks,
        state,
        cost,
        quality,
    })
}

#[cfg(test)]
struct Encoded<B: Budget> {
    bytes: Buffer<u8, B>,
    history: Buffer<u8, B>,
}
/// Fixture-only convenience; production retains plans and emits its winner.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn encode_domain<B: Budget>(
    domain: &Domain<B>,
    history: &[u8],
    initial: EncoderMatchState,
    version: u8,
    dictionary: usize,
    partition: usize,
    config: HybridCodecOptions,
    cheap: bool,
    is_last: bool,
    allowance: &B,
    control: &ReadControl,
    cancelled: &dyn Fn() -> bool,
    work: &mut HybridWork,
) -> Result<Encoded<B>> {
    let mut evidence = shared_evidence(
        history,
        domain,
        dictionary,
        config,
        &[],
        allowance,
        control,
        cancelled,
        work,
    )?;
    let plan = plan_domain(
        domain,
        &mut evidence,
        initial,
        version,
        partition,
        config,
        cheap,
        is_last,
        allowance,
        control,
        cancelled,
        work,
    )?;
    Ok(Encoded {
        bytes: plan.emit(allowance)?,
        history: history_after(history, &domain.bytes, dictionary, allowance)?,
    })
}

struct Candidate<B: Budget> {
    representation: usize,
    partition: usize,
    protected: bool,
    plan: Planned<B>,
    append: Buffer<u8, B>,
    next_cost: usize,
}
impl<B: Budget> Candidate<B> {
    fn rank(&self) -> (usize, usize, usize) {
        (self.plan.cost, self.representation, self.partition)
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_partition<B: Budget>(
    input: &[u8],
    lookahead: &[u8],
    start: &HybridCodecState<B>,
    config: HybridCodecOptions,
    mandatory_filters: &[crate::FilterSpec],
    is_last: bool,
    allowance: &B,
    control: &ReadControl,
    cancelled: &dyn Fn() -> bool,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<HybridPartition<B>> {
    encode_partition_with_hints(
        input,
        lookahead,
        start,
        config,
        mandatory_filters,
        &[],
        is_last,
        allowance,
        control,
        cancelled,
        progress,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_partition_with_hints<B: Budget>(
    input: &[u8],
    lookahead: &[u8],
    start: &HybridCodecState<B>,
    config: HybridCodecOptions,
    mandatory_filters: &[crate::FilterSpec],
    hints: &[HybridMatchHint],
    is_last: bool,
    allowance: &B,
    control: &ReadControl,
    cancelled: &dyn Fn() -> bool,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<HybridPartition<B>> {
    let mut chain = CommittedChain::new_from_history(
        start.history(),
        start.dictionary_size,
        start.stream_offset,
        allowance,
    )?;
    let seeded = chain.seeded_positions();
    let mut result = encode_partition_with_chain(
        input,
        lookahead,
        start,
        config,
        mandatory_filters,
        hints,
        &mut chain,
        is_last,
        allowance,
        control,
        cancelled,
        progress,
    )?;
    result.work.seeded_positions += seeded;
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_partition_with_chain<B: Budget>(
    input: &[u8],
    lookahead: &[u8],
    start: &HybridCodecState<B>,
    config: HybridCodecOptions,
    mandatory_filters: &[crate::FilterSpec],
    hints: &[HybridMatchHint],
    chain: &mut CommittedChain<B>,
    is_last: bool,
    allowance: &B,
    control: &ReadControl,
    cancelled: &dyn Fn() -> bool,
    progress: Option<&mut dyn FnMut(usize) -> bool>,
) -> Result<HybridPartition<B>> {
    check(control, cancelled)?;
    validate(config)?;
    if hints.len() > 256 {
        return Err(Error::InvalidData("hybrid hint quota exceeded"));
    }
    if input.len() > HYBRID_WINDOW
        || lookahead.len() > HYBRID_WINDOW
        || (!is_last && input.len() != HYBRID_WINDOW)
        || (is_last && !lookahead.is_empty())
    {
        return Err(Error::InvalidData("hybrid decision window is incomplete"));
    }
    if start.history.len() > start.dictionary_size
        || start.dictionary_size == 0
        || start.reps.iter().any(|&d| d > start.dictionary_size)
        || start.last_length > MAX_ENCODER_MATCH_LENGTH
    {
        return Err(Error::InvalidData(
            "hybrid start state is outside its dictionary domain",
        ));
    }
    let size = distance_size(start.algorithm_version)?;
    let next_offset = start
        .member_offset
        .checked_add(input.len() as u64)
        .ok_or(Error::InvalidData("hybrid member offset overflows"))?;
    let end_offset = start
        .stream_offset
        .checked_add(input.len() as u64)
        .ok_or(Error::InvalidData("hybrid stream offset overflows"))?;
    let mut work = HybridWork::default();
    let representations = if config.auto_filters && mandatory_filters.is_empty() {
        config.finalists.min(4)
    } else {
        1
    };
    let partitions = if config.full_partitions {
        if config.finalists == 4 {
            4
        } else {
            3
        }
    } else {
        1
    };
    // Slot zero is the protected ordinary-strategy alternative. The remaining
    // slots contain compact exact plans, never match graphs or trial archives.
    let mut selected: Buffer<Candidate<B>, B> = Buffer::with_capacity(config.finalists, allowance)?;
    for representation_id in 0..representations {
        let domain = make_domain(
            input,
            start.member_offset,
            mandatory_filters,
            representation(representation_id),
            allowance,
            control,
            cancelled,
        )?;
        let mut evidence = shared_evidence_with_chain(
            start.history(),
            &domain,
            start.dictionary_size,
            chain,
            start.stream_offset,
            config,
            hints,
            allowance,
            control,
            cancelled,
            &mut work,
        )?;
        if representation_id == 0 {
            let options = EncodeOptions::new(config.max_match_candidates.min(16))
                .with_max_match_distance(start.dictionary_size);
            let tokens = protected_tokens(
                &mut evidence,
                start.matches(),
                chain,
                start.stream_offset,
                options,
                size,
                allowance,
                control,
                cancelled,
                &mut work,
            )?;
            let plan = plan_token_block_with_state(
                tokens,
                &domain.records,
                start.algorithm_version,
                size,
                is_last,
                allowance,
                start.matches(),
            )?;
            let mut blocks = Buffer::with_capacity(1, allowance)?;
            let state = plan.state();
            let cost = plan.len();
            blocks.push_admitted(plan);
            let mut quality = Buffer::with_capacity(1, allowance)?;
            quality.push_admitted(MatchCacheQuality {
                every_position: false,
                max_visits: options.max_match_candidates,
                run_cap: 0,
                ..evidence.quality
            });
            selected.push_admitted(Candidate {
                representation: 0,
                partition: 0,
                protected: true,
                plan: Planned {
                    blocks,
                    state,
                    cost,
                    quality,
                },
                append: Buffer::copied(&domain.bytes, allowance)?,
                next_cost: 0,
            });
        }
        let mut seen = [([0usize; 4], 0usize); 4];
        let mut seen_count = 0;
        for partition in 0..partitions {
            let shape = boundaries(input.len(), partition);
            if seen[..seen_count].contains(&shape) {
                continue;
            }
            seen[seen_count] = shape;
            seen_count += 1;
            work.screened += 1;
            // With no matches the full-window beam is exactly the protected
            // literal plan; retain its existing owner rather than duplicating it.
            if config.finalists == 1 || (config.max_match_candidates == 0 && partition == 0) {
                continue;
            }
            let plan = plan_domain(
                &domain,
                &mut evidence,
                start.matches(),
                start.algorithm_version,
                partition,
                config,
                false,
                is_last,
                allowance,
                control,
                cancelled,
                &mut work,
            )?;
            let rank = (plan.cost, representation_id, partition);
            let position = selected[1..]
                .iter()
                .position(|old| rank < old.rank())
                .map_or(selected.len(), |at| at + 1);
            if position < config.finalists {
                let candidate = Candidate {
                    representation: representation_id,
                    partition,
                    protected: false,
                    plan,
                    append: Buffer::copied(&domain.bytes, allowance)?,
                    next_cost: 0,
                };
                if selected.len() == config.finalists {
                    selected.pop();
                }
                selected.insert(position, candidate)?;
            }
        }
        work.compared_bytes += evidence.equality.compared;
    }
    // The chosen representations share actual history bytes across all their
    // partitions. Build each next-window domain/tape once, then price each
    // finalist from its own recent-distance/last-length state.
    for representation_id in 0..representations {
        let Some(first) = selected
            .iter()
            .position(|candidate| candidate.representation == representation_id)
        else {
            continue;
        };
        if lookahead.is_empty() {
            break;
        }
        let history = history_after(
            start.history(),
            &selected[first].append,
            start.dictionary_size,
            allowance,
        )?;
        let next_domain = make_domain(
            lookahead,
            next_offset,
            mandatory_filters,
            None,
            allowance,
            control,
            cancelled,
        )?;
        let cheap_config = HybridCodecOptions {
            max_match_candidates: config.max_match_candidates.min(16),
            deeper_search: false,
            ..config
        };
        let mut evidence = shared_evidence_with_chain(
            &history,
            &next_domain,
            start.dictionary_size,
            chain,
            end_offset,
            cheap_config,
            &[],
            allowance,
            control,
            cancelled,
            &mut work,
        )?;
        for candidate in selected
            .iter_mut()
            .filter(|candidate| candidate.representation == representation_id)
        {
            let next = plan_domain(
                &next_domain,
                &mut evidence,
                candidate.plan.state,
                start.algorithm_version,
                0,
                cheap_config,
                true,
                true,
                allowance,
                control,
                cancelled,
                &mut work,
            )?;
            candidate.next_cost = next.cost;
            work.lookahead_bytes += lookahead.len() as u64;
        }
        work.compared_bytes += evidence.equality.compared;
    }
    work.finalists = selected.len() as u64;
    let winner = selected
        .iter()
        .enumerate()
        .min_by_key(|(_, candidate)| {
            (
                candidate.plan.cost.saturating_add(candidate.next_cost),
                !candidate.protected,
                candidate.representation,
                candidate.partition,
            )
        })
        .map(|(index, _)| index)
        .ok_or(Error::InvalidData("hybrid has no complete finalist"))?;
    let winner = selected.remove(winner);
    // Only the winning payload is serialized. Failed/cancelled speculation has
    // not changed committed bytes, history, output, or completed-input progress.
    check(control, cancelled)?;
    let bytes = winner.plan.emit(allowance)?;
    let history = history_after(
        start.history(),
        &winner.append,
        start.dictionary_size,
        allowance,
    )?;
    check(control, cancelled)?;
    if progress.is_some_and(|report| !report(input.len())) {
        return Err(Error::Cancelled);
    }
    chain.commit(start.history(), &winner.append, start.stream_offset)?;
    Ok(HybridPartition {
        bytes,
        end_state: HybridCodecState {
            history,
            dictionary_size: start.dictionary_size,
            algorithm_version: start.algorithm_version,
            stream_offset: end_offset,
            member_offset: next_offset,
            reps: winner.plan.state.reps,
            last_length: winner.plan.state.last_length,
        },
        history_append: winner.append,
        work,
        partition_id: winner.partition,
        representation_id: winner.representation,
        next_cost: winner.next_cost,
        cache_quality: winner.plan.quality,
    })
}

#[cfg(test)]
#[path = "hybrid_encoder_tests.rs"]
mod tests;
