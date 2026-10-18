use super::*;
use crate::hybrid::IndexLimits;
use std::cell::Cell;

fn index(cache_bytes: u64, members: &[(u64, Vec<u8>)]) -> RepeatIndex {
    let mut index = RepeatIndex::create(
        std::env::temp_dir(),
        IndexLimits {
            cache_bytes,
            max_disk_bytes: 1_000_000,
        },
    )
    .unwrap();
    for (id, text) in members {
        index.begin_member(*id).unwrap();
        for byte in text.chunks(1) {
            index.append(byte).unwrap();
        }
        index.finish_member().unwrap();
    }
    index.seal().unwrap();
    index
}

fn oracle(members: &[(u64, Vec<u8>)], pattern: &[u8]) -> Vec<Occurrence> {
    let mut found = Vec::new();
    for (id, text) in members {
        for offset in 0..text.len() {
            if text.get(offset..offset + pattern.len()) == Some(pattern) {
                found.push(Occurrence {
                    member_id: *id,
                    offset: offset as u64,
                });
            }
        }
    }
    found.sort_unstable();
    found
}

fn collect(
    index: &mut RepeatIndex,
    pattern: &[u8],
    budget: &mut QueryBudget,
) -> (QueryResult, Vec<Occurrence>) {
    let mut found = Vec::new();
    let result = index
        .for_each_occurrence_bounded(pattern, budget, &|| false, &mut |occurrence| {
            found.push(occurrence);
            Ok(true)
        })
        .unwrap();
    (result, found)
}

#[test]
fn bounded_queries_never_overshoot_or_turn_exhaustion_into_a_miss() {
    let members = [
        (19, b"banana".to_vec()),
        (3, b"ananas".to_vec()),
        (7, b"banana".to_vec()),
    ];
    for cache_bytes in [0, 8192] {
        let mut tree = index(cache_bytes, &members);
        let mut full = QueryBudget::new(u64::MAX);
        let (complete, expected_order) = collect(&mut tree, b"ana", &mut full);
        assert!(complete.complete);
        assert_eq!(complete.occurrences, expected_order.len() as u64);
        let required = full.used();
        assert!(required > complete.occurrences);
        for limit in 0..=required {
            let mut budget = QueryBudget::new(limit);
            let reads_before = tree.nodes.io.reads + tree.members.io.reads + tree.bytes.io.reads;
            let (result, found) = collect(&mut tree, b"ana", &mut budget);
            let reads_after = tree.nodes.io.reads + tree.members.io.reads + tree.bytes.io.reads;
            if cache_bytes == 0 {
                // With no cache each actual store read has an independent
                // counter. This catches an unmetered member/sibling/byte path.
                assert_eq!(reads_after - reads_before, budget.used());
            }
            assert_eq!(budget.used() + budget.remaining(), limit);
            assert!(budget.used() <= limit);
            assert_eq!(found, expected_order[..found.len()]);
            assert_eq!(result.occurrences, found.len() as u64);
            assert_eq!(result.complete, limit == required, "limit={limit}");
            if !result.complete {
                assert_eq!(budget.remaining(), 0);
            }
        }
        let mut none = QueryBudget::new(0);
        assert_eq!(
            collect(&mut tree, b"missing", &mut none).0,
            QueryResult {
                occurrences: 0,
                complete: false
            }
        );
        let mut enough = QueryBudget::new(1024);
        assert_eq!(
            collect(&mut tree, b"missing", &mut enough).0,
            QueryResult {
                occurrences: 0,
                complete: true
            }
        );
        // A completed no-match still consumes real record lookup effort.
        assert!(enough.used() > 0);
    }
}

#[test]
fn shared_budget_and_cache_hits_account_for_the_same_logical_reads() {
    let members = [
        (91, b"ababababa".to_vec()),
        (17, b"abacaba".to_vec()),
        (23, Vec::new()),
    ];
    let patterns = [b"ab".as_slice(), b"aba", b"aca", b"not present"];
    let mut costs = Vec::new();
    for cache_bytes in [0, 8192] {
        let mut tree = index(cache_bytes, &members);
        let mut budget = QueryBudget::new(10_000);
        for _ in 0..2 {
            for pattern in patterns {
                let before = budget.used();
                let (result, mut found) = collect(&mut tree, pattern, &mut budget);
                assert!(result.complete);
                found.sort_unstable();
                assert_eq!(found, oracle(&members, pattern));
                costs.push(budget.used() - before);
            }
        }
        assert_eq!(budget.used(), costs[costs.len() - 8..].iter().sum());
    }
    assert_eq!(costs[..4], costs[4..8]);
    assert_eq!(costs[..8], costs[8..]);
}

#[test]
fn cancellation_and_visitor_stops_leave_the_complete_index_reusable() {
    let members = [(6, b"aaaaaa".to_vec()), (2, b"aaaaaa".to_vec())];
    let mut tree = index(1024, &members);
    let mut budget = QueryBudget::new(10_000);
    let checks = Cell::new(0);
    assert_eq!(
        tree.for_each_occurrence_bounded(
            b"aa",
            &mut budget,
            &|| {
                checks.set(checks.get() + 1);
                checks.get() > 12
            },
            &mut |_| Ok(true),
        )
        .unwrap_err(),
        Error::Cancelled
    );
    assert!(budget.used() > 0);
    assert!(budget.remaining() > 0);
    let before = budget.used();
    let mut accepted = 0;
    let stopped = tree
        .for_each_occurrence_bounded(b"aa", &mut budget, &|| false, &mut |_| {
            if accepted == 2 {
                Ok(false)
            } else {
                accepted += 1;
                Ok(true)
            }
        })
        .unwrap();
    assert_eq!(
        stopped,
        QueryResult {
            occurrences: 2,
            complete: false
        }
    );
    assert!(budget.used() > before);
    assert_eq!(
        tree.for_each_occurrence_bounded(b"aa", &mut budget, &|| false, &mut |_| {
            Err(Error::Cancelled)
        })
        .unwrap_err(),
        Error::Cancelled
    );
    let (result, mut found) = collect(&mut tree, b"aa", &mut budget);
    found.sort_unstable();
    assert!(result.complete);
    assert_eq!(found, oracle(&members, b"aa"));
    assert_eq!(tree.occurrences(b"aa").unwrap(), found);
}

fn binary_strings(maximum: usize) -> Vec<Vec<u8>> {
    (0..=maximum)
        .flat_map(|length| {
            (0..1usize << length).map(move |value| {
                (0..length)
                    .map(|bit| b'a' + ((value >> bit) & 1) as u8)
                    .collect()
            })
        })
        .collect()
}

#[test]
fn completed_queries_match_exhaustive_overlapping_and_member_boundary_oracle() {
    let patterns = binary_strings(4);
    for text in binary_strings(5) {
        let members = [
            (19, text.clone()),
            (2, text.iter().rev().copied().collect()),
            (81, Vec::new()),
            (7, text.clone()),
        ];
        let mut tree = index(8192, &members);
        let mut budget = QueryBudget::new(1_000_000);
        for pattern in patterns.iter().filter(|pattern| !pattern.is_empty()) {
            let (result, mut found) = collect(&mut tree, pattern, &mut budget);
            found.sort_unstable();
            assert!(result.complete);
            assert_eq!(result.occurrences, found.len() as u64);
            assert_eq!(
                found,
                oracle(&members, pattern),
                "members={members:?}, pattern={pattern:?}"
            );
        }
    }
    let members = [(0, b"abcd".to_vec()), (1, b"efgh".to_vec())];
    let mut tree = index(0, &members);
    let mut budget = QueryBudget::new(10_000);
    let (result, found) = collect(&mut tree, b"cdef", &mut budget);
    assert!(result.complete);
    assert!(found.is_empty());
}
