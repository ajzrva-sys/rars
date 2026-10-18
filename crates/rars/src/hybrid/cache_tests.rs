use super::*;

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rars-record-cache-test-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn records<T: Record>(directory: &Directory, slots: usize) -> Records<T> {
    Records::create(
        &directory.0.join("records"),
        (slots * std::mem::size_of::<Slot<T>>()) as u64,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap()
}

fn disk_node(records: &Records<Node>, id: u64) -> Node {
    let mut file = records.file.try_clone().unwrap();
    let mut bytes = [0u8; RECORD_BYTES];
    read_at(&mut file, &mut bytes, Records::<Node>::offset(id).unwrap()).unwrap();
    Node::decode(&bytes)
}

#[test]
fn resident_mutations_do_no_io_until_explicit_flush() {
    let directory = Directory::new();
    let mut records = self::records::<Node>(&directory, 8);
    let id = records
        .append(Node {
            start: 7,
            ..Node::empty()
        })
        .unwrap();
    for start in 8..1000 {
        records
            .put(
                id,
                Node {
                    start,
                    ..Node::empty()
                },
            )
            .unwrap();
        assert_eq!(records.get(id).unwrap().start, start);
    }
    assert_eq!((records.io.reads, records.io.writes), (0, 0));
    assert_eq!(records.file.metadata().unwrap().len(), 0);
    records.flush().unwrap();
    assert_eq!(records.io.writes, 1);
    assert_eq!(records.io.written_bytes, Node::WIDTH as u64);
    assert_eq!(disk_node(&records, id).start, 999);
    records.flush().unwrap();
    assert_eq!(records.io.writes, 1);
}

#[test]
fn node_and_member_groups_coalesce_without_changing_cache_capacity() {
    let nodes_directory = Directory::new();
    let node_count = PAGE / Node::WIDTH;
    let mut nodes = records::<Node>(&nodes_directory, node_count);
    assert_eq!(nodes.cache.len(), 46);
    assert_eq!(
        nodes.allocated(),
        (46 * std::mem::size_of::<Slot<Node>>()) as u64
    );
    for id in 0..node_count {
        nodes
            .append(Node {
                start: id as u64,
                ..Node::empty()
            })
            .unwrap();
    }
    nodes.flush().unwrap();
    assert_eq!(nodes.io.writes, 1);
    assert_eq!(nodes.io.written_bytes, (node_count * Node::WIDTH) as u64);
    for id in 0..node_count as u64 {
        assert_eq!(disk_node(&nodes, id).start, id);
    }
    let members_directory = Directory::new();
    let member_count = PAGE / Member::WIDTH;
    let mut members = records::<Member>(&members_directory, member_count);
    assert_eq!(members.cache.len(), 102);
    for id in 0..member_count {
        members
            .append(Member {
                id: id as u64,
                ..Member::default()
            })
            .unwrap();
    }
    members.flush().unwrap();
    assert_eq!(members.io.writes, 1);
    assert_eq!(
        members.io.written_bytes,
        (member_count * Member::WIDTH) as u64
    );
}

#[test]
fn dirty_runs_never_overwrite_clean_or_absent_records() {
    let directory = Directory::new();
    let mut records = self::records::<Node>(&directory, 10);
    for id in 0..6 {
        records
            .append(Node {
                start: id,
                ..Node::empty()
            })
            .unwrap();
    }
    records.flush().unwrap();
    let writes = records.io.writes;
    let written = records.io.written_bytes;
    for id in [0, 2, 3, 5] {
        records
            .put(
                id,
                Node {
                    start: 100 + id,
                    ..Node::empty()
                },
            )
            .unwrap();
    }
    records.flush_id(2).unwrap();
    assert_eq!(records.io.writes - writes, 3);
    assert_eq!(records.io.written_bytes - written, 4 * Node::WIDTH as u64);
    for id in 0..6 {
        let expected = if [0, 2, 3, 5].contains(&id) {
            100 + id
        } else {
            id
        };
        assert_eq!(disk_node(&records, id).start, expected);
    }
}

#[test]
fn tiny_cache_collisions_and_evictions_match_independent_record_oracle() {
    for capacity in [0, 1, 2, 3, 46, 47] {
        let directory = Directory::new();
        let mut records = self::records::<Node>(&directory, capacity);
        let mut oracle = Vec::new();
        for id in 0..137 {
            oracle.push(id);
            records
                .append(Node {
                    start: id,
                    ..Node::empty()
                })
                .unwrap();
        }
        for step in 0..600 {
            let at = (step * 19 + 7) % oracle.len();
            assert_eq!(records.get(at as u64).unwrap().start, oracle[at]);
            if step % 3 == 0 {
                oracle[at] += 1000;
                records
                    .put(
                        at as u64,
                        Node {
                            start: oracle[at],
                            ..Node::empty()
                        },
                    )
                    .unwrap();
            }
        }
        records.flush().unwrap();
        for (id, expected) in oracle.into_iter().enumerate() {
            assert_eq!(disk_node(&records, id as u64).start, expected);
        }
        if capacity == 0 {
            assert_eq!(records.io.writes, 137 + 200);
        }
    }
}

#[test]
fn read_and_write_errors_poison_shared_stores_before_cached_hits() {
    let directory = Directory::new();
    let mut records = self::records::<Node>(&directory, 4);
    records.append(Node::empty()).unwrap();
    records.file = File::open(directory.0.join("records")).unwrap();
    assert!(records.flush().is_err());
    assert!(Records::<Node>::dirty(records.cache[0].id));
    assert!(records.get(0).is_err());
    assert!(records.put(0, Node::empty()).is_err());
    let failed = records.failed.clone();
    let mut bytes = Bytes::create(&directory.0.join("bytes"), 0, failed).unwrap();
    assert!(bytes.append(b"x").is_err());

    let directory = Directory::new();
    let mut records = self::records::<Node>(&directory, 2);
    records.append(Node::empty()).unwrap();
    records.flush().unwrap();
    let mut bytes = Bytes::create(&directory.0.join("bytes"), 0, records.failed.clone()).unwrap();
    bytes.append(b"x").unwrap();
    bytes.file.set_len(0).unwrap();
    assert!(bytes.get(0).is_err());
    assert!(records.get(0).is_err());
}

#[test]
fn finish_and_seal_surface_storage_errors_without_publishing_completion() {
    let mut tree = RepeatIndex::create(
        std::env::temp_dir(),
        IndexLimits {
            cache_bytes: 64 * 1024,
            max_disk_bytes: 1_000_000,
        },
    )
    .unwrap();
    tree.begin_member(0).unwrap();
    tree.append(b"banana").unwrap();
    tree.nodes.file = File::open(tree.test_directory().join("nodes")).unwrap();
    assert!(tree.finish_member().is_err());
    assert!(tree.active_member.is_some());
    assert!(tree.occurrences(b"ana").is_err());
    assert!(tree.member_source(0).is_err());
    assert!(tree.seal().is_err());

    let mut tree = RepeatIndex::create(
        std::env::temp_dir(),
        IndexLimits {
            cache_bytes: 64 * 1024,
            max_disk_bytes: 1_000_000,
        },
    )
    .unwrap();
    // The root is dirty even with no members, so seal must report this failure.
    tree.nodes.file = File::open(tree.test_directory().join("nodes")).unwrap();
    assert!(tree.seal().is_err());
    assert!(tree.begin_member(0).is_err());
}

#[test]
fn record_end_overflow_is_rejected_before_any_write_or_publication() {
    let directory = Directory::new();
    let mut records = self::records::<Node>(&directory, 0);
    let id = u64::MAX / Node::WIDTH as u64;
    assert!(records.put(id, Node::empty()).is_err());
    assert_eq!(records.io.writes, 0);
    assert_eq!(records.file.metadata().unwrap().len(), 0);
    assert_eq!(records.length, 0);
    // Argument errors alone do not poison a healthy storage owner.
    records.append(Node::empty()).unwrap();
    assert_eq!(records.io.writes, 1);
}

#[test]
fn partial_run_write_keeps_every_record_dirty_and_poisons_the_store() {
    let directory = Directory::new();
    let mut records = self::records::<Node>(&directory, 8);
    for start in 0..4 {
        records
            .append(Node {
                start,
                ..Node::empty()
            })
            .unwrap();
    }
    records.fail_write_after = Some(Node::WIDTH + Node::WIDTH / 2);
    assert!(records.flush().is_err());
    assert_eq!(
        records.file.metadata().unwrap().len(),
        (Node::WIDTH + Node::WIDTH / 2) as u64
    );
    for at in 0..4 {
        assert!(Records::<Node>::dirty(records.cache[at].id));
        assert!(records.get(at as u64).is_err());
    }
    assert!(records.flush().is_err());
}

#[test]
fn zero_cache_write_error_is_immediate_and_never_publishes_the_record() {
    let directory = Directory::new();
    let mut records = self::records::<Node>(&directory, 0);
    records.file = File::open(directory.0.join("records")).unwrap();
    assert!(records.append(Node::empty()).is_err());
    assert_eq!(records.length, 0);
    assert_eq!(records.file.metadata().unwrap().len(), 0);
    assert!(records.append(Node::empty()).is_err());
    assert_eq!(records.io.writes, 1);
}
