use super::*;

#[test]
fn complete_plans_match_existing_emission_with_filters_and_recent_distances() {
    let tokens = [
        EncodeToken::Literal(b'A'),
        EncodeToken::Match {
            length: 8,
            distance: 4,
        },
        EncodeToken::Match {
            length: 8,
            distance: 4,
        },
        EncodeToken::Match {
            length: 12,
            distance: 7,
        },
        EncodeToken::Match {
            length: 15,
            distance: 257,
        },
        EncodeToken::Match {
            length: 20,
            distance: 8193,
        },
        EncodeToken::Literal(b'Z'),
    ];
    for (version, size) in [(0, DISTANCE_TABLE_SIZE_50), (1, DISTANCE_TABLE_SIZE_70)] {
        for initial in [
            EncoderMatchState::default(),
            EncoderMatchState {
                reps: [4, 7, 257, 8193],
                last_length: 8,
            },
        ] {
            for filter_type in [None, Some(FilterType::E8), Some(FilterType::Delta)] {
                let filters: Vec<_> = filter_type
                    .into_iter()
                    .map(|filter_type| EncodeFilter {
                        offset: 256,
                        length: 65536,
                        filter_type,
                        channels: 4,
                    })
                    .collect();
                let allowance = Allowance::default();
                for is_last in [false, true] {
                    let plan = plan_token_block_with_state(
                        Buffer::copied(&tokens, &allowance).unwrap(),
                        &filters,
                        version,
                        size,
                        is_last,
                        &allowance,
                        initial,
                    )
                    .unwrap();
                    let prefixed: Vec<_> = filters
                        .iter()
                        .copied()
                        .map(EncodeToken::Filter)
                        .chain(tokens)
                        .collect();
                    let (ordinary, ending) = encode_token_block_with_state(
                        &prefixed, version, size, is_last, &allowance, initial,
                    )
                    .unwrap();
                    let actual = emit_token_block_plan(&plan).unwrap();
                    assert_eq!(plan.len(), ordinary.len());
                    assert_eq!(&*actual, &*ordinary);
                    assert_eq!(plan.state(), ending);
                    assert_eq!(plan.header[0] & 0x40 != 0, is_last);
                    assert_eq!(plan.header[0] & 0x80, 0x80);
                    if !filters.is_empty() {
                        assert!(plan.lengths().main[256] != 0);
                    }
                }
            }
        }
    }
}

#[test]
fn planned_blocks_decode_across_fresh_tables_with_real_continuation_state() {
    for (version, size) in [(0, DISTANCE_TABLE_SIZE_50), (1, DISTANCE_TABLE_SIZE_70)] {
        let allowance = Allowance::default();
        let first = [
            EncodeToken::Literal(b'A'),
            EncodeToken::Literal(b'B'),
            EncodeToken::Literal(b'C'),
            EncodeToken::Literal(b'D'),
            EncodeToken::Match {
                length: 8,
                distance: 4,
            },
        ];
        let first = plan_token_block_with_state(
            Buffer::copied(&first, &allowance).unwrap(),
            &[],
            version,
            size,
            false,
            &allowance,
            EncoderMatchState::default(),
        )
        .unwrap();
        let second = [
            EncodeToken::Match {
                length: 8,
                distance: 4,
            },
            EncodeToken::Literal(b'X'),
            EncodeToken::Match {
                length: 5,
                distance: 1,
            },
        ];
        let second = plan_token_block_with_state(
            Buffer::copied(&second, &allowance).unwrap(),
            &[EncodeFilter {
                offset: 0,
                length: 14,
                filter_type: FilterType::E8,
                channels: 0,
            }],
            version,
            size,
            true,
            &allowance,
            first.state(),
        )
        .unwrap();
        let mut packed = emit_token_block_plan(&first).unwrap().into_vec();
        packed.extend_from_slice(&emit_token_block_plan(&second).unwrap());
        let expected = b"ABCDABCDABCDABCDABCDXXXXXX";
        assert_eq!(
            decode_lz(&packed, version, expected.len()).unwrap(),
            expected
        );
        assert_eq!(first.state().reps[0], 4);
        assert_eq!(second.state().reps[..2], [1, 4]);
    }
}

#[test]
fn filter_cost_grammar_covers_integer_widths_and_all_filter_kinds() {
    for value in [0, 1, 255, 256, 65535, 65536, 0x00ff_ffff, u32::MAX] {
        for (kind, channels) in [
            (FilterType::E8, 0),
            (FilterType::E8E9, 0),
            (FilterType::Arm, 0),
            (FilterType::Delta, 1),
            (FilterType::Delta, MAX_DELTA_CHANNELS),
        ] {
            let record = EncodeFilter {
                offset: value as usize,
                length: value as usize,
                filter_type: kind,
                channels,
            };
            let mut bits = BitWriter::new();
            try_write_filter(&mut bits, record).unwrap();
            assert_eq!(filter_payload_bits(record).unwrap(), bits.bit_pos);
        }
    }
    for channels in [0, MAX_DELTA_CHANNELS + 1] {
        assert!(filter_payload_bits(EncodeFilter {
            offset: 0,
            length: 1,
            filter_type: FilterType::Delta,
            channels,
        })
        .is_err());
    }
}

#[test]
fn complete_plan_header_cost_tracks_byte_width_and_padding_boundaries() {
    for length in [0usize, 1, 255, 256, 65535, 65536, 0x00ff_ffff] {
        let expected_width = if length <= 255 {
            1
        } else if length <= 65535 {
            2
        } else {
            3
        };
        for final_bits in 1..=8 {
            let bits = length.saturating_sub(1) * 8 + if length == 0 { 0 } else { final_bits };
            let (header, header_len) = compressed_block_header(length, bits, true, true).unwrap();
            assert_eq!(header_len, 2 + expected_width);
            assert_eq!((header[0] >> 3) & 3, (expected_width - 1) as u8);
            assert_eq!(
                usize::from(header[0] & 7),
                if length == 0 { 0 } else { final_bits - 1 }
            );
            assert_eq!(
                header[1],
                header[2..header_len]
                    .iter()
                    .fold(0x5a ^ header[0], |a, b| a ^ b)
            );
        }
    }
    assert!(compressed_block_header(256, 255 * 8, true, false).is_err());
    assert!(compressed_block_header(256, 256 * 8 + 1, true, false).is_err());
    assert!(compressed_block_header(0x0100_0000, 0, true, false).is_err());
}

#[test]
fn planning_retains_tokens_and_small_tables_without_allocating_payload() {
    let count = 100_000;
    let token_bytes = count * std::mem::size_of::<EncodeToken>();
    let allowance = Allowance::limited((token_bytes + 32 * 1024) as u64);
    let tokens = Buffer::collect(
        (0..count).map(|i| EncodeToken::Literal(i as u8)),
        &allowance,
    )
    .unwrap();
    let plan = plan_token_block_with_state(
        tokens,
        &[],
        0,
        DISTANCE_TABLE_SIZE_50,
        true,
        &allowance,
        EncoderMatchState::default(),
    )
    .unwrap();
    assert!(plan.len() > 64 * 1024);
    assert!(allowance.used() < (token_bytes + 16 * 1024) as u64);
    assert!(matches!(
        emit_token_block_plan(&plan),
        Err(Error::WorkspaceLimitExceeded(_))
    ));
    // A failed speculative emission does not change the immutable plan.
    assert_eq!(plan.state(), EncoderMatchState::default());
    drop(plan);
    assert_eq!(allowance.used(), 0);
}

#[test]
fn plan_and_emission_refusals_release_every_owned_allocation() {
    use crate::codec::workspace::RefusingBudget;
    let run = |allowance: &RefusingBudget| -> Result<()> {
        let tokens = Buffer::collect(
            b"a complete plan owns its candidate until selection"
                .iter()
                .copied()
                .map(EncodeToken::Literal),
            allowance,
        )?;
        let plan = plan_token_block_with_state(
            tokens,
            &[EncodeFilter {
                offset: 0,
                length: 16,
                filter_type: FilterType::Arm,
                channels: 0,
            }],
            1,
            DISTANCE_TABLE_SIZE_70,
            true,
            allowance,
            EncoderMatchState::default(),
        )?;
        let emitted = emit_token_block_plan(&plan)?;
        assert_eq!(emitted.len(), plan.len());
        Ok(())
    };
    let baseline = RefusingBudget::new(usize::MAX);
    run(&baseline).unwrap();
    assert_eq!(baseline.used(), 0);
    let attempts = baseline.attempts();
    assert!(attempts > 10);
    for fail_at in 0..attempts {
        let budget = RefusingBudget::new(fail_at);
        assert!(
            matches!(run(&budget), Err(Error::Cancelled)),
            "allocation={fail_at}"
        );
        assert_eq!(budget.used(), 0, "allocation={fail_at}");
    }
}
