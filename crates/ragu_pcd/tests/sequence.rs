//! Characterization tests for sequence concatenation over coefficient
//! polynomials, in the real PCD shape: two [`SeedSequence`] leaves establish
//! initial sequences whose name pairs (sequence + length token) ride their
//! headers, and a [`ConcatSequences`] **fuse** binds its four witnessed
//! inputs to those header-carried names in-circuit before proving the
//! concatenation and the token product.
//!
//! The headline numbers, at `ProductionRank`:
//!
//! * A sequence alone holds up to **8,192 members** (degree `≤ 8191`); a
//!   **length-threaded** sequence holds **8,191**, because its token `X^L`
//!   needs degree `L` — the same ceiling as a multiset, for a different
//!   reason.
//! * The fuse circuit is **`O(1)` in the length**: six 2-wire names, eight
//!   cross-proof equalities, six claims, one challenge, two multiplications
//!   and one addition. The runtime offset `z^{|A|}` arrives as a poly-query
//!   opening of the committed monomial — no in-circuit loop, no
//!   const-generic length.
//! * A length token needs **no monomial proof**: `commit(Xⁿ)` is the `n`-th
//!   host generator, so the token's canonical name is recomputable by any
//!   consumer from the cycle parameters, and under binding the name is the
//!   proof.
//! * Downstream consumers see only the output pair `(C, M_c)`.
//!
//! Run the ignored `print_concat_characterization` (ideally with
//! `--release`) for wall-clock numbers across sizes.
//!
//! [`SeedSequence`]: ragu_testing::pcd::sequence::SeedSequence
//! [`ConcatSequences`]: ragu_testing::pcd::sequence::ConcatSequences

use ragu_arithmetic::rand::{SeedableRng, rngs::StdRng};
use ragu_circuits::polynomials::{ProductionRank, Rank};
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_testing::pcd::{
    collections::collections_app,
    sequence::{
        ConcatSequences, ConcatSequencesWitness, fuse_concat, length_token, seed_sequence,
        sequence_polynomial,
    },
};

type R = ProductionRank;

fn members(values: &[u64]) -> Vec<Fp> {
    values.iter().map(|v| Fp::from(*v)).collect()
}

/// Two seeded sequences fuse into their concatenation, the parent verifies,
/// and the output's members are `A`'s followed by `B`'s — order and
/// duplicates preserved.
#[test]
fn seeded_sequences_fuse_into_their_concatenation() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(1729);

    // A repeated member and an order-sensitive layout.
    let left = seed_sequence(&app, &mut rng, &members(&[3, 5, 5]))?;
    let right = seed_sequence(&app, &mut rng, &members(&[7, 3]))?;
    assert!(app.verify(&left, &mut rng)?, "the left seed verifies");
    assert!(app.verify(&right, &mut rng)?, "the right seed verifies");

    let out = fuse_concat(&app, &mut rng, left, right)?;
    assert!(app.verify(&out, &mut rng)?, "the concatenation verifies");

    // Longhand: the carried members are the concatenated list, position by
    // position, and the sequence polynomial's coefficients agree.
    let expected = [3u64, 5, 5, 7, 3].map(Fp::from);
    assert_eq!(out.data().members.len(), expected.len());
    for (i, want) in expected.iter().enumerate() {
        assert_eq!(out.data().members[i], *want, "member {i} in order");
    }
    let poly = sequence_polynomial::<Fp, R>(&out.data().members);
    let coeffs: Vec<Fp> = poly.iter_coeffs().collect();
    for (i, want) in expected.iter().enumerate() {
        assert_eq!(coeffs[i], *want, "coefficient {i} is member {i}");
    }

    Ok(())
}

/// A wrong offset token is rejected — and it is the cross-proof header tie
/// that fires: the child's header names `X^{|A|}`, and a parent witnessing
/// any other token cannot bind to it. Assembly does not check trace
/// satisfaction, so the violated in-circuit equality may only surface at
/// [`verify`] — rejection at either layer is the contract.
///
/// [`verify`]: ragu_pcd::Application::verify
#[test]
fn a_wrong_offset_is_rejected() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(6174);

    let a = members(&[3, 5]);
    let b = members(&[7, 11]);
    let left = seed_sequence(&app, &mut rng, &a)?;
    let right = seed_sequence(&app, &mut rng, &b)?;

    // The parent shifts by 1 instead of |A| = 2, output computed honestly
    // *for that offset* (overlapping concatenation), tokens consistent with
    // the cheat — only the header tie can reject it.
    let mut overlapped = vec![Fp::from(3u64); 3];
    overlapped[1] = Fp::from(5u64) + Fp::from(7u64);
    overlapped[2] = Fp::from(11u64);
    let result = app.fuse(
        &mut rng,
        ConcatSequences::new(),
        ConcatSequencesWitness {
            a: app.commit_polynomial(&sequence_polynomial(&a))?,
            b: app.commit_polynomial(&sequence_polynomial(&b))?,
            a_token: app.commit_polynomial(&length_token(1))?,
            b_token: app.commit_polynomial(&length_token(b.len()))?,
            output: app.commit_polynomial(&sequence_polynomial(&overlapped))?,
            output_token: app.commit_polynomial(&length_token(3))?,
        },
        left,
        right,
    );

    let rejected = match result {
        Err(_) => true,
        Ok((out, ())) => !app.verify(&out, &mut rng)?,
    };
    assert!(
        rejected,
        "an offset that is not the child's header-named token must be rejected"
    );
    Ok(())
}

/// A length token is publicly decodable: any consumer holding the cycle
/// parameters recomputes `commit(Xⁿ).coords()` and compares — the name is
/// the proof that the committed polynomial is exactly `Xⁿ`, with no
/// in-circuit monomial check anywhere.
#[test]
fn a_length_token_is_publicly_decodable() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;

    // The prover's token for length 5 and the consumer's independent
    // recomputation name the same commitment.
    let prover_side = app.commit_polynomial(&length_token::<Fp, R>(5))?;
    let consumer_side = app.commit_polynomial(&length_token::<Fp, R>(5))?;
    assert_eq!(prover_side.coords(), consumer_side.coords());

    // And distinct lengths have distinct names (the generators are
    // independent points).
    let other = app.commit_polynomial(&length_token::<Fp, R>(6))?;
    assert_ne!(prover_side.coords(), other.coords());

    Ok(())
}

/// The ceilings, pinned by arithmetic: a bare sequence fills every
/// coefficient the rank provides (8,192 members); the length token for that
/// sequence needs degree 8,192 and fails at construction, so a
/// length-threaded sequence caps at 8,191 members.
#[test]
fn the_sequence_ceiling_is_8192_and_the_threaded_ceiling_is_8191() {
    assert_eq!(<R as Rank>::num_coeffs(), 8192);

    // A full-capacity bare sequence is a well-formed polynomial...
    let full: Vec<Fp> = (1..=8192u64).map(Fp::from).collect();
    let seq = sequence_polynomial::<Fp, R>(&full);
    assert_eq!(seq.iter_coeffs().count(), 8192);

    // ...and the largest token is X^8191.
    let _ = length_token::<Fp, R>(8191);
}

/// One past the threaded ceiling: `X^8192` needs 8,193 coefficients.
#[test]
#[should_panic(expected = "exceeds capacity")]
fn a_token_past_the_ceiling_fails_at_construction() {
    let _ = length_token::<Fp, R>(8192);
}

/// Wall-clock characterization across sizes. The circuit shapes are
/// identical at every size — one application serves all of them.
///
/// Ignored by default; run explicitly, ideally in release mode:
/// `cargo test -p ragu_pcd --release print_concat_characterization -- --ignored --nocapture`
#[test]
#[ignore = "characterization; run explicitly with --release --nocapture"]
fn print_concat_characterization() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(2222);

    println!();
    println!("sequence length | seed left | seed right | fuse concat | verify");
    for total in [256u64, 1024, 4096, 8191] {
        let half = total / 2;
        let a: Vec<Fp> = (1..=half).map(Fp::from).collect();
        let b: Vec<Fp> = (half + 1..=total).map(Fp::from).collect();

        let t = std::time::Instant::now();
        let left = seed_sequence(&app, &mut rng, &a)?;
        let seed_left = t.elapsed();
        let t = std::time::Instant::now();
        let right = seed_sequence(&app, &mut rng, &b)?;
        let seed_right = t.elapsed();

        let t = std::time::Instant::now();
        let out = fuse_concat(&app, &mut rng, left, right)?;
        let fuse = t.elapsed();

        let t = std::time::Instant::now();
        assert!(app.verify(&out, &mut rng)?);
        let verify = t.elapsed();

        println!(
            "{total:>15} | {seed_left:>9.2?} | {seed_right:>10.2?} | {fuse:>11.2?} | {verify:>6.2?}"
        );
    }

    Ok(())
}
