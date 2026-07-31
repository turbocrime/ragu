//! Characterization tests for the polynomial collections, in the real PCD
//! shape: every collection starts as a **singleton seed** — one literal
//! member — and grows only by **fusing** two proven collections, so a
//! collection of `N` members is a tree of `N` seeds and `N − 1` fuses.
//!
//! What the proofs establish:
//!
//! * A **multiset** is the monic polynomial whose roots are its members
//!   (with multiplicity); fusing is polynomial multiplication, proven by
//!   one opened claim.
//! * A **sequence** is the polynomial whose coefficients are its members,
//!   with a **sentinel** coefficient `1` above the last member; its header
//!   carries the member count next to the name, and fusing is the shifted
//!   addition `C = A + X^{ℓa}·(B − 1)`, the offset factor `z^{ℓa}` computed
//!   in fixed shape from the header-carried length rather than witnessed.
//! * Cross-proof identity is plain field equality on names: a fuse
//!   re-witnesses the children's polynomials and enforces its handles'
//!   coordinates equal the header wires.
//!
//! Both fuse circuits are `O(1)` in collection size; every size-dependent
//! cost is native. The ceiling at `ProductionRank` is **8,191 members** for
//! either collection: the rank provides `2^13 = 8192` coefficients, and one
//! sits above the last member (the multiset's leading coefficient, the
//! sequence's sentinel).
//!
//! Run the ignored `print_*_characterization` tests (ideally with
//! `--release`) for wall-clock numbers.

use ragu_arithmetic::{
    ff::Field,
    rand::{SeedableRng, rngs::StdRng},
};
use ragu_circuits::polynomials::{ProductionRank, Rank};
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::Pcd;
use ragu_testing::pcd::collections::{
    collections_app, fuse_concat, fuse_merge, merged_polynomial, seed_sequence, seed_set,
    sequence_polynomial, set_polynomial,
    step::{
        ConcatSequences, ConcatSequencesWitness, MergeSets, MergeSetsWitness, SeqHeader, SetHeader,
    },
};

type R = ProductionRank;

/// Two singleton seeds fuse into a two-member set, which fuses with a third
/// singleton — a repeated member — into `{3, 5, 5}`; the parent verifies,
/// and the merged polynomial is exactly the expected set polynomial, root
/// by root and by name.
#[test]
fn seeded_singletons_fuse_into_their_merge() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(31415);

    let three = seed_set(&app, &mut rng, Fp::from(3u64))?;
    let five_a = seed_set(&app, &mut rng, Fp::from(5u64))?;
    let five_b = seed_set(&app, &mut rng, Fp::from(5u64))?;
    assert!(app.verify(&three, &mut rng)?, "a singleton seed verifies");

    let pair = fuse_merge(&app, &mut rng, three, five_a)?;
    let merged = fuse_merge(&app, &mut rng, pair, five_b)?;
    assert!(app.verify(&merged, &mut rng)?, "the merge tree verifies");

    // Longhand root checks on the carried product.
    let product = &merged.data().polynomial;
    for m in [3u64, 5] {
        assert_eq!(
            product.eval(Fp::from(m)),
            Fp::ZERO,
            "every seeded member is a root of the merge"
        );
    }
    assert_ne!(
        product.eval(Fp::from(13u64)),
        Fp::ZERO,
        "a non-member is not a root"
    );
    // Multiplicity: 5 was seeded twice, so it is a repeated root of the
    // merge — its derivative also vanishes there. Derivative computed
    // longhand from the coefficients.
    let coeffs: Vec<Fp> = product.iter_coeffs().collect();
    let mut derivative_at_5 = Fp::ZERO;
    let mut power = Fp::ONE; // 5^(i-1)
    for (i, c) in coeffs.iter().enumerate().skip(1) {
        derivative_at_5 += Fp::from(i as u64) * *c * power;
        power *= Fp::from(5u64);
    }
    assert_eq!(derivative_at_5, Fp::ZERO, "5 is a double root of the merge");

    // And the header-named polynomial is exactly the expected set: any
    // consumer recomputing `{3, 5, 5}`'s commitment gets the merge's name.
    let expected = set_polynomial::<Fp, R>(&[3u64, 5, 5].map(Fp::from));
    assert_eq!(
        merged.data().coords,
        app.commit_polynomial(&expected)?.coords(),
        "the merge's name is the expected set's name"
    );

    Ok(())
}

/// The cross-proof identity check fires: a parent whose witnessed
/// contributing set is not the child's header-named set cannot produce a
/// verifying proof. Assembly does not check trace satisfaction, so the
/// violated in-circuit equality may only surface at [`verify`] — rejection
/// at either layer is the contract.
///
/// [`verify`]: ragu_pcd::Application::verify
#[test]
fn a_parent_cannot_merge_a_set_that_is_not_the_childs() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(2718);

    let left = seed_set(&app, &mut rng, Fp::from(3u64))?;
    let right = seed_set(&app, &mut rng, Fp::from(7u64))?;

    // The parent swaps in a different left set, product computed honestly
    // *for the substitute* — every claim is internally consistent; only the
    // header tie can reject it.
    let substitute = set_polynomial::<Fp, R>(&[Fp::from(11u64)]);
    let b = set_polynomial::<Fp, R>(&[Fp::from(7u64)]);
    let result = app.fuse(
        &mut rng,
        MergeSets::new(),
        MergeSetsWitness {
            a: app.commit_polynomial(&substitute)?,
            b: app.commit_polynomial(&b)?,
            product: app.commit_polynomial(&merged_polynomial(&substitute, &b))?,
        },
        left,
        right,
    );

    let rejected = match result {
        Err(_) => true,
        Ok((merged, ())) => !app.verify(&merged, &mut rng)?,
    };
    assert!(
        rejected,
        "the in-circuit name-vs-header equality must reject a substituted set"
    );
    Ok(())
}

/// A claimed merge that is not the product is rejected at fuse time: the
/// merged set's claim carries `a(z)·b(z)` as its claimed evaluation, and the
/// wrong polynomial does not evaluate to it.
#[test]
fn a_wrong_merge_is_rejected() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(1618);

    let left = seed_set(&app, &mut rng, Fp::from(3u64))?;
    let right = seed_set(&app, &mut rng, Fp::from(7u64))?;

    // The claimed merge drops member 7.
    let result = app.fuse(
        &mut rng,
        MergeSets::new(),
        MergeSetsWitness {
            a: app.commit_polynomial(&set_polynomial(&[Fp::from(3u64)]))?,
            b: app.commit_polynomial(&set_polynomial(&[Fp::from(7u64)]))?,
            product: app.commit_polynomial(&set_polynomial(&[Fp::from(3u64)]))?,
        },
        left,
        right,
    );

    assert!(
        result.is_err(),
        "a merge whose product drops a member must fail to prove"
    );
    Ok(())
}

/// Four singleton seeds fuse pairwise, then the pairs fuse into
/// `[3, 5, 5, 7]` — order and duplicates preserved; the parent verifies,
/// the carried members match position by position, and the header-named
/// polynomial is the expected monic encoding.
#[test]
fn seeded_singletons_fuse_into_their_concatenation() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(1729);

    let three = seed_sequence(&app, &mut rng, Fp::from(3u64))?;
    let five_a = seed_sequence(&app, &mut rng, Fp::from(5u64))?;
    let five_b = seed_sequence(&app, &mut rng, Fp::from(5u64))?;
    let seven = seed_sequence(&app, &mut rng, Fp::from(7u64))?;
    assert!(app.verify(&three, &mut rng)?, "a singleton seed verifies");

    let left = fuse_concat(&app, &mut rng, three, five_a)?; // [3, 5]
    let right = fuse_concat(&app, &mut rng, five_b, seven)?; // [5, 7]
    let out = fuse_concat(&app, &mut rng, left, right)?; // [3, 5, 5, 7]
    assert!(app.verify(&out, &mut rng)?, "the concatenation verifies");

    // Longhand: the carried members are the concatenated list, position by
    // position.
    let expected = [3u64, 5, 5, 7].map(Fp::from);
    assert_eq!(out.data().members.len(), expected.len());
    for (i, want) in expected.iter().enumerate() {
        assert_eq!(out.data().members[i], *want, "member {i} in order");
    }

    // And the header-named polynomial is exactly the expected monic
    // encoding `[3, 5, 5, 7, 1]`: any consumer recomputing the expected
    // sequence's commitment gets the output's name.
    let expected_poly = sequence_polynomial::<Fp, R>(&expected);
    let coeffs: Vec<Fp> = expected_poly.iter_coeffs().collect();
    assert_eq!(
        coeffs[4],
        Fp::ONE,
        "the sentinel sits above the last member"
    );
    assert_eq!(
        out.data().coords,
        app.commit_polynomial(&expected_poly)?.coords(),
        "the output's name is the expected sequence's name"
    );

    Ok(())
}

/// The sentinel makes every member value representable: `[0]` alone would
/// commit to the zero polynomial (the identity, which the framework
/// rejects), but its monic encoding `[0, 1]` is the polynomial `X`.
#[test]
fn a_zero_member_is_a_valid_sequence() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(4104);

    let zero = seed_sequence(&app, &mut rng, Fp::ZERO)?;
    let three = seed_sequence(&app, &mut rng, Fp::from(3u64))?;
    let out = fuse_concat(&app, &mut rng, zero, three)?;
    assert!(app.verify(&out, &mut rng)?, "[0, 3] verifies");
    assert_eq!(out.data().members, vec![Fp::ZERO, Fp::from(3u64)]);

    Ok(())
}

/// The cross-proof identity check fires for sequences too: a parent whose
/// witnessed contributing sequence is not the child's header-named sequence
/// cannot produce a verifying proof. Rejection at either layer is the
/// contract, as in the multiset test.
#[test]
fn a_parent_cannot_concatenate_a_sequence_that_is_not_the_childs() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(6174);

    let left = seed_sequence(&app, &mut rng, Fp::from(3u64))?;
    let right = seed_sequence(&app, &mut rng, Fp::from(7u64))?;

    // The parent swaps in a different left sequence, output computed
    // honestly *for the substitute* — only the header tie can reject it.
    let substitute = [Fp::from(11u64)];
    let result = app.fuse(
        &mut rng,
        ConcatSequences::new(),
        ConcatSequencesWitness {
            a: app.commit_polynomial(&sequence_polynomial(&substitute))?,
            b: app.commit_polynomial(&sequence_polynomial(&[Fp::from(7u64)]))?,
            output: app
                .commit_polynomial(&sequence_polynomial(&[Fp::from(11u64), Fp::from(7u64)]))?,
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
        "the in-circuit name-vs-header equality must reject a substituted sequence"
    );
    Ok(())
}

/// A claimed concatenation that is not `A ++ B` is rejected at fuse time:
/// the output's claim carries `a(z) + z^{ℓa}·(b(z) − 1)` as its claimed
/// evaluation, and the wrong polynomial does not evaluate to it.
#[test]
fn a_wrong_concatenation_is_rejected() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(2222);

    let left = seed_sequence(&app, &mut rng, Fp::from(3u64))?;
    let right = seed_sequence(&app, &mut rng, Fp::from(7u64))?;

    // The claimed output drops member 7.
    let result = app.fuse(
        &mut rng,
        ConcatSequences::new(),
        ConcatSequencesWitness {
            a: app.commit_polynomial(&sequence_polynomial(&[Fp::from(3u64)]))?,
            b: app.commit_polynomial(&sequence_polynomial(&[Fp::from(7u64)]))?,
            output: app.commit_polynomial(&sequence_polynomial(&[Fp::from(3u64)]))?,
        },
        left,
        right,
    );

    assert!(
        result.is_err(),
        "a concatenation that drops a member must fail to prove"
    );
    Ok(())
}

/// The shared size ceiling, pinned by arithmetic: the rank provides
/// `2^13 = 8192` coefficients and one sits above the last member, so either
/// collection holds at most `8191` members. Constructing at the ceiling
/// works.
#[test]
fn the_collection_ceiling_is_8191_members() {
    assert_eq!(
        <R as Rank>::num_coeffs(),
        8192,
        "the rank's coefficient capacity, spelled out"
    );

    // A ceiling-sized multiset: 4096 + 4095 members merge to degree 8191.
    let a: Vec<Fp> = (1..=4096u64).map(Fp::from).collect();
    let b: Vec<Fp> = (1..=4095u64).map(Fp::from).collect();
    let product = merged_polynomial(&set_polynomial::<Fp, R>(&a), &set_polynomial::<Fp, R>(&b));
    assert_eq!(
        product.eval(Fp::from(4096u64)),
        Fp::ZERO,
        "the ceiling-sized merge is a well-formed set polynomial"
    );

    // A ceiling-sized sequence: 8191 members and the sentinel fill all
    // 8192 coefficients.
    let full: Vec<Fp> = (1..=8191u64).map(Fp::from).collect();
    let seq = sequence_polynomial::<Fp, R>(&full);
    assert_eq!(seq.iter_coeffs().count(), 8192);
}

/// One member past the ceiling fails at construction, before any proving:
/// 8,192 members need 8,193 coefficients.
#[test]
#[should_panic(expected = "exceeds capacity")]
fn one_set_member_past_the_ceiling_fails_at_construction() {
    let members: Vec<Fp> = (1..=8192u64).map(Fp::from).collect();
    let _ = set_polynomial::<Fp, R>(&members);
}

/// The same ceiling for sequences: 8,192 members plus the sentinel need
/// 8,193 coefficients.
#[test]
#[should_panic(expected = "exceeds capacity")]
fn one_sequence_member_past_the_ceiling_fails_at_construction() {
    let members: Vec<Fp> = (1..=8192u64).map(Fp::from).collect();
    let _ = sequence_polynomial::<Fp, R>(&members);
}

/// Builds a balanced fuse tree over `n` singleton seeds (`n` a power of
/// two), printing the average seed time and per-level average fuse time.
fn characterize<H, S, F>(n: u64, mut seed: S, mut fuse: F) -> Result<Pcd<Pasta, R, H>>
where
    H: ragu_pcd::header::Header<Fp>,
    S: FnMut(u64) -> Result<Pcd<Pasta, R, H>>,
    F: FnMut(Pcd<Pasta, R, H>, Pcd<Pasta, R, H>) -> Result<Pcd<Pasta, R, H>>,
{
    let t = std::time::Instant::now();
    let mut nodes = (1..=n).map(&mut seed).collect::<Result<Vec<_>>>()?;
    println!(
        "{n:>4} seeds               | {:>9.2?} avg",
        t.elapsed() / n as u32
    );

    let mut size = 2u64;
    while nodes.len() > 1 {
        let pairs = (nodes.len() / 2) as u32;
        let t = std::time::Instant::now();
        let mut next = Vec::with_capacity(nodes.len() / 2);
        let mut iter = nodes.into_iter();
        while let (Some(a), Some(b)) = (iter.next(), iter.next()) {
            next.push(fuse(a, b)?);
        }
        println!(
            "{pairs:>4} fuses to size {size:>4} | {:>9.2?} avg",
            t.elapsed() / pairs
        );
        nodes = next;
        size *= 2;
    }
    Ok(nodes.pop().expect("n >= 1"))
}

/// Wall-clock characterization: a balanced merge tree over 32 singleton
/// seeds. The fuse circuit shape is identical at every level — the per-fuse
/// time stays flat as the sets double.
///
/// Ignored by default; run explicitly, ideally in release mode:
/// `cargo test -p ragu_pcd --release print_merge_characterization -- --ignored --nocapture`
#[test]
#[ignore = "characterization; run explicitly with --release --nocapture"]
fn print_merge_characterization() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;
    let rng = std::cell::RefCell::new(StdRng::seed_from_u64(1234));

    println!();
    println!("merge tree over 32 singletons");
    let merged: Pcd<Pasta, R, SetHeader<R>> = characterize(
        32,
        |m| seed_set(&app, &mut *rng.borrow_mut(), Fp::from(m)),
        |a, b| fuse_merge(&app, &mut *rng.borrow_mut(), a, b),
    )?;

    let t = std::time::Instant::now();
    assert!(app.verify(&merged, &mut *rng.borrow_mut())?);
    println!("final verify at size 32  | {:>9.2?}", t.elapsed());

    Ok(())
}

/// Wall-clock characterization: a balanced concat tree over 32 singleton
/// seeds, ending in the sequence `[1, 2, .., 32]`.
///
/// Ignored by default; run explicitly, ideally in release mode:
/// `cargo test -p ragu_pcd --release print_concat_characterization -- --ignored --nocapture`
#[test]
#[ignore = "characterization; run explicitly with --release --nocapture"]
fn print_concat_characterization() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;
    let rng = std::cell::RefCell::new(StdRng::seed_from_u64(5678));

    println!();
    println!("concat tree over 32 singletons");
    let out: Pcd<Pasta, R, SeqHeader> = characterize(
        32,
        |m| seed_sequence(&app, &mut *rng.borrow_mut(), Fp::from(m)),
        |a, b| fuse_concat(&app, &mut *rng.borrow_mut(), a, b),
    )?;

    let t = std::time::Instant::now();
    assert!(app.verify(&out, &mut *rng.borrow_mut())?);
    println!("final verify at size 32  | {:>9.2?}", t.elapsed());

    let expected: Vec<Fp> = (1..=32u64).map(Fp::from).collect();
    assert_eq!(out.data().members, expected, "order preserved end to end");

    Ok(())
}
