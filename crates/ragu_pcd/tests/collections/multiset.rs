//! Characterization tests for multiset merging over set polynomials, in the
//! real PCD shape: two [`SeedSet`] leaves establish initial sets whose names
//! ride their headers, and a [`MergeSets`] **fuse** binds its witnessed
//! inputs to those header-carried names in-circuit before proving the
//! product — the cross-proof identity check, end to end.
//!
//! The headline numbers, at `ProductionRank`:
//!
//! * The **merged** set holds at most **8,191 members** — a set of `N`
//!   members is a degree-`N` polynomial, and the rank provides `2^13 = 8192`
//!   coefficients.
//! * The merge circuit is **`O(1)` in `N`**: three 2-wire names, four
//!   cross-proof equalities, three claims, one challenge, one
//!   multiplication. Every size-dependent cost is native.
//! * Downstream consumers see **only the merged set**: the output header
//!   carries `C`'s name alone.
//!
//! Run the ignored `print_merge_characterization` (ideally with `--release`)
//! for wall-clock numbers across sizes.
//!
//! [`SeedSet`]: ragu_testing::pcd::collections::multiset::SeedSet
//! [`MergeSets`]: ragu_testing::pcd::collections::multiset::MergeSets

use ragu_arithmetic::{
    ff::Field,
    rand::{SeedableRng, rngs::StdRng},
};
use ragu_circuits::polynomials::Rank;
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_testing::pcd::collections::{
    collections_app,
    multiset::{
        MergeSets, MergeSetsWitness, fuse_merge, merged_polynomial, seed_set, set_polynomial,
    },
};

use crate::{R, members};

/// Two seeded sets fuse into their merge, the parent verifies, and the
/// merged polynomial's roots are exactly the members of both sets,
/// multiplicity included.
#[test]
fn seeded_sets_fuse_into_their_merge() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(31415);

    // 5 appears in both sets: the union must keep both copies.
    let left = seed_set(&app, &mut rng, &members(&[3, 5, 11]))?;
    let right = seed_set(&app, &mut rng, &members(&[5, 7]))?;
    assert!(app.verify(&left, &mut rng)?, "the left seed verifies");
    assert!(app.verify(&right, &mut rng)?, "the right seed verifies");

    let merged = fuse_merge(&app, &mut rng, left, right)?;
    assert!(app.verify(&merged, &mut rng)?, "the merge verifies");

    // Longhand root checks on the carried product, without calling the code
    // under test to produce the expected values.
    let product = &merged.data().polynomial;
    for m in [3u64, 5, 7, 11] {
        assert_eq!(
            product.eval(Fp::from(m)),
            Fp::ZERO,
            "every member of either set is a root of the merge"
        );
    }
    assert_ne!(
        product.eval(Fp::from(13u64)),
        Fp::ZERO,
        "a non-member is not a root"
    );
    // Multiplicity: 5 appears in both sets, so it is a repeated root of the
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

    let left = seed_set(&app, &mut rng, &members(&[3, 5]))?;
    let right = seed_set(&app, &mut rng, &members(&[7]))?;

    // The parent swaps in a different left set, product computed honestly
    // *for the substitute* — every claim is internally consistent; only the
    // header tie can reject it.
    let substitute = set_polynomial::<Fp, R>(&members(&[11]));
    let b = set_polynomial::<Fp, R>(&members(&[7]));
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

    let left = seed_set(&app, &mut rng, &members(&[3, 5]))?;
    let right = seed_set(&app, &mut rng, &members(&[7]))?;

    // The claimed merge drops member 7.
    let result = app.fuse(
        &mut rng,
        MergeSets::new(),
        MergeSetsWitness {
            a: app.commit_polynomial(&set_polynomial(&members(&[3, 5])))?,
            b: app.commit_polynomial(&set_polynomial(&members(&[7])))?,
            product: app.commit_polynomial(&set_polynomial(&members(&[3, 5])))?,
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

/// The size ceiling, pinned by arithmetic: the rank provides `2^13 = 8192`
/// coefficients, so the largest representable multiset — merged or not —
/// has `8191` members. Constructing at the ceiling works.
#[test]
fn the_merged_set_ceiling_is_8191_members() {
    assert_eq!(
        <R as Rank>::num_coeffs(),
        8192,
        "the rank's coefficient capacity, spelled out"
    );

    // 4096 + 4095 members merge to exactly the ceiling: degree 8191,
    // 8192 coefficients.
    let a: Vec<Fp> = (1..=4096u64).map(Fp::from).collect();
    let b: Vec<Fp> = (1..=4095u64).map(Fp::from).collect();
    let product = merged_polynomial(&set_polynomial::<Fp, R>(&a), &set_polynomial::<Fp, R>(&b));
    assert_eq!(
        product.eval(Fp::from(4096u64)),
        Fp::ZERO,
        "the ceiling-sized merge is a well-formed set polynomial"
    );
}

/// One member past the ceiling fails at construction, before any proving:
/// 8,192 members need 8,193 coefficients.
#[test]
#[should_panic(expected = "exceeds capacity")]
fn one_member_past_the_ceiling_fails_at_construction() {
    let members: Vec<Fp> = (1..=8192u64).map(Fp::from).collect();
    let _ = set_polynomial::<Fp, R>(&members);
}

/// Wall-clock characterization across sizes: seed the two halves, fuse, and
/// verify as the merged set grows. The circuit shapes are identical at
/// every size — one application serves all of them.
///
/// Ignored by default; run explicitly, ideally in release mode:
/// `cargo test -p ragu_pcd --release print_merge_characterization -- --ignored --nocapture`
#[test]
#[ignore = "characterization; run explicitly with --release --nocapture"]
fn print_merge_characterization() -> Result<()> {
    let pasta = Pasta::baked();
    let app = collections_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(1234);

    println!();
    println!("merged-set size | seed left | seed right | fuse merge | verify");
    for total in [256u64, 1024, 4096, 8191] {
        let half = total / 2;
        let a: Vec<Fp> = (1..=half).map(Fp::from).collect();
        let b: Vec<Fp> = (half + 1..=total).map(Fp::from).collect();

        let t = std::time::Instant::now();
        let left = seed_set(&app, &mut rng, &a)?;
        let seed_left = t.elapsed();
        let t = std::time::Instant::now();
        let right = seed_set(&app, &mut rng, &b)?;
        let seed_right = t.elapsed();

        let t = std::time::Instant::now();
        let merged = fuse_merge(&app, &mut rng, left, right)?;
        let fuse = t.elapsed();

        let t = std::time::Instant::now();
        assert!(app.verify(&merged, &mut rng)?);
        let verify = t.elapsed();

        println!(
            "{total:>15} | {seed_left:>9.2?} | {seed_right:>10.2?} | {fuse:>10.2?} | {verify:>6.2?}"
        );
    }

    Ok(())
}
