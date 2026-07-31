//! Characterization tests for multiset merging over set polynomials: what a
//! merge costs, what it proves, and how large it can be.
//!
//! The headline numbers, at `ProductionRank`:
//!
//! * The **merged** set holds at most **8,191 members** — a set of `N`
//!   members is a degree-`N` polynomial with `N + 1` coefficients, and the
//!   rank provides `2^13 = 8192` coefficients.
//! * The step circuit is **`O(1)` in `N`**: three 2-wire names, three
//!   claims, one width-6 challenge, one in-circuit multiplication. Every
//!   size-dependent cost is native — the product FFT, the commitment MSMs,
//!   and the fold.
//! * Downstream consumers see **only the merged set**: the output header
//!   binds `C`'s identity, and the contributing sets never leave the proof.
//!
//! Run the ignored `print_merge_characterization` (ideally with `--release`)
//! for wall-clock numbers across sizes.

use ragu_arithmetic::{
    Cycle,
    ff::Field,
    rand::{SeedableRng, rngs::StdRng},
};
use ragu_circuits::polynomials::{ProductionRank, Rank};
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_testing::pcd::multiset::{
    MergeSets, MergeSetsWitness, merge_app, merged_polynomial, seed_merge, set_polynomial,
};

type R = ProductionRank;

fn members(values: &[u64]) -> Vec<Fp> {
    values.iter().map(|v| Fp::from(*v)).collect()
}

/// An honest merge is witnessed and verified, and the merged polynomial's
/// roots are exactly the members of both sets, multiplicity included.
///
/// The multiset semantics are checked longhand against the carried product:
/// a member shared by both sets is a root of multiplicity two (dividing out
/// one factor still leaves a root), and a non-member is not a root.
#[test]
fn a_merge_is_witnessed_and_verified_with_multiplicity() -> Result<()> {
    let pasta = Pasta::baked();
    let app = merge_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(31415);

    // 5 appears in both sets: the union must keep both copies.
    let a = members(&[3, 5, 11]);
    let b = members(&[5, 7]);
    let merged = seed_merge(&app, pasta, &mut rng, &a, &b)?;

    assert!(app.verify(&merged, &mut rng)?, "the honest merge verifies");

    // Longhand root checks on the carried product, without calling the
    // code under test to produce the expected values.
    let product = &merged.data().product;
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
    // Multiplicity: (X - 5) divides the product twice. Divide out one factor
    // by synthetic division at 5 and check 5 is still a root of the quotient:
    // q(x) = product(x) / (x - 5) evaluated at 6 vs the recomputation... the
    // direct statement is the derivative test: product'(5) == 0 iff 5 is a
    // repeated root. Compute the derivative longhand from the coefficients.
    let coeffs: Vec<Fp> = product.iter_coeffs().collect();
    let mut derivative_at_5 = Fp::ZERO;
    let mut power = Fp::ONE; // 5^(i-1)
    for (i, c) in coeffs.iter().enumerate().skip(1) {
        derivative_at_5 += Fp::from(i as u64) * *c * power;
        power *= Fp::from(5u64);
    }
    assert_eq!(
        derivative_at_5,
        Fp::ZERO,
        "5 appears in both sets, so it is a double root of the merge"
    );

    Ok(())
}

/// A claimed merge that is not the product is rejected at proving: the
/// merged set's claim carries `a(z)·b(z)` as its claimed evaluation, and the
/// wrong polynomial does not evaluate to it (Schwartz–Zippel over the
/// Fiat–Shamir `z`).
#[test]
fn a_wrong_merge_is_rejected() -> Result<()> {
    let pasta = Pasta::baked();
    let app = merge_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(2718);

    let a = members(&[3, 5]);
    let b = members(&[7]);
    // The claimed merge drops member 7.
    let wrong = set_polynomial::<Fp, R>(&members(&[3, 5]));

    let result = app.seed(
        &mut rng,
        MergeSets::new(Pasta::circuit_poseidon(pasta)),
        MergeSetsWitness {
            a: app.commit_polynomial(&set_polynomial(&a))?,
            b: app.commit_polynomial(&set_polynomial(&b))?,
            product: app.commit_polynomial(&wrong)?,
        },
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
    let product = merged_polynomial::<Fp, R>(&a, &b);
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

/// Wall-clock characterization across sizes: how long the native work
/// (product FFT, commitments, proving) and verification take as the merged
/// set grows. The circuit shape is identical at every size — one
/// application serves all of them.
///
/// Ignored by default; run explicitly, ideally in release mode:
/// `cargo test -p ragu_pcd --release print_merge_characterization -- --ignored --nocapture`
#[test]
#[ignore = "characterization; run explicitly with --release --nocapture"]
fn print_merge_characterization() -> Result<()> {
    let pasta = Pasta::baked();
    let app = merge_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(1618);

    println!();
    println!("merged-set size | build+commit | prove (seed) | verify");
    for total in [256u64, 1024, 4096, 8191] {
        let half = total / 2;
        let a: Vec<Fp> = (1..=half).map(Fp::from).collect();
        let b: Vec<Fp> = (half + 1..=total).map(Fp::from).collect();

        let t = std::time::Instant::now();
        let witness = MergeSetsWitness {
            a: app.commit_polynomial(&set_polynomial(&a))?,
            b: app.commit_polynomial(&set_polynomial(&b))?,
            product: app.commit_polynomial(&merged_polynomial(&a, &b))?,
        };
        let build = t.elapsed();

        let t = std::time::Instant::now();
        let (merged, ()) = app.seed(
            &mut rng,
            MergeSets::new(Pasta::circuit_poseidon(pasta)),
            witness,
        )?;
        let prove = t.elapsed();

        let t = std::time::Instant::now();
        assert!(app.verify(&merged, &mut rng)?);
        let verify = t.elapsed();

        println!("{total:>15} | {build:>12.2?} | {prove:>12.2?} | {verify:>6.2?}");
    }

    Ok(())
}
