//! End-to-end tests for the polynomial-query oracle: witnessing a polynomial
//! in a step, deriving challenges, evaluating, and enforcing evaluations —
//! through seed/fuse/verify on the real pipeline.

use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{Error, Result};
use ragu_pasta::{Fp, Pasta};
use ragu_testing::pcd::poly_query::{
    CommitAndOpen, CommitAndOpenWitness, OpenAndHash, OpenAndHashWitness, open_app, poly, seed_leaf,
};
use rand::{SeedableRng, rngs::StdRng};

type R = ProductionRank;

/// The full oracle loop, honest witness: a leaf witnesses a polynomial and its
/// framework commitment, derives a challenge bound to the commitment, evaluates
/// at it, and enforces the evaluation; a merge step then opens the *same*
/// polynomial at a chosen point. Both proofs verify.
///
/// `verify` is the whole assertion, and it is a strong one. For a root proof it
/// checks natively what no parent has bound yet — see the claim and challenge
/// blocks in `src/verify.rs`: that every slot list has the declared
/// length, that each claim's commitment names one of the polynomial slots and
/// that polynomial really evaluates to the claimed `y` at the claimed `x`, that
/// each carried polynomial commits to its recorded host commitment, and that
/// commitment bridges to the instance-bound nested one. So reading the claim
/// slots back here to re-assert any of it would restate the verifier against the
/// very proof it just accepted.
///
/// Two framework properties are pinned by the *shape this runs at* rather than by
/// an assertion, which is why the app is declared `POLYS = 1, CLAIMS = 2`:
///
/// - **A repeat opening spends a claim slot, not a polynomial slot.**
///   `CommitAndOpen` opens one handle twice. There is no second polynomial slot
///   to spend, so had the repeat needed one — a second bridge stage, commitment
///   and MSM — `seed` would have failed outright.
/// - **A fusing step that raises no claims still carries the full capacity.**
///   `OpenAndHash` raises one claim of its own, and `verify` requires two claim
///   slots regardless, filled with the canonical padding claim. That uniform
///   instance shape is what every internal circuit reads.
///
/// The dishonest directions are covered where an assertion can actually fail:
/// `dishonest_evaluation_is_rejected` below, and `tests/recursive_claims.rs` for
/// the recursive and desync cases.
#[test]
fn oracle_end_to_end() -> Result<()> {
    let pasta = Pasta::baked();
    let app = open_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(1234);

    let p1 = poly(&[3, 1, 4, 1, 5]);
    let com1 = app.commit_polynomial(&p1)?;
    let (leaf1, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(Pasta::circuit_poseidon(pasta)),
        CommitAndOpenWitness {
            commitment: com1.clone(),
            claimed_y: None,
        },
    )?;
    assert!(app.verify(&leaf1, &mut rng)?);

    let leaf2 = seed_leaf(&app, pasta, &mut rng, &[2, 7, 1, 8, 2, 8])?;

    // Merge the two leaves, opening p1 at a chosen point with an honest
    // evaluation. The commitment handed in is `com1` — the same handle the leaf
    // witnessed — so this is a *cross-step* opening of one polynomial.
    let x = Fp::from(9u64);
    let y = p1.eval(x);
    let (node, ()) = app.fuse(
        &mut rng,
        OpenAndHash::new(Pasta::circuit_poseidon(pasta)),
        OpenAndHashWitness {
            commitment: com1,
            x,
            y,
        },
        leaf1,
        leaf2,
    )?;
    assert!(app.verify(&node, &mut rng)?);

    Ok(())
}

/// A dishonest evaluation claim (y != p(z)) is rejected at fuse time with
/// `InvalidWitness`.
#[test]
fn dishonest_evaluation_is_rejected() -> Result<()> {
    let pasta = Pasta::baked();
    let app = open_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(1234);

    let p = poly(&[3, 1, 4, 1, 5]);
    let commitment = app.commit_polynomial(&p)?;
    let result = app.seed(
        &mut rng,
        CommitAndOpen::new(Pasta::circuit_poseidon(pasta)),
        CommitAndOpenWitness {
            commitment,
            claimed_y: Some(Fp::from(42u64)),
        },
    );
    assert!(
        matches!(result, Err(Error::InvalidWitness(_))),
        "expected InvalidWitness",
    );
    Ok(())
}
