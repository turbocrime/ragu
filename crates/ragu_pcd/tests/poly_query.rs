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

/// The full oracle loop with honest witnesses: seed, cross-step opening via
/// fuse, verify. Declared at `POLYS = 1, CLAIMS = 2` so the repeat opening
/// must spend a claim slot, not a polynomial slot, or `seed` would fail.
#[test]
fn oracle_end_to_end() -> Result<()> {
    let pasta = Pasta::baked();
    let app = open_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(1234);

    let p1 = poly(&[3, 1, 4, 1, 5]);
    let com1 = app.commit_polynomial(&p1)?;
    let (leaf1, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            commitment: com1.clone(),
            polynomial: p1.clone(),
            claimed_y: None,
        },
    )?;
    assert!(app.verify(&leaf1, &mut rng)?);

    let leaf2 = seed_leaf(&app, pasta, &mut rng, &[2, 7, 1, 8, 2, 8])?;

    // `com1` is the same handle the leaf witnessed: a cross-step opening.
    let x = Fp::from(9u64);
    let y = p1.eval(x);
    let (node, ()) = app.fuse(
        &mut rng,
        OpenAndHash::new(Pasta::circuit_poseidon(pasta)),
        OpenAndHashWitness {
            commitment: com1,
            polynomial: p1.clone(),
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
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            commitment,
            polynomial: p.clone(),
            claimed_y: Some(Fp::from(42u64)),
        },
    );
    assert!(
        matches!(result, Err(Error::InvalidWitness(_))),
        "expected InvalidWitness",
    );
    Ok(())
}
