//! End-to-end tests for the polynomial-query oracle: witnessing a polynomial
//! in a step, deriving challenges, evaluating, and enforcing evaluations —
//! through seed/fuse/verify on the real pipeline.

use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::{ProductionRank, sparse};
use ragu_core::{Error, Result};
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::ApplicationBuilder;
use ragu_testing::pcd::poly_query::{
    CommitAndOpen, CommitAndOpenWitness, OpenAndHash, OpenAndHashWitness,
};
use rand::{SeedableRng, rngs::StdRng};

type R = ProductionRank;
const HEADER_SIZE: usize = 4;

fn poly(coeffs: &[u64]) -> sparse::Polynomial<Fp, R> {
    sparse::Polynomial::from_coeffs(coeffs.iter().map(|c| Fp::from(*c)).collect())
}

fn open_app() -> Result<ragu_pcd::Application<'static, Pasta, R, HEADER_SIZE>> {
    let pasta = Pasta::baked();
    ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register(CommitAndOpen::<Pasta, R>::new(Pasta::circuit_poseidon(
            pasta,
        )))?
        .register(OpenAndHash::<Pasta, R>::new(Pasta::circuit_poseidon(pasta)))?
        .finalize(pasta)
}

/// The full oracle loop, honest witness: a leaf witnesses a polynomial and its
/// framework commitment, derives a challenge bound to the commitment,
/// evaluates at it, and enforces the evaluation; a merge step opens the same
/// polynomial at a chosen point. Both proofs verify, and the claim instances
/// are persisted in the proofs.
#[test]
fn oracle_end_to_end() -> Result<()> {
    let pasta = Pasta::baked();
    let app = open_app()?;
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
    // All claim slots are present (unused slots hold the padding claim);
    // the step's real claim occupies slot 0.
    assert_eq!(
        leaf1.proof().application_claims().len(),
        ragu_pcd::NUM_POLY_QUERY_SLOTS
    );
    let claim0 = leaf1.proof().application_claims()[0];
    assert_eq!(claim0.com, com1.commitment());
    assert_eq!(claim0.y, p1.eval(claim0.x));

    let p2 = poly(&[2, 7, 1, 8, 2, 8]);
    let com2 = app.commit_polynomial(&p2)?;
    let (leaf2, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(Pasta::circuit_poseidon(pasta)),
        CommitAndOpenWitness {
            commitment: com2,
            claimed_y: None,
        },
    )?;

    // Merge the two leaves, opening p1 at a chosen point with an honest
    // evaluation.
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
    assert_eq!(
        node.proof().application_claims().len(),
        ragu_pcd::NUM_POLY_QUERY_SLOTS
    );

    Ok(())
}

/// A dishonest evaluation claim (y != p(z)) is rejected at fuse time with
/// `InvalidWitness`.
#[test]
fn dishonest_evaluation_is_rejected() -> Result<()> {
    let pasta = Pasta::baked();
    let app = open_app()?;
    let mut rng = StdRng::seed_from_u64(1234);

    let p = poly(&[3, 1, 4, 1, 5]);
    let com = app.commit_polynomial(&p)?;
    let result = app.seed(
        &mut rng,
        CommitAndOpen::new(Pasta::circuit_poseidon(pasta)),
        CommitAndOpenWitness {
            commitment: com,
            claimed_y: Some(Fp::from(42u64)),
        },
    );
    assert!(
        matches!(result, Err(Error::InvalidWitness(_))),
        "expected InvalidWitness",
    );
    Ok(())
}

// The old `mismatched_commitment_is_rejected` test constructed a witness whose
// commitment bound one polynomial and whose coefficients were another. The
// `PolyCommitment` handle from `commit_polynomial` now bundles the two, so an
// honest caller can no longer express that mismatch through the API. The
// interior malicious-prover version of this case is covered by the poly-query
// binding (S1) test on the enforcement path.

// The multiset merge end-to-end test lived here; `Multiset`/`MergeMultisets`
// were a consumer concern and have been removed. The framework's poly-query
// path is exercised by the `CommitAndOpen`/`OpenAndHash` tests above and by
// `recursive_claims.rs`.
