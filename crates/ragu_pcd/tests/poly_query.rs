//! End-to-end tests for the polynomial-query oracle: witnessing a polynomial
//! in a step, deriving challenges, evaluating, and enforcing evaluations —
//! through seed/fuse/verify on the real pipeline.

use ragu_arithmetic::{Cycle, ff::Field};
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{Error, Result};
use ragu_pasta::{Fp, Pasta};
use ragu_testing::pcd::poly_query::{
    CommitAndOpen, CommitAndOpenWitness, OpenAndHash, OpenAndHashWitness, open_app, poly, seed_leaf,
};
use rand::{SeedableRng, rngs::StdRng};

type R = ProductionRank;

/// The full oracle loop, honest witness: a leaf witnesses a polynomial and its
/// framework commitment, derives a challenge bound to the commitment,
/// evaluates at it, and enforces the evaluation; a merge step opens the same
/// polynomial at a chosen point. Both proofs verify, and the claim instances
/// are persisted in the proofs.
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
    // Every claim slot the application has is present. The counts are the
    // application's *declared* capacity, not a framework constant: this
    // application declares two claims over one polynomial, and this step opens
    // that polynomial at two points — which is the whole point of splitting the
    // two counts, and is what the recursion is sized for.
    assert_eq!(leaf1.proof().application_claims().len(), 2);
    assert_eq!(leaf1.proof().application_polys().len(), 1);
    // `bridge_com` is derived by the framework from the claim's bridge stage once the
    // slot is known, so the test cannot recompute it; the opening is what the
    // claim asserts.
    let claim0 = leaf1.proof().application_claims()[0];
    assert_eq!(claim0.y, p1.eval(claim0.x));

    // A claim names its polynomial by bridge commitment, and it is the *same*
    // commitment the polynomial slot carries — not a second copy.
    assert_eq!(
        claim0.bridge_com,
        leaf1.proof().application_polys()[0],
        "a claim should carry its polynomial's own bridge commitment"
    );

    // The step opened one polynomial twice, and both claims carry the *same*
    // commitment — a repeat opening spends a query slot, not a polynomial slot.
    // This is the whole point of separating the two counts: had the second
    // opening needed its own polynomial, it would sit in slot 1 and carry a
    // second bridge stage, commitment and MSM.
    let claim1 = leaf1.proof().application_claims()[1];
    assert_eq!(
        claim1.bridge_com, claim0.bridge_com,
        "a repeat opening should reuse its polynomial's bridge commitment"
    );
    assert_eq!(claim1.x, Fp::ZERO, "the repeat opens at x = 0");
    assert_eq!(claim1.y, p1.eval(claim1.x));

    let leaf2 = seed_leaf(&app, pasta, &mut rng, &[2, 7, 1, 8, 2, 8])?;

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
    // The fusing step raises no claims of its own, so its proof carries the
    // application's capacity in padding claims — the uniform instance shape
    // every internal circuit reads.
    assert_eq!(node.proof().application_claims().len(), 2);

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
