//! End-to-end tests for the polynomial-query oracle: witnessing a polynomial
//! in a step, deriving challenges, evaluating, and enforcing evaluations —
//! through seed/fuse/verify on the real pipeline.

use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::{ProductionRank, sparse};
use ragu_core::{Error, Result};
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::ApplicationBuilder;
use ragu_testing::pcd::{
    merge_multisets::{MergeMultisets, WitnessMultiset, WitnessMultisetWitness},
    poly_query::{CommitAndOpen, CommitAndOpenWitness, OpenAndHash, OpenAndHashWitness},
};
use rand::{SeedableRng, rngs::StdRng};

type R = ProductionRank;
const HEADER_SIZE: usize = 4;

fn poly(coeffs: &[u64]) -> sparse::Polynomial<Fp, R> {
    sparse::Polynomial::from_coeffs(coeffs.iter().map(|c| Fp::from(*c)).collect())
}

fn open_app() -> Result<ragu_pcd::Application<'static, Pasta, R, HEADER_SIZE>> {
    let pasta = Pasta::baked();
    ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new(pasta)
        .register(CommitAndOpen::<Pasta, R>::new(Pasta::circuit_poseidon(
            pasta,
        )))?
        .register(OpenAndHash::<Pasta, R>::new(Pasta::circuit_poseidon(pasta)))?
        .finalize()
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
            com: com1,
            polynomial: p1.clone(),
            claimed_y: None,
        },
    )?;
    assert!(app.verify(&leaf1, &mut rng)?);
    assert_eq!(leaf1.proof().application_claims().len(), 1);
    let (claim_com, _z, claim_y) = leaf1.proof().application_claims()[0];
    assert_eq!(claim_com, com1);
    assert_eq!(claim_y, p1.eval(leaf1.proof().application_claims()[0].1));

    let p2 = poly(&[2, 7, 1, 8, 2, 8]);
    let com2 = app.commit_polynomial(&p2)?;
    let (leaf2, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(Pasta::circuit_poseidon(pasta)),
        CommitAndOpenWitness {
            com: com2,
            polynomial: p2.clone(),
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
            com: com1,
            x,
            y,
            polynomial: p1.clone(),
        },
        leaf1,
        leaf2,
    )?;
    assert!(app.verify(&node, &mut rng)?);
    assert_eq!(node.proof().application_claims().len(), 1);

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
            com,
            polynomial: p,
            claimed_y: Some(Fp::from(42u64)),
        },
    );
    assert!(
        matches!(result, Err(Error::InvalidWitness(_))),
        "expected InvalidWitness",
    );
    Ok(())
}

/// A commitment that does not bind the claimed polynomial is rejected at fuse
/// time with `InvalidWitness`.
#[test]
fn mismatched_commitment_is_rejected() -> Result<()> {
    let pasta = Pasta::baked();
    let app = open_app()?;
    let mut rng = StdRng::seed_from_u64(1234);

    let p = poly(&[3, 1, 4, 1, 5]);
    let other = poly(&[2, 7, 1, 8]);
    let wrong_com = app.commit_polynomial(&other)?;
    let result = app.seed(
        &mut rng,
        CommitAndOpen::new(Pasta::circuit_poseidon(pasta)),
        CommitAndOpenWitness {
            com: wrong_com,
            polynomial: p,
            claimed_y: None,
        },
    );
    assert!(
        matches!(result, Err(Error::InvalidWitness(_))),
        "expected InvalidWitness",
    );
    Ok(())
}

/// Multiset merge end-to-end: two leaves carry multisets; the merge step
/// derives a Schwartz–Zippel challenge from the framework (no sponge in the
/// step body), evaluates all three polynomials at it, and enforces the three
/// openings. The fused proof verifies and persists three claim instances.
#[test]
fn multiset_merge_end_to_end() -> Result<()> {
    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new(pasta)
        .register(WitnessMultiset::<Pasta, R>::new())?
        .register(MergeMultisets::<Pasta, R>::new())?
        .finalize()?;
    let mut rng = StdRng::seed_from_u64(5678);

    let a = poly(&[1, 2, 3]);
    let b = poly(&[4, 0, 5]);
    let a_com = app.commit_polynomial(&a)?;
    let b_com = app.commit_polynomial(&b)?;

    let (left, ()) = app.seed(
        &mut rng,
        WitnessMultiset::new(),
        WitnessMultisetWitness {
            commitment: a_com,
            polynomial: a.clone(),
        },
    )?;
    assert!(app.verify(&left, &mut rng)?);
    let (right, ()) = app.seed(
        &mut rng,
        WitnessMultiset::new(),
        WitnessMultisetWitness {
            commitment: b_com,
            polynomial: b.clone(),
        },
    )?;

    // The product polynomial and its commitment, supplied by the prover.
    // (`iter_coeffs` pads to the rank's capacity; trim before multiplying.)
    let product = {
        let trimmed = |p: &sparse::Polynomial<Fp, R>| {
            let mut coeffs: Vec<Fp> = p.iter_coeffs().collect();
            while coeffs
                .last()
                .is_some_and(|c| bool::from(ff::Field::is_zero(c)))
            {
                coeffs.pop();
            }
            coeffs
        };
        let mut out = Vec::new();
        ragu_arithmetic::poly_mul(&trimmed(&a), &trimmed(&b), &mut out);
        sparse::Polynomial::<Fp, R>::from_coeffs(out)
    };
    let product_com = app.commit_polynomial(&product)?;

    let (merged, ()) = app.fuse(&mut rng, MergeMultisets::new(), product_com, left, right)?;
    assert!(app.verify(&merged, &mut rng)?);
    assert_eq!(merged.proof().application_claims().len(), 3);
    assert_eq!(merged.data().commitment, product_com);

    // A dishonest product commitment (not binding the product polynomial) is
    // rejected: the framework's native claim check catches it even though the
    // in-circuit Schwartz–Zippel identity still holds.
    let (left2, ()) = app.seed(
        &mut rng,
        WitnessMultiset::new(),
        WitnessMultisetWitness {
            commitment: a_com,
            polynomial: a.clone(),
        },
    )?;
    let (right2, ()) = app.seed(
        &mut rng,
        WitnessMultiset::new(),
        WitnessMultisetWitness {
            commitment: b_com,
            polynomial: b.clone(),
        },
    )?;
    let result = app.fuse(&mut rng, MergeMultisets::new(), a_com, left2, right2);
    assert!(
        matches!(result, Err(Error::InvalidWitness(_))),
        "expected InvalidWitness, got wrong-commitment fuse result",
    );

    Ok(())
}
