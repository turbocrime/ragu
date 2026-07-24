//! Recursive enforcement of poly-query claims: a dishonest claim instance
//! that bypasses the honest prover's fuse-time pre-check (simulated by
//! corrupting a child proof) is rejected by the circuits — directly at root
//! verify, and recursively when the corrupted proof is fused as a child.
//!
//! Requires the `unstable-fuzzing` feature for the proof-corruption helpers:
//!
//! ```text
//! cargo test -p ragu_pcd --features unstable-fuzzing --test recursive_claims
//! ```

#![cfg(feature = "unstable-fuzzing")]

use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::{ProductionRank, sparse};
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::{ApplicationBuilder, fuzz_utils::Corruption};
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

/// Corrupting a proof's claim instance (as a malicious prover who skips the
/// native pre-check would) makes the proof fail root verification, and makes
/// any parent fuse of that proof fail to produce a verifying proof.
#[test]
fn corrupted_claim_is_rejected_directly_and_recursively() -> Result<()> {
    let pasta = Pasta::baked();
    let app = open_app()?;
    let mut rng = StdRng::seed_from_u64(1234);

    let make_leaf = |rng: &mut StdRng, coeffs: &[u64]| -> Result<_> {
        let p = poly(coeffs);
        let com = app.commit_polynomial(&p)?;
        let (leaf, ()) = app.seed(
            rng,
            CommitAndOpen::new(Pasta::circuit_poseidon(pasta)),
            CommitAndOpenWitness {
                com,
                polynomial: p,
                claimed_y: None,
            },
        )?;
        Ok(leaf)
    };

    // An honest leaf verifies.
    let leaf1 = make_leaf(&mut rng, &[3, 1, 4, 1, 5])?;
    assert!(app.verify(&leaf1, &mut rng)?);

    // Corrupt the claimed evaluation in slot 0. Root verification rejects it:
    // the carried claim polynomial no longer evaluates to the claimed y.
    let mut corrupted_leaf = leaf1;
    corrupted_leaf.corrupt(Corruption::ClaimY(0, Fp::from(1u64)));
    assert!(
        !app.verify(&corrupted_leaf, &mut rng)?,
        "root verify must reject a corrupted claim instance"
    );

    // Fuse the corrupted leaf with an honest one. The parent's circuits bind
    // the child's claim instances via the application k(Y) and enforce the
    // claim quotients in compute_v, so the parent either fails to fuse or
    // produces a proof that does not verify.
    let leaf2 = make_leaf(&mut rng, &[2, 7, 1, 8, 2, 8])?;
    let p1 = poly(&[3, 1, 4, 1, 5]);
    let com1 = app.commit_polynomial(&p1)?;
    let x = Fp::from(9u64);
    let y = p1.eval(x);

    let fused = app.fuse(
        &mut rng,
        OpenAndHash::new(Pasta::circuit_poseidon(pasta)),
        OpenAndHashWitness {
            com: com1,
            x,
            y,
            polynomial: p1,
        },
        corrupted_leaf,
        leaf2,
    );
    match fused {
        Err(e) => std::eprintln!("fuse rejected natively: {e:?}"),
        Ok((parent, ())) => {
            std::eprintln!("fuse produced a proof; checking verify...");
            assert!(
                !app.verify(&parent, &mut rng)?,
                "a parent of a corrupted-claim child must not verify"
            );
        }
    }

    Ok(())
}
