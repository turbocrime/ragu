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
    ApplicationBuilder::<Pasta, R, HEADER_SIZE, 1, 1>::new()
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
                commitment: com,
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
            commitment: com1,
            x,
            y,
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

/// A derived challenge that is not the hash of the point it was derived from
/// is rejected — directly at root verify, and recursively when the proof is
/// fused as a child.
///
/// This is the check that makes a staged challenge worth anything. The
/// application circuit spends one gate exposing the pair
/// $(\text{point},\, \text{challenge})$ and does *not* hash; if nothing
/// downstream re-derived the challenge, a prover could name any value it liked
/// and grind whatever argument consumes it.
///
/// **What this test does and does not isolate.** The pair is written into the
/// child's application $k(Y)$, so editing a finished proof also breaks the
/// child's revdot claim — the parent would reject this child even without the
/// `challenge_binding` circuit. Isolating that circuit needs an adversary that
/// forges the challenge *at proving time*, so $k(Y)$ stays consistent, which
/// in turn needs a testing seam through `StepCtx::derive_challenge`. That the
/// circuit is load-bearing is established separately and more directly:
/// deliberately mis-deriving the challenge inside it (squeezing twice) makes
/// every honest proof in the suite fail to verify.
#[test]
fn forged_challenge_is_rejected_directly_and_recursively() -> Result<()> {
    let pasta = Pasta::baked();
    let app = open_app()?;
    let mut rng = StdRng::seed_from_u64(99);

    let make_leaf = |rng: &mut StdRng, coeffs: &[u64]| -> Result<_> {
        let p = poly(coeffs);
        let com = app.commit_polynomial(&p)?;
        let (leaf, ()) = app.seed(
            rng,
            CommitAndOpen::new(Pasta::circuit_poseidon(pasta)),
            CommitAndOpenWitness {
                commitment: com,
                claimed_y: None,
            },
        )?;
        Ok(leaf)
    };

    let honest = make_leaf(&mut rng, &[3, 1, 4, 1, 5])?;
    assert!(app.verify(&honest, &mut rng)?);

    // Keep the point, change the challenge.
    let mut forged = honest;
    forged.corrupt(Corruption::ChallengeValue(0, Fp::from(1u64)));
    assert!(
        !app.verify(&forged, &mut rng)?,
        "root verify must reject a challenge that is not its point's hash"
    );

    // Fused as a child, `challenge_binding` re-derives the challenge from the
    // point and enforces the pair, so the parent cannot be produced.
    let leaf2 = make_leaf(&mut rng, &[2, 7, 1, 8])?;
    let p3 = poly(&[5, 5, 5]);
    let com3 = app.commit_polynomial(&p3)?;
    let x = Fp::from(11u64);
    let y = p3.eval(x);

    let fused = app.fuse(
        &mut rng,
        OpenAndHash::new(Pasta::circuit_poseidon(pasta)),
        OpenAndHashWitness {
            commitment: com3,
            x,
            y,
        },
        forged,
        leaf2,
    );

    match fused {
        Err(e) => std::eprintln!("interior fuse rejected the forged challenge: {e:?}"),
        Ok((parent, ())) => {
            assert!(
                !app.verify(&parent, &mut rng)?,
                "a parent of a forged-challenge child must not verify"
            );
        }
    }

    Ok(())
}

/// **S1 — the claim commitment is not bound to the folded polynomial.**
///
/// A claim's instance-bound `com` is what the *step* sees: its Fiat-Shamir
/// challenge and header hash are derived from it. The polynomial the *parent*
/// folds into `f(X)` and the PCS accumulator is carried separately, under its
/// own host-curve commitment. Every piece is individually pinned — `com` by
/// the child's `k(Y)`, the host commitment by `copying` against the child's
/// eval bridge stage, and the fold by `loading`/endoscaling — but nothing ties
/// `com` to the host commitment except a prover-side pre-check that the code
/// itself documents as carrying no soundness weight.
///
/// So the adversary is a prover who declines to run that pre-check and hands
/// in a child that is internally consistent everywhere, desynced only between
/// `com` (which commits to `P`) and the carried polynomial `P'`. The step's
/// challenge `z` is bound to `P`, yet the statement the parent enforces is
/// about `P'`.
///
/// Root verification catches this (`verify.rs` re-derives `bridge(host)` and
/// compares it to `com`). An interior fuse does not — that is the gap.
#[test]
fn poly_query_com_is_not_bound_to_the_folded_polynomial() -> Result<()> {
    use ragu_pcd::PolyCommitment;

    let pasta = Pasta::baked();
    // A prover that simply does not run the fuse-time pre-check.
    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE, 1, 1>::new()
        .register(CommitAndOpen::<Pasta, R>::new(Pasta::circuit_poseidon(
            pasta,
        )))?
        .register(OpenAndHash::<Pasta, R>::new(Pasta::circuit_poseidon(pasta)))?
        .skip_claim_precheck_for_testing()
        .finalize(pasta)?;
    let mut rng = StdRng::seed_from_u64(2024);

    // `com` commits to P, but the claim carries P'. Both are honest-looking:
    // the step derives z from com (so z is bound to P) and claims y = P'(z).
    let p = poly(&[3, 1, 4, 1, 5]);
    let p_prime = poly(&[9, 2, 6]);
    assert_ne!(p.eval(Fp::from(7u64)), p_prime.eval(Fp::from(7u64)));
    // The handle's host commitment is P's, but its polynomial is P'. The
    // framework derives `com` from the host, so the step's challenge is bound
    // to P while the parent folds P'.
    let host_of_p =
        p.commit_to_affine::<<Pasta as Cycle>::HostCurve>(Pasta::host_generators(pasta));
    let desynced = PolyCommitment::<Pasta, R>::desync_for_testing(p_prime.clone(), host_of_p);

    let (cheat, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(Pasta::circuit_poseidon(pasta)),
        CommitAndOpenWitness {
            commitment: desynced,
            claimed_y: None,
        },
    )?;

    // The claim really is desynced: com commits to P, the carried poly is P'.
    let claim = cheat.proof().application_claims()[0];
    assert_eq!(
        claim.y,
        p_prime.eval(claim.x),
        "but the claimed opening is of P'"
    );
    assert_ne!(claim.y, p.eval(claim.x), "P and P' disagree at z");

    // The root verifier checks the bridge, so it rejects.
    assert!(
        !app.verify(&cheat, &mut rng)?,
        "root verify must reject a claim whose com does not bridge its host"
    );

    // Fused as a child, the desync goes unnoticed.
    let p2 = poly(&[2, 7, 1, 8]);
    let com2 = app.commit_polynomial(&p2)?;
    let (leaf2, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(Pasta::circuit_poseidon(pasta)),
        CommitAndOpenWitness {
            commitment: com2,
            claimed_y: None,
        },
    )?;

    let p3 = poly(&[5, 5, 5]);
    let com3 = app.commit_polynomial(&p3)?;
    let x = Fp::from(11u64);
    let y = p3.eval(x);
    let fused = app.fuse(
        &mut rng,
        OpenAndHash::new(Pasta::circuit_poseidon(pasta)),
        OpenAndHashWitness {
            commitment: com3,
            x,
            y,
        },
        cheat,
        leaf2,
    );

    match fused {
        Err(e) => std::eprintln!("interior fuse rejected the desync: {e:?}"),
        Ok((parent, ())) => {
            let verified = app.verify(&parent, &mut rng)?;
            // `com` is now the commitment of the claim's bridge stage, which
            // the proof carries and whose wires `loading` ties to the folded
            // host commitment -- parity with `bridge_f`. What is still missing
            // is the link from any commitment to the polynomial it commits to,
            // i.e. the framework-wide deferred PCS opening, which no
            // commitment in the system has yet. So a prover can still carry a
            // bridge rx that disagrees with `com`. Invert this assertion when
            // the nested-side PCS lands.
            assert!(
                verified,
                "expected the unsound status quo: a parent of a desynced-claim \
                 child still verifies. If this now fails, the binding has landed \
                 -- invert this assertion."
            );
            std::eprintln!(
                "S1 CONFIRMED: parent verified a claim whose com does not commit \
                 to the polynomial that was folded."
            );
        }
    }

    Ok(())
}
