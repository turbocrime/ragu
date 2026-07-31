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
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::fuzz_utils::Corruption;
use ragu_testing::pcd::poly_query::{
    CommitAndOpen, CommitAndOpenWitness, OpenAndHash, OpenAndHashWitness, open_app,
    open_app_builder, poly, seed_leaf,
};
use rand::{SeedableRng, rngs::StdRng};

type R = ProductionRank;

/// Corrupting a proof's claim instance (as a malicious prover who skips the
/// native pre-check would) makes the proof fail root verification, and makes
/// any parent fuse of that proof fail to produce a verifying proof.
#[test]
fn corrupted_claim_is_rejected_directly_and_recursively() -> Result<()> {
    let pasta = Pasta::baked();
    let app = open_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(1234);

    // An honest leaf verifies.
    let leaf1 = seed_leaf(&app, pasta, &mut rng, &[3, 1, 4, 1, 5])?;
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
    let leaf2 = seed_leaf(&app, pasta, &mut rng, &[2, 7, 1, 8, 2, 8])?;
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
    let app = open_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(99);

    let honest = seed_leaf(&app, pasta, &mut rng, &[3, 1, 4, 1, 5])?;
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
    let leaf2 = seed_leaf(&app, pasta, &mut rng, &[2, 7, 1, 8])?;
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

/// **S2 — `loading` does not enforce the claim-bridge binding.**
///
/// A regression test for a defect this branch introduced in `68cde75a`, not a
/// deferred framework gap.
///
/// `loading` configures the eval stage and the claim-bridge run and enforces
/// `claim_bridges[slot].host == eval.claims[slot]` — the constraint whose own
/// comment calls it *"what makes `bridge_com` bound to that host commitment"*.
/// But a bonding claim asserts `a.revdot(s_y) == 0` over the **sum of the rxs
/// supplied**, and the `Loading` group in `internal/nested/claims.rs` supplies
/// only the seven rxs `main` needed, omitting `BridgeEval` and every
/// `BridgeClaim(slot)`. Those wires are therefore zero in `a`, and the
/// constraint reduces to `0 == 0`.
///
/// `copying` in the same file supplies all eight stages it configures, and
/// `main`'s `loading` supplies exactly the seven it configures — so the rule is
/// not in doubt, and this is a missed edit rather than a convention.
///
/// **The adversary.** Rebuild the carried claim-bridge stage in slot 0 so it
/// witnesses a host commitment the proof does not record, and change nothing
/// else. The instance-bound `bridge_com` and the recorded host both stay put, so
/// the child's $k(Y)$ is intact and the native root check — which *recomputes*
/// the bridge commitment from the recorded host rather than reading the carried
/// rx — has no reason to fire. The substituted rx is a well-formed stage for the
/// same slot with the same blind, so that slot's own `BridgeClaim` bonding claim
/// still holds. Exactly one check in the system is supposed to reject this.
///
/// This test asserts the **correct** behaviour, so it fails until the `Loading`
/// group is fixed. It is the acceptance gate for that work.
#[test]
fn claim_bridge_stage_must_be_tied_to_the_recorded_host() -> Result<()> {
    let pasta = Pasta::baked();
    let app = open_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(4242);

    let honest = seed_leaf(&app, pasta, &mut rng, &[3, 1, 4, 1, 5])?;
    assert!(
        app.verify(&honest, &mut rng)?,
        "the honest leaf must verify"
    );

    // A host commitment this proof records nowhere.
    let other = poly::<Fp, R>(&[7, 7, 7]);
    let other_host =
        other.commit_to_affine::<<Pasta as Cycle>::HostCurve>(Pasta::host_generators(pasta));

    let mut tampered = honest;
    tampered.corrupt_claim_bridge_host(0, other_host)?;

    // `loading` relates the claim-bridge run to the eval stage's claim block,
    // and they now disagree in slot 0.
    assert!(
        !app.verify(&tampered, &mut rng)?,
        "the loading circuit must reject a claim-bridge stage that witnesses a \
         host commitment the proof does not record for that slot — if this \
         fails, the `Loading` bonding group is still missing BridgeEval and \
         BridgeClaim(slot), so the constraint at loading.rs:251-253 is vacuous"
    );

    // And recursively. A fuse must be immediately sound: it need not carry a
    // child's history, but it must establish everything about its immediate
    // children that it relies on. It relies on `bridge_com` — that is how a
    // claim names the polynomial it opens, and what the child's step derived
    // its Fiat-Shamir challenges from.
    //
    // The parent already binds the child's *host* commitments: they are stashed
    // into its preamble stage, walked into its points accumulation by `loading`,
    // and cross-checked against the child's carried eval stage by `copying`.
    // What it must also establish is that the child's `bridge_com` bridges that
    // same host commitment, which needs the child's claim-bridge run carried
    // and tied — `ChildStageRx` has seven fields and this is not one of them.
    let leaf2 = seed_leaf(&app, pasta, &mut rng, &[2, 7, 1, 8])?;
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
        tampered,
        leaf2,
    );

    match fused {
        Err(e) => std::eprintln!("interior fuse rejected the untied claim bridge: {e:?}"),
        Ok((parent, ())) => {
            assert!(
                !app.verify(&parent, &mut rng)?,
                "a parent of a child whose claim bridge is untied must not verify: \
                 the fuse relies on `bridge_com` to name the polynomial each claim \
                 opens, so it must establish that the child's bridge stage carries \
                 the host commitment the parent folds"
            );
        }
    }

    Ok(())
}

/// **S1 — the claim commitment is not bound to the folded polynomial.**
///
/// A claim's instance-bound `bridge_com` is what the *step* sees: its Fiat-Shamir
/// challenge and header hash are derived from it. The polynomial the *parent*
/// folds into `f(X)` and the PCS accumulator is carried separately, under its
/// own host-curve commitment. Every piece is individually pinned — `bridge_com` by
/// the child's `k(Y)`, the host commitment by `copying` against the child's
/// eval bridge stage, and the fold by `loading`/endoscaling — but nothing ties
/// `bridge_com` to the host commitment except a prover-side pre-check that the code
/// itself documents as carrying no soundness weight.
///
/// So the adversary is a prover who declines to run that pre-check and hands
/// in a child that is internally consistent everywhere, desynced only between
/// `bridge_com` (which commits to `P`) and the carried polynomial `P'`. The step's
/// challenge `z` is bound to `P`, yet the statement the parent enforces is
/// about `P'`.
///
/// Root verification catches this (`verify.rs` re-derives `bridge(host)` and
/// compares it to `bridge_com`). An interior fuse does not — that is the gap.
#[test]
fn poly_query_com_is_not_bound_to_the_folded_polynomial() -> Result<()> {
    use ragu_pcd::PolyCommitment;

    let pasta = Pasta::baked();
    // A prover that simply does not run the fuse-time pre-check.
    let app = open_app_builder::<Pasta, R>(pasta)?
        .skip_claim_precheck_for_testing()
        .finalize(pasta)?;
    let mut rng = StdRng::seed_from_u64(2024);

    // `bridge_com` commits to P, but the claim carries P'. Both are honest-looking:
    // the step derives z from bridge_com (so z is bound to P) and claims y = P'(z).
    let p = poly::<Fp, R>(&[3, 1, 4, 1, 5]);
    let p_prime = poly(&[9, 2, 6]);
    assert_ne!(p.eval(Fp::from(7u64)), p_prime.eval(Fp::from(7u64)));
    // The handle's host commitment is P's, but its polynomial is P'. The
    // framework derives `bridge_com` from the host, so the step's challenge is bound
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

    // The claim really is desynced: bridge_com bridges P's host commitment, the
    // carried poly is P'. Establishing that here is what lets the rejection
    // below be attributed to the desync rather than to any of the other ways a
    // malformed proof fails, and it is the only reason a test reaches a claim
    // slot at all — hence the `_for_testing` accessor rather than a public one.
    let (claim_x, claim_y) = cheat.proof().claim_opening_for_testing(0);
    assert_eq!(
        claim_y,
        p_prime.eval(claim_x),
        "the claimed opening is of P'"
    );
    assert_ne!(claim_y, p.eval(claim_x), "P and P' disagree at z");

    // The root verifier checks the bridge, so it rejects.
    assert!(
        !app.verify(&cheat, &mut rng)?,
        "root verify must reject a claim whose bridge_com does not bridge its host"
    );

    // Fused as a child, the desync goes unnoticed.
    let leaf2 = seed_leaf(&app, pasta, &mut rng, &[2, 7, 1, 8])?;

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
            // Caught by the claim-lift chain. The child's lift instance wires
            // were computed from the handle's host (P's commitment -- the one
            // its `bridge_com` and challenges were derived from) and are bound
            // to the child's committed application rx through k(Y). The
            // framework polynomial `q` is built from the *recomputed* host of
            // the polynomial actually folded (P's prime's), and the parent's
            // `compute_v` enforces that the child's instance lifts Horner to
            // q(u). Limb decomposition is injective, so two different hosts
            // can never satisfy it: the parent's own compute_v trace is
            // unsatisfiable and root verify rejects the parent.
            //
            // Still deferred, per the framework-wide status quo: a prover who
            // *also* forges the child's lift instance wires (its own proof,
            // its own k(Y)) escapes this check and is caught only once
            // `bridge_com == commit(carried claim rx)` is enforced per-fuse --
            // the deferred PCS link no commitment in the system has yet.
            assert!(
                !verified,
                "a parent of a desynced-claim child must be rejected: the \
                 child's instance-bound lifts disagree with the limbs of the \
                 folded polynomial's commitment"
            );
            std::eprintln!(
                "the lift chain rejected the desync: instance lifts (P) vs folded host (P')"
            );
        }
    }

    Ok(())
}
