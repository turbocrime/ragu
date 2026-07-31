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

/// **S2 — a claim naming a commitment outside the instance is rejected.**
///
/// A claim names the polynomial it opens by the polynomial's embedded host
/// coordinates. Perturb one coordinate of a claim's name and nothing else:
/// the poly region, the recorded hosts, and the claim polynomials all stay
/// put, so the name now matches no slot. At root, `verify`'s claim walk finds
/// no slot and rejects; fused as a child, `_08_f` finds no polynomial for the
/// quotient and the fuse fails (or, past it, `compute_v`'s one-hot cannot
/// select a slot and no proof exists).
#[test]
fn a_claim_naming_no_slot_is_rejected() -> Result<()> {
    let pasta = Pasta::baked();
    let app = open_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(4242);

    let honest = seed_leaf(&app, pasta, &mut rng, &[3, 1, 4, 1, 5])?;
    assert!(
        app.verify(&honest, &mut rng)?,
        "the honest leaf must verify"
    );

    let mut tampered = honest;
    tampered.corrupt(Corruption::ClaimName(0, Fp::from(0xbad)));

    assert!(
        !app.verify(&tampered, &mut rng)?,
        "root verify must reject a claim whose name matches no polynomial slot"
    );

    // And recursively: the parent resolves each child claim's name against
    // the child's poly region before folding the quotient.
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
        Err(e) => std::eprintln!("interior fuse rejected the unresolvable claim name: {e:?}"),
        Ok((parent, ())) => {
            assert!(
                !app.verify(&parent, &mut rng)?,
                "a parent of a child whose claim names no slot must not verify"
            );
        }
    }

    Ok(())
}

/// **S1 — a claim's commitment desynced from the folded polynomial is
/// rejected.**
///
/// A claim's instance-bound coordinate pair is what the *step* sees: its
/// Fiat-Shamir challenge and header hash are derived from it. The polynomial
/// the *parent* folds into `f(X)` and the PCS accumulator is carried
/// separately, under its own host-curve commitment.
///
/// The adversary is a prover who declines to run the fuse-time pre-check
/// (which carries no soundness weight) and hands in a child that is
/// internally consistent everywhere, desynced only between the instance name
/// (the coordinates of `P`'s commitment) and the carried polynomial `P'`.
/// The step's challenge `z` is bound to `P`, yet the statement the parent
/// enforces is about `P'`.
///
/// Root verification catches it directly (`verify` recomputes the coordinate
/// region from the recorded host); an interior fuse catches it through the
/// coordinate chain — see the assertion below for the attribution.
#[test]
fn poly_query_com_is_not_bound_to_the_folded_polynomial() -> Result<()> {
    use ragu_pcd::PolyCommitment;

    let pasta = Pasta::baked();
    // A prover that simply does not run the fuse-time pre-check.
    let app = open_app_builder::<Pasta, R>(pasta)?
        .skip_claim_precheck_for_testing()
        .finalize(pasta)?;
    let mut rng = StdRng::seed_from_u64(2024);

    // The instance names P, but the claim carries P'. Both are honest-looking:
    // the step derives z from P's embedded coordinates (so z is bound to P)
    // and claims y = P'(z).
    let p = poly::<Fp, R>(&[3, 1, 4, 1, 5]);
    let p_prime = poly(&[9, 2, 6]);
    assert_ne!(p.eval(Fp::from(7u64)), p_prime.eval(Fp::from(7u64)));
    // The handle's host commitment is P's, but its polynomial is P'. The
    // framework embeds the host's coordinates as the in-circuit name, so the
    // step's challenge is bound to P while the parent folds P'.
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

    // The claim really is desynced: the instance names P's host commitment,
    // the carried poly is P'. Establishing that here is what lets the
    // rejection below be attributed to the desync rather than to any of the
    // other ways a malformed proof fails, and it is the only reason a test
    // reaches a claim slot at all — hence the `_for_testing` accessor rather
    // than a public one.
    let (claim_x, claim_y) = cheat.proof().claim_opening_for_testing(0);
    assert_eq!(
        claim_y,
        p_prime.eval(claim_x),
        "the claimed opening is of P'"
    );
    assert_ne!(claim_y, p.eval(claim_x), "P and P' disagree at z");

    // The root verifier recomputes the coordinate region from the recorded
    // host — the commitment of the carried polynomial — so it rejects.
    assert!(
        !app.verify(&cheat, &mut rng)?,
        "root verify must reject a claim whose name is not the folded polynomial's commitment"
    );

    // Fused as a child, the desync is caught by the coordinate chain.
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
            // Caught by the coordinate chain. The child's coordinate instance
            // wires were computed from the handle's host (P's commitment --
            // the one its name and challenges were derived from) and are
            // bound to the child's committed application rx through k(Y).
            // The framework polynomial `q` is built from the *recomputed*
            // host of the polynomial actually folded (P''s), and the parent's
            // `compute_v` enforces that the child's instance coordinates
            // Horner to q(u). The coordinate embedding is injective, so two
            // different hosts can never satisfy it: the parent's own
            // compute_v trace is unsatisfiable and root verify rejects the
            // parent.
            assert!(
                !verified,
                "a parent of a desynced-claim child must be rejected: the \
                 child's instance-bound coordinates disagree with the folded \
                 polynomial's commitment"
            );
            std::eprintln!(
                "the coordinate chain rejected the desync: instance coords (P) vs folded host (P')"
            );
        }
    }

    Ok(())
}

/// **The coordinate region is bound: a forged coordinate wire is rejected at
/// root and through a fuse.**
///
/// A step's view of its commitment — the limbs `poly_limbs` hands it and the
/// embedded coordinates the same bits pack into — is provable because each
/// coordinate is an instance wire, and that wire is checked twice: natively
/// at root, where `verify` recomputes every slot's coordinates from the
/// recorded host commitment, and in-circuit at every fuse, where the parent's
/// `compute_v` re-derives the claim-coordinate polynomial's $q(u)$ from the
/// child's coordinate wires and enforces it against the eval stage's carried
/// value (which the accumulator folds).
///
/// **The adversary.** Flip one coordinate wire's recorded value and nothing
/// else: the hosts and claim polynomials all stay put, so
/// every other check keeps passing and a rejection is attributable to the
/// coordinate binding alone.
#[test]
fn forged_coordinate_wires_are_rejected_directly_and_recursively() -> Result<()> {
    let pasta = Pasta::baked();
    let app = open_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(2027);

    let honest = seed_leaf(&app, pasta, &mut rng, &[3, 1, 4, 1, 5])?;
    assert!(app.verify(&honest, &mut rng)?, "the honest leaf verifies");

    let mut tampered = seed_leaf(&app, pasta, &mut rng, &[3, 1, 4, 1, 5])?;
    tampered.corrupt_application_coord(0, Fp::from(0xbad));

    assert!(
        !app.verify(&tampered, &mut rng)?,
        "root verify must recompute the coordinate region from the recorded \
         hosts and reject a forged wire"
    );

    // And recursively: the parent's `compute_v` Horner-walks the child's
    // coordinate wires to q(u); a forged wire makes its own trace
    // unsatisfiable.
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
        Err(e) => std::eprintln!("interior fuse rejected the forged coordinate: {e:?}"),
        Ok((parent, ())) => {
            assert!(
                !app.verify(&parent, &mut rng)?,
                "a parent of a child with a forged coordinate wire must not \
                 verify: compute_v re-derives q(u) from exactly these wires"
            );
        }
    }

    Ok(())
}
