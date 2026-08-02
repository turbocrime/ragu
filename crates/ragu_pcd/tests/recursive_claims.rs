//! Recursive enforcement of poly-query claims.
//!
//! Requires the `unstable-fuzzing` feature for the proof-corruption helpers:
//! `cargo test -p ragu_pcd --features unstable-fuzzing --test recursive_claims`

#![cfg(feature = "unstable-fuzzing")]

use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::fuzz_utils::Corruption;
use ragu_testing::pcd::poly_query::{
    CommitAndOpen, CommitAndOpenWitness, OpenAndHash, OpenAndHashWitness, open_app,
    open_app_builder, poly,
};
use rand::{SeedableRng, rngs::StdRng};

type R = ProductionRank;

#[test]
fn corrupted_claim_is_rejected_directly_and_recursively() -> Result<()> {
    let pasta = Pasta::baked();
    let app = open_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(1234);

    let polynomial = poly(&[3, 1, 4, 1, 5]);
    let (leaf1, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            commitment: app.commit_polynomial(&polynomial)?,
            polynomial,
            claimed_y: None,
        },
    )?;
    assert!(app.verify(&leaf1, &mut rng)?);

    // Corrupt the claimed evaluation in slot 0.
    let mut proof = leaf1.proof().clone();
    proof.corrupt(Corruption::ClaimY(0, Fp::from(1u64)));
    let corrupted_leaf = proof.carry(leaf1.data().clone());
    assert!(
        !app.verify(&corrupted_leaf, &mut rng)?,
        "root verify must reject a corrupted claim instance"
    );

    let polynomial = poly(&[2, 7, 1, 8, 2, 8]);
    let (leaf2, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            commitment: app.commit_polynomial(&polynomial)?,
            polynomial,
            claimed_y: None,
        },
    )?;
    let p1 = poly(&[3, 1, 4, 1, 5]);
    let com1 = app.commit_polynomial(&p1)?;
    let x = Fp::from(9u64);
    let y = p1.eval(x);

    let fused = app.fuse(
        &mut rng,
        OpenAndHash::new(Pasta::circuit_poseidon(pasta)),
        OpenAndHashWitness {
            commitment: com1,
            polynomial: p1.clone(),
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
/// fused as a child. (Editing a finished proof also breaks the child's revdot
/// claim, so this does not isolate the `challenge_binding` circuit.)
#[test]
fn forged_challenge_is_rejected_directly_and_recursively() -> Result<()> {
    let pasta = Pasta::baked();
    let app = open_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(99);

    let polynomial = poly(&[3, 1, 4, 1, 5]);
    let (honest, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            commitment: app.commit_polynomial(&polynomial)?,
            polynomial,
            claimed_y: None,
        },
    )?;
    assert!(app.verify(&honest, &mut rng)?);

    // Keep the point, change the challenge.
    let mut proof = honest.proof().clone();
    proof.corrupt(Corruption::ChallengeValue(0, Fp::from(1u64)));
    let forged = proof.carry(honest.data().clone());
    assert!(
        !app.verify(&forged, &mut rng)?,
        "root verify must reject a challenge that is not its point's hash"
    );

    let polynomial = poly(&[2, 7, 1, 8]);
    let (leaf2, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            commitment: app.commit_polynomial(&polynomial)?,
            polynomial,
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
            polynomial: p3.clone(),
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

/// S2 — a claim naming a commitment outside the instance is rejected: perturb
/// one coordinate of a claim's name and nothing else, and the name matches no
/// slot, at root and through a fuse.
#[test]
fn a_claim_naming_no_slot_is_rejected() -> Result<()> {
    let pasta = Pasta::baked();
    let app = open_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(4242);

    let polynomial = poly(&[3, 1, 4, 1, 5]);
    let (honest, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            commitment: app.commit_polynomial(&polynomial)?,
            polynomial,
            claimed_y: None,
        },
    )?;
    assert!(
        app.verify(&honest, &mut rng)?,
        "the honest leaf must verify"
    );

    let mut proof = honest.proof().clone();
    proof.corrupt(Corruption::ClaimName(0, Fp::from(0xbad)));
    let tampered = proof.carry(honest.data().clone());

    assert!(
        !app.verify(&tampered, &mut rng)?,
        "root verify must reject a claim whose name matches no polynomial slot"
    );

    let polynomial = poly(&[2, 7, 1, 8]);
    let (leaf2, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            commitment: app.commit_polynomial(&polynomial)?,
            polynomial,
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
            polynomial: p3.clone(),
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

/// S1 — a claim whose instance-bound commitment names `P` while the carried
/// (folded) polynomial is `P'` is rejected, from a prover who skips the
/// fuse-time pre-check (which carries no soundness weight).
#[test]
fn poly_query_com_is_not_bound_to_the_folded_polynomial() -> Result<()> {
    use ragu_pcd::PolyCommitment;

    let pasta = Pasta::baked();
    let app = open_app_builder::<Pasta, R>(pasta)?
        .skip_claim_precheck_for_testing()
        .finalize(pasta)?;
    let mut rng = StdRng::seed_from_u64(2024);

    // The step derives z from P's embedded coordinates but claims y = P'(z).
    let p = poly::<Fp, R>(&[3, 1, 4, 1, 5]);
    let p_prime = poly(&[9, 2, 6]);
    assert_ne!(p.eval(Fp::from(7u64)), p_prime.eval(Fp::from(7u64)));
    let host_of_p =
        p.commit_to_affine::<<Pasta as Cycle>::HostCurve>(Pasta::host_generators(pasta));
    let desynced =
        PolyCommitment::<Pasta>::desync_for_testing(p_prime.iter_coeffs().collect(), host_of_p)?;

    let (cheat, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            commitment: desynced,
            polynomial: p_prime.clone(),
            claimed_y: None,
        },
    )?;

    assert!(
        !app.verify(&cheat, &mut rng)?,
        "root verify must reject a claim whose name is not the folded polynomial's commitment"
    );

    let polynomial = poly(&[2, 7, 1, 8]);
    let (leaf2, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            commitment: app.commit_polynomial(&polynomial)?,
            polynomial,
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
            polynomial: p3.clone(),
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
            // The child's instance coordinate wires Horner to q(u) of P's
            // host, but `q` is rebuilt from the folded polynomial's (P''s)
            // host; the coordinate embedding is injective, so the parent's
            // compute_v trace is unsatisfiable.
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

/// A forged coordinate instance wire (with everything else left intact) is
/// rejected: root `verify` recomputes each slot's coordinates from the
/// recorded host, and a parent's `compute_v` re-derives q(u) from these wires.
#[test]
fn forged_coordinate_wires_are_rejected_directly_and_recursively() -> Result<()> {
    let pasta = Pasta::baked();
    let app = open_app::<Pasta, R>(pasta)?;
    let mut rng = StdRng::seed_from_u64(2027);

    let polynomial = poly(&[3, 1, 4, 1, 5]);
    let (honest, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            commitment: app.commit_polynomial(&polynomial)?,
            polynomial,
            claimed_y: None,
        },
    )?;
    assert!(app.verify(&honest, &mut rng)?, "the honest leaf verifies");

    let polynomial = poly(&[3, 1, 4, 1, 5]);
    let (leaf, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            commitment: app.commit_polynomial(&polynomial)?,
            polynomial,
            claimed_y: None,
        },
    )?;
    let mut proof = leaf.proof().clone();
    proof.corrupt(Corruption::ApplicationCoord(0, Fp::from(0xbad)));
    let tampered = proof.carry(leaf.data().clone());

    assert!(
        !app.verify(&tampered, &mut rng)?,
        "root verify must recompute the coordinate region from the recorded \
         hosts and reject a forged wire"
    );

    let polynomial = poly(&[2, 7, 1, 8]);
    let (leaf2, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            commitment: app.commit_polynomial(&polynomial)?,
            polynomial,
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
            polynomial: p3.clone(),
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
