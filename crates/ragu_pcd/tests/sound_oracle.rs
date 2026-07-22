//! End-to-end tests for the *sound* polynomial oracle: the polynomial is
//! witnessed in-circuit, the challenge is the in-circuit sponge hash of its
//! commitment, the evaluation is computed by in-circuit Horner, and the claim
//! is enforced by an equality constraint — so a dishonest witness cannot
//! yield a proof at all.

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::ApplicationBuilder;
use ragu_testing::pcd::sound_oracle::{SoundMerge, SoundOpen, SoundOpenWitness};
use rand::{SeedableRng, rngs::StdRng};

type R = ProductionRank;
const HEADER_SIZE: usize = 4;

fn coeffs(values: &[u64]) -> Vec<Fp> {
    values.iter().map(|v| Fp::from(*v)).collect()
}

fn sound_app() -> Result<ragu_pcd::Application<'static, Pasta, R, HEADER_SIZE>> {
    ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new(Pasta::baked())
        .register(SoundOpen::<Pasta>::new())?
        .register(SoundMerge::<Pasta>::new())?
        .finalize()
}

/// The full sound oracle loop: witness a polynomial in-circuit, derive a
/// challenge bound to its commitment, evaluate at it, enforce the evaluation
/// — then merge two leaves with sound cross-node chaining. All proofs verify.
#[test]
fn sound_oracle_end_to_end() -> Result<()> {
    let app = sound_app()?;
    let mut rng = StdRng::seed_from_u64(97);

    let (left, ()) = app.seed(
        &mut rng,
        SoundOpen::new(),
        SoundOpenWitness {
            coefficients: coeffs(&[3, 1, 4, 1, 5]),
            claimed_y: None,
        },
    )?;
    assert!(app.verify(&left, &mut rng)?);

    let (right, ()) = app.seed(
        &mut rng,
        SoundOpen::new(),
        SoundOpenWitness {
            coefficients: coeffs(&[2, 7, 1, 8]),
            claimed_y: None,
        },
    )?;
    assert!(app.verify(&right, &mut rng)?);

    // Merge: re-witnesses both children's polynomials, binds them to the
    // children's header commitments in-circuit, evaluates both at a shared
    // challenge, and hashes everything into the output header.
    let (merged, ()) = app.fuse(&mut rng, SoundMerge::new(), (), left, right)?;
    assert!(app.verify(&merged, &mut rng)?);

    Ok(())
}

/// A dishonest evaluation claim makes the leaf circuit unsatisfiable: the
/// prover either fails to produce a proof, or the proof it produces does not
/// verify. Either way, no accepting proof of a false claim exists.
#[test]
fn sound_oracle_rejects_dishonest_evaluation() -> Result<()> {
    let app = sound_app()?;
    let mut rng = StdRng::seed_from_u64(97);

    let result = app.seed(
        &mut rng,
        SoundOpen::new(),
        SoundOpenWitness {
            coefficients: coeffs(&[3, 1, 4, 1, 5]),
            claimed_y: Some(Fp::from(42u64)),
        },
    );

    match result {
        Err(_) => {} // rejected at proving time
        Ok((pcd, ())) => {
            assert!(
                !app.verify(&pcd, &mut rng)?,
                "a proof of a dishonest evaluation claim must not verify"
            );
        }
    }
    Ok(())
}

/// An oversized coefficient vector (longer than the fixture's declared
/// capacity) is rejected as an invalid witness.
#[test]
fn sound_oracle_rejects_oversized_polynomial() -> Result<()> {
    let app = sound_app()?;
    let mut rng = StdRng::seed_from_u64(97);

    let result = app.seed(
        &mut rng,
        SoundOpen::new(),
        SoundOpenWitness {
            coefficients: coeffs(&[1, 2, 3, 4, 5, 6, 7, 8, 9]),
            claimed_y: None,
        },
    );
    assert!(result.is_err(), "oversized polynomial must be rejected");
    Ok(())
}
