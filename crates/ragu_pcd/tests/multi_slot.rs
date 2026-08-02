//! Multi-slot proving regression: shapes with more than one polynomial slot
//! must prove *and verify*. `select_claim`'s prover-side matcher once set a
//! bit for **every** slot sharing the claim's name, and padding slots share
//! a name — so at `POLYS ≥ 2` the one-hot's sum-to-one was violated in the
//! trace and the proof survived until root verification.

use ragu_arithmetic::rand::{SeedableRng, rngs::StdRng};
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::Result;
use ragu_pasta::Pasta;
use ragu_pcd::{AppHooks, ApplicationBuilder};
use ragu_testing::pcd::poly_query::{CommitAndOpen, CommitAndOpenWitness, poly};

type R = ProductionRank;
const HEADER_SIZE: usize = 4;

/// One honest polynomial at the pinned slotted shape, padding filling the
/// second slot: duplicate padding names must resolve to exactly one one-hot
/// bit.
#[test]
fn the_pinned_slotted_shape_proves_and_verifies() -> Result<()> {
    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE, AppHooks<2, 3, 1, 2>>::new()
        .register(CommitAndOpen::<Pasta, R>::new(pasta))?
        .finalize(pasta)?;
    let mut rng = StdRng::seed_from_u64(999);

    let polynomial = poly(&[3, 1, 4, 1, 5]);
    let commitment = app.commit_polynomial(&polynomial)?;
    let (leaf, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(pasta),
        CommitAndOpenWitness {
            commitment,
            polynomial,
            claimed_y: None,
        },
    )?;
    assert!(
        app.verify(&leaf, &mut rng)?,
        "an honest proof at a multi-poly-slot capacity must verify"
    );
    Ok(())
}
