//! Multi-slot proving regression: shapes with more than one polynomial slot
//! must prove *and verify*.
//!
//! Found by the multiset characterization: `select_claim`'s prover-side
//! matcher set a bit for **every** slot sharing the claim's name, and a
//! trivial child's padding slots all share the padding polynomial's name —
//! so at `POLYS ≥ 2` the one-hot's sum-to-one constraint was violated in
//! the trace, and (since assembly does not check satisfaction) the proof
//! survived until root verification. The pinned slotted registration shape
//! `(2, 3, 1)` had never been proved by any test before this one.

use ragu_arithmetic::{
    Cycle,
    rand::{SeedableRng, rngs::StdRng},
};
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::Result;
use ragu_pasta::Pasta;
use ragu_pcd::ApplicationBuilder;
use ragu_testing::pcd::poly_query::{CommitAndOpen, CommitAndOpenWitness, poly};

type R = ProductionRank;
const HEADER_SIZE: usize = 4;

/// One honest polynomial at the pinned slotted shape, padding filling the
/// second slot: duplicate padding names must resolve to exactly one one-hot
/// bit.
#[test]
fn the_pinned_slotted_shape_proves_and_verifies() -> Result<()> {
    let pasta = Pasta::baked();
    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE, 2, 3, 1, 2>::new()
        .register(CommitAndOpen::<Pasta, R>::new(Pasta::circuit_poseidon(
            pasta,
        )))?
        .finalize(pasta)?;
    let mut rng = StdRng::seed_from_u64(999);

    let commitment = app.commit_polynomial(&poly(&[3, 1, 4, 1, 5]))?;
    let (leaf, ()) = app.seed(
        &mut rng,
        CommitAndOpen::new(Pasta::circuit_poseidon(pasta)),
        CommitAndOpenWitness {
            commitment,
            claimed_y: None,
        },
    )?;
    assert!(
        app.verify(&leaf, &mut rng)?,
        "an honest proof at a multi-poly-slot capacity must verify"
    );
    Ok(())
}
