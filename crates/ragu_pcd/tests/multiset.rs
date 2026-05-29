//! End-to-end test of the [`multiset_pcd`] fixtures: seed two leaf multisets,
//! fuse them with the merge step (which calls `enforce_poly_product`), and
//! verify every proof.
//!
//! [`multiset_pcd`]: ragu_testing::pcd::multiset_pcd

use ragu_arithmetic::{Cycle, FixedGenerators, poly_mul};
use ragu_circuits::polynomials::{ProductionRank, sparse};
use ragu_core::Result;
use ragu_pasta::{EpAffine, Fp, Pasta};
use ragu_pcd::ApplicationBuilder;
use ragu_testing::pcd::multiset_pcd::{
    MultisetLeaf, MultisetLeafWitness, MultisetMerge, MultisetMergeWitness,
};
use rand::{SeedableRng, rngs::StdRng};

type R = ProductionRank;

/// An arbitrary nested-curve point standing in for a commitment. The fixtures
/// do not verify openings (deferred to fuse time), so the value is immaterial.
fn commitment() -> EpAffine {
    Pasta::nested_generators(Pasta::baked()).g()[0]
}

fn poly(coeffs: &[u64]) -> sparse::Polynomial<Fp, R> {
    sparse::Polynomial::from_coeffs(coeffs.iter().map(|&c| Fp::from(c)).collect())
}

/// The product polynomial `left · right`, which the merge step takes as a
/// witness. The in-circuit `y_prod = y_a·y_b` check is real, so this must be the
/// genuine product for the proof to satisfy.
fn poly_product(a: &[u64], b: &[u64]) -> sparse::Polynomial<Fp, R> {
    let a: Vec<Fp> = a.iter().map(|&c| Fp::from(c)).collect();
    let b: Vec<Fp> = b.iter().map(|&c| Fp::from(c)).collect();
    let mut out = Vec::new();
    poly_mul(&a, &b, &mut out);
    sparse::Polynomial::from_coeffs(out)
}

#[test]
fn multiset_merge_pcd() -> Result<()> {
    let pasta = Pasta::baked();
    let params = Pasta::circuit_poseidon(pasta);

    let app = ApplicationBuilder::<Pasta, R, 4>::new()
        .register(MultisetLeaf::<Pasta, R>::new(params))?
        .register(MultisetMerge::<Pasta, R>::new(params))?
        .finalize(pasta)?;

    let mut rng = StdRng::seed_from_u64(1234);

    let (leaf_a, _) = app.seed(
        &mut rng,
        MultisetLeaf::<Pasta, R>::new(params),
        MultisetLeafWitness {
            commitment: commitment(),
            polynomial: poly(&[1, 2, 3]),
        },
    )?;
    assert!(app.verify(&leaf_a, &mut rng)?);

    let (leaf_b, _) = app.seed(
        &mut rng,
        MultisetLeaf::<Pasta, R>::new(params),
        MultisetLeafWitness {
            commitment: commitment(),
            polynomial: poly(&[4, 5]),
        },
    )?;
    assert!(app.verify(&leaf_b, &mut rng)?);

    // Fuse the two leaves via the merge step. The third argument is the
    // prover-supplied product polynomial and its commitment.
    let (node, _) = app.fuse(
        &mut rng,
        MultisetMerge::<Pasta, R>::new(params),
        MultisetMergeWitness {
            commitment: commitment(),
            polynomial: poly_product(&[1, 2, 3], &[4, 5]),
        },
        leaf_a,
        leaf_b,
    )?;
    assert!(app.verify(&node, &mut rng)?);

    Ok(())
}
