//! Demonstrates that the `poly_ops` relations are about polynomial
//! relationships, not PCD tree structure: each step witnesses all of its
//! polynomials locally, confirms the relation, and outputs the result set —
//! seeded once, verified, with no `fuse` and no children anywhere.

use ragu_arithmetic::{Cycle, FixedGenerators, poly_mul};
use ragu_circuits::polynomials::{ProductionRank, sparse};
use ragu_core::Result;
use ragu_pasta::{EpAffine, Fp, Pasta};
use ragu_pcd::ApplicationBuilder;
use ragu_testing::pcd::poly_ops_pcd::{
    ConcatenateSequences, ConcatenateSequencesWitness, MergeMultisets, MergeMultisetsWitness,
    SplitSequence, SplitSequenceWitness,
};
use rand::{SeedableRng, rngs::StdRng};

type R = ProductionRank;

/// An arbitrary nested-curve point standing in for a commitment. Openings are
/// not verified at fuse time, so the value is immaterial — only the polynomials
/// must satisfy the relation for the in-circuit check to pass.
fn commitment() -> EpAffine {
    Pasta::nested_generators(Pasta::baked()).g()[0]
}

/// The public generator `G_k = Com(X^k)`, the monomial commitment required by
/// the concatenation relation.
fn monomial(k: usize) -> EpAffine {
    Pasta::nested_generators(Pasta::baked()).g()[k]
}

fn poly(coeffs: &[u64]) -> sparse::Polynomial<Fp, R> {
    sparse::Polynomial::from_coeffs(coeffs.iter().map(|&c| Fp::from(c)).collect())
}

/// The product polynomial `a · b` — the merged multiset's root polynomial. The
/// in-circuit `y_prod = y_a·y_b` check is real, so this must be the genuine
/// product.
fn poly_product(a: &[u64], b: &[u64]) -> sparse::Polynomial<Fp, R> {
    let a: Vec<Fp> = a.iter().map(|&c| Fp::from(c)).collect();
    let b: Vec<Fp> = b.iter().map(|&c| Fp::from(c)).collect();
    let mut out = Vec::new();
    poly_mul(&a, &b, &mut out);
    sparse::Polynomial::from_coeffs(out)
}

/// Merge two multisets in a single childless step and verify, then concatenate
/// two sequences in another single childless step and verify. No `fuse`.
#[test]
fn poly_ops_in_single_steps() -> Result<()> {
    let pasta = Pasta::baked();
    let params = Pasta::circuit_poseidon(pasta);

    let shift = 3; // length of the first sequence

    let app = ApplicationBuilder::<Pasta, R, 4>::new()
        .register(MergeMultisets::<Pasta, R>::new(params))?
        .register(ConcatenateSequences::<Pasta, R>::new(params, shift))?
        .register(SplitSequence::<Pasta, R>::new(params, shift))?
        .finalize(pasta)?;

    let mut rng = StdRng::seed_from_u64(1234);

    // Multisets {1,2,3} and {4,5} (as root polynomials) and their union (the
    // product) — all witnessed in this one step, which outputs the merged set.
    let (merged, _) = app.seed(
        &mut rng,
        MergeMultisets::<Pasta, R>::new(params),
        MergeMultisetsWitness {
            a_commitment: commitment(),
            a_polynomial: poly(&[1, 2, 3]),
            b_commitment: commitment(),
            b_polynomial: poly(&[4, 5]),
            product_commitment: commitment(),
            product_polynomial: poly_product(&[1, 2, 3], &[4, 5]),
        },
    )?;
    assert!(app.verify(&merged, &mut rng)?);

    // Sequences (1,2,3) and (4,5) (as coefficient polynomials) and their
    // concatenation (1,2,3,4,5) = a + X^3·b — all witnessed in this one step,
    // which outputs the concatenated set.
    let (concatenated, _) = app.seed(
        &mut rng,
        ConcatenateSequences::<Pasta, R>::new(params, shift),
        ConcatenateSequencesWitness {
            a_commitment: commitment(),
            a_polynomial: poly(&[1, 2, 3]),
            b_commitment: commitment(),
            b_polynomial: poly(&[4, 5]),
            cat_commitment: commitment(),
            cat_polynomial: poly(&[1, 2, 3, 4, 5]),
            monomial_commitment: monomial(shift),
        },
    )?;
    assert!(app.verify(&concatenated, &mut rng)?);

    // Split (1,2,3,4,5) back into (1,2,3) and (4,5) at offset 3 — the *same*
    // identity as the concatenation above (cat = low + X^3·high), confirmed by
    // the same `enforce_poly_shifted_sum` call, just framed as a decomposition.
    let (split, _) = app.seed(
        &mut rng,
        SplitSequence::<Pasta, R>::new(params, shift),
        SplitSequenceWitness {
            cat_commitment: commitment(),
            cat_polynomial: poly(&[1, 2, 3, 4, 5]),
            low_commitment: commitment(),
            low_polynomial: poly(&[1, 2, 3]),
            high_commitment: commitment(),
            high_polynomial: poly(&[4, 5]),
            monomial_commitment: monomial(shift),
        },
    )?;
    assert!(app.verify(&split, &mut rng)?);

    Ok(())
}
