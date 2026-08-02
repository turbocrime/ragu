//! Polynomial-collection fixtures, registered as the four steps of one
//! application; see [`step`] for the two collection types and how a seed and
//! a fuse build them.

pub mod step;

use ff::PrimeField;
use ragu_arithmetic::{Cycle, poly_mul, poly_with_roots};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::Result;
use ragu_pcd::{AppHooks, Application, ApplicationBuilder};

use self::step::{ConcatSequences, MergeSets, SeedSequence, SeedSet};

/// The shared header size: a suffix slot plus the sequence header's three
/// elements; the set header's two fit inside it.
pub const HEADER_SIZE: usize = 4;

/// An [`Application`] at the shared capacity.
pub type CollectionsApp<'params, C, R> =
    Application<'params, C, R, HEADER_SIZE, AppHooks<3, 3, 1, 6>>;

/// All four collection steps registered and finalized.
pub fn collections_app<C: Cycle, R: Rank>(params: &C::Params) -> Result<CollectionsApp<'_, C, R>> {
    ApplicationBuilder::<C, R, HEADER_SIZE, AppHooks<3, 3, 1, 6>>::new()
        .register(SeedSet::<C, R>::new())?
        .register(SeedSequence::<C, R>::new())?
        .register(MergeSets::<C, R>::new(params))?
        .register(ConcatSequences::<C, R>::new(params))?
        .finalize(params)
}

/// The monic set polynomial `∏ (X − m)` over `members`, multiplicity
/// included; the empty set is the constant `1`.
pub fn set_polynomial<F: PrimeField, R: Rank>(members: &[F]) -> sparse::Polynomial<F, R> {
    sparse::Polynomial::from_coeffs(poly_with_roots(members))
}

/// A polynomial's coefficients with the zero tail dropped.
fn trimmed_coeffs<F: PrimeField, R: Rank>(poly: &sparse::Polynomial<F, R>) -> Vec<F> {
    let mut coeffs: Vec<F> = poly.iter_coeffs().collect();
    while coeffs.last() == Some(&F::ZERO) {
        coeffs.pop();
    }
    coeffs
}

/// The merged polynomial `A·B`, computed with the library's FFT multiply.
pub fn merged_polynomial<F: PrimeField, R: Rank>(
    a: &sparse::Polynomial<F, R>,
    b: &sparse::Polynomial<F, R>,
) -> sparse::Polynomial<F, R> {
    let mut out = Vec::new();
    poly_mul(&trimmed_coeffs(a), &trimmed_coeffs(b), &mut out);
    sparse::Polynomial::from_coeffs(out)
}

/// The sequence polynomial: member `i` is the coefficient of `Xⁱ`, with a
/// monic sentinel coefficient `1` above the last member, so a sequence of
/// `L` members has degree exactly `L`.
pub fn sequence_polynomial<F: PrimeField, R: Rank>(members: &[F]) -> sparse::Polynomial<F, R> {
    let mut coeffs = members.to_vec();
    coeffs.push(F::ONE);
    sparse::Polynomial::from_coeffs(coeffs)
}
