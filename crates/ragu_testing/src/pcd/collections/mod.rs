//! The shared application for the polynomial-collection fixtures: multiset
//! merging and sequence concatenation, registered as the four steps of
//! **one** application ([`step`]).
//!
//! Both collections follow the same lifecycle: a **seed** proves a
//! one-member collection from a literal element, and a **fuse** combines
//! two proven collections, binding its witnessed inputs to the children's
//! header-carried names in-circuit. Growth happens only by fusing, so a
//! collection of `N` members is a tree of `N` seeds and `N − 1` fuses, and
//! well-formedness is inductive from the singleton base case.
//!
//! The two fuses present the same shape — three polynomials, three claims,
//! one width-6 challenge — so registering them together costs no padding
//! asymmetry: the shared capacity is every step's exact need.

pub mod step;

use ff::PrimeField;
use ragu_arithmetic::{CryptoRngCore, Cycle, poly_mul, poly_with_roots};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::Result;
use ragu_pcd::{Application, ApplicationBuilder, Pcd};

use self::step::{
    ConcatSequences, ConcatSequencesWitness, MergeSets, MergeSetsWitness, SeedSequence,
    SeedSequenceWitness, SeedSet, SeedSetWitness, SeqHeader, SetHeader,
};

/// The shared capacity. One header slot is reserved for the suffix, so the
/// sequence header's three elements (name + length) need `HEADER_SIZE = 4`;
/// the set header's two fit inside it.
pub const HEADER_SIZE: usize = 4;
pub const POLYS: usize = 3;
pub const CLAIMS: usize = 3;
pub const CHALLENGES: usize = 1;
pub const CHALLENGE_WIDTH: usize = 6;

/// An [`Application`] at the shared capacity.
pub type CollectionsApp<'params, C, R> =
    Application<'params, C, R, HEADER_SIZE, POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH>;

/// An [`ApplicationBuilder`] at the shared capacity.
pub type CollectionsAppBuilder<'params, C, R> =
    ApplicationBuilder<'params, C, R, HEADER_SIZE, POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH>;

/// All four collection steps registered and finalized: the one application
/// every collection test proves through — two singleton seeds, two fuses
/// combining children by their header-carried names.
pub fn collections_app<C: Cycle, R: Rank>(params: &C::Params) -> Result<CollectionsApp<'_, C, R>> {
    CollectionsAppBuilder::<C, R>::new()
        .register(SeedSet::<C, R>::new())?
        .register(SeedSequence::<C, R>::new())?
        .register(MergeSets::<C, R>::new())?
        .register(ConcatSequences::<C, R>::new())?
        .finalize(params)
}

/// The monic set polynomial `∏ (X − m)` over `members`, multiplicity
/// included, via the library's [`poly_with_roots`] (a product tree over the
/// FFT multiply): a multiset of `N` members is a degree-`N` polynomial with
/// `N + 1` coefficients. The empty set is the constant polynomial `1`.
///
/// Panics (via `from_coeffs`) if `members.len() + 1` exceeds the rank's
/// coefficient capacity — the size ceiling the tests pin.
pub fn set_polynomial<F: PrimeField, R: Rank>(members: &[F]) -> sparse::Polynomial<F, R> {
    sparse::Polynomial::from_coeffs(poly_with_roots(members))
}

/// A polynomial's coefficients with the zero tail dropped, for feeding
/// [`poly_mul`] without ballooning to the rank's dense width.
pub fn trimmed_coeffs<F: PrimeField, R: Rank>(poly: &sparse::Polynomial<F, R>) -> Vec<F> {
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

/// The monic coefficient polynomial of a sequence: member `i` is the
/// coefficient of `Xⁱ`, and one **sentinel** coefficient `1` sits above the
/// last member, so a sequence of `L` members has degree exactly `L`.
///
/// The sentinel keeps every sequence's commitment well-defined — `[0]` and
/// even the empty sequence commit to a nonzero polynomial — and marks the
/// end of the members in-band.
///
/// Panics (via `from_coeffs`) when `members.len() + 1` exceeds the rank's
/// coefficient capacity: the ceiling is `num_coeffs − 1` members — the same
/// ceiling as a multiset, for the same reason (one coefficient above the
/// last member).
pub fn sequence_polynomial<F: PrimeField, R: Rank>(members: &[F]) -> sparse::Polynomial<F, R> {
    let mut coeffs = members.to_vec();
    coeffs.push(F::ONE);
    sparse::Polynomial::from_coeffs(coeffs)
}

/// Seed a one-member set from its literal member.
pub fn seed_set<C: Cycle, R: Rank, RNG: CryptoRngCore>(
    app: &CollectionsApp<'_, C, R>,
    rng: &mut RNG,
    member: C::CircuitField,
) -> Result<Pcd<C, R, SetHeader<R>>> {
    let (leaf, ()) = app.seed(
        rng,
        SeedSet::new(),
        SeedSetWitness {
            set: app.commit_polynomial(&set_polynomial(&[member]))?,
        },
    )?;
    Ok(leaf)
}

/// Fuse two set children into their merge, computing the product honestly
/// from the polynomials the children carry.
pub fn fuse_merge<C: Cycle, R: Rank, RNG: CryptoRngCore>(
    app: &CollectionsApp<'_, C, R>,
    rng: &mut RNG,
    left: Pcd<C, R, SetHeader<R>>,
    right: Pcd<C, R, SetHeader<R>>,
) -> Result<Pcd<C, R, SetHeader<R>>> {
    let product = merged_polynomial(&left.data().polynomial, &right.data().polynomial);
    let witness = MergeSetsWitness {
        a: app.commit_polynomial(&left.data().polynomial)?,
        b: app.commit_polynomial(&right.data().polynomial)?,
        product: app.commit_polynomial(&product)?,
    };
    let (merged, ()) = app.fuse(rng, MergeSets::new(), witness, left, right)?;
    Ok(merged)
}

/// Seed a one-member sequence from its literal member: the committed
/// polynomial is `[member, 1]` — the member and the sentinel.
pub fn seed_sequence<C: Cycle, R: Rank, RNG: CryptoRngCore>(
    app: &CollectionsApp<'_, C, R>,
    rng: &mut RNG,
    member: C::CircuitField,
) -> Result<Pcd<C, R, SeqHeader>> {
    let (leaf, ()) = app.seed(
        rng,
        SeedSequence::new(),
        SeedSequenceWitness {
            sequence: app.commit_polynomial(&sequence_polynomial(&[member]))?,
            member,
        },
    )?;
    Ok(leaf)
}

/// Fuse two sequence children into their concatenation, computing the
/// output honestly from the members the children carry.
pub fn fuse_concat<C: Cycle, R: Rank, RNG: CryptoRngCore>(
    app: &CollectionsApp<'_, C, R>,
    rng: &mut RNG,
    left: Pcd<C, R, SeqHeader>,
    right: Pcd<C, R, SeqHeader>,
) -> Result<Pcd<C, R, SeqHeader>> {
    let concatenated: Vec<C::CircuitField> = left
        .data()
        .members
        .iter()
        .chain(right.data().members.iter())
        .copied()
        .collect();
    let witness = ConcatSequencesWitness {
        a: app.commit_polynomial(&sequence_polynomial(&left.data().members))?,
        b: app.commit_polynomial(&sequence_polynomial(&right.data().members))?,
        output: app.commit_polynomial(&sequence_polynomial(&concatenated))?,
    };
    let (out, ()) = app.fuse(rng, ConcatSequences::new(), witness, left, right)?;
    Ok(out)
}
