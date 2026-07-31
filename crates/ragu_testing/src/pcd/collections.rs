//! The shared application for the polynomial-collection fixtures: multiset
//! merging ([`multiset::MergeSets`]) and sequence concatenation
//! ([`sequence::ConcatSequences`]) registered as steps of **one**
//! application.
//!
//! Capacity is declared per application and every step's instance exposes
//! it, so the shared shape is the pointwise maximum of what the two steps
//! need: the concatenation's six polynomials, six claims and width-12
//! challenge cover the merge's three/three/six, and the merge step's unused
//! slots are padded by the framework. That cost asymmetry is itself part of
//! the characterization: registering steps together prices every step at
//! the heaviest step's shape.
//!
//! [`multiset::MergeSets`]: super::multiset::MergeSets
//! [`sequence::ConcatSequences`]: super::sequence::ConcatSequences

use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::Rank;
use ragu_core::Result;
use ragu_pcd::{Application, ApplicationBuilder};

use super::{
    multiset::{MergeSets, SeedSet},
    sequence::{ConcatSequences, SeedSequence},
};

/// The shared capacity: the pointwise maximum of the two steps' needs.
/// One header slot is reserved for the suffix, so the sequence header's four
/// name elements need `HEADER_SIZE = 5`.
pub const HEADER_SIZE: usize = 5;
pub const POLYS: usize = 6;
pub const CLAIMS: usize = 6;
pub const CHALLENGES: usize = 1;
pub const CHALLENGE_WIDTH: usize = 12;

/// An [`Application`] at the shared capacity.
pub type CollectionsApp<'params, C, R> =
    Application<'params, C, R, HEADER_SIZE, POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH>;

/// An [`ApplicationBuilder`] at the shared capacity.
pub type CollectionsAppBuilder<'params, C, R> =
    ApplicationBuilder<'params, C, R, HEADER_SIZE, POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH>;

/// All four collection fixtures registered and finalized: the one
/// application every multiset and sequence test proves through — two seeds
/// establishing initial collections, two fuses combining children by their
/// header-carried names.
pub fn collections_app<C: Cycle, R: Rank>(params: &C::Params) -> Result<CollectionsApp<'_, C, R>> {
    CollectionsAppBuilder::<C, R>::new()
        .register(SeedSet::<C, R>::new())?
        .register(SeedSequence::<C, R>::new())?
        .register(MergeSets::<C, R>::new())?
        .register(ConcatSequences::<C, R>::new())?
        .finalize(params)
}
