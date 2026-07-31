//! Characterization tests for the polynomial-collection fixtures — multiset
//! merging and sequence concatenation — proving through the one shared
//! application from `ragu_testing::pcd::collections`.
//!
//! Each collection has its own module; the seed/fuse shape, the rejection
//! contract, and the size ceilings are documented there.

mod multiset;
mod sequence;

use ragu_circuits::polynomials::ProductionRank;
use ragu_pasta::Fp;

type R = ProductionRank;

/// Field members from small integers, shared by both collections' tests.
fn members(values: &[u64]) -> Vec<Fp> {
    values.iter().map(|v| Fp::from(*v)).collect()
}
