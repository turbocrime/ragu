//! Internal proving and verification engine for the recursive PCD protocol.
//!
//! This module defines the circuits, claim-building abstractions, and
//! supporting gadgets that implement recursion across both curves of the
//! cycle.
//!
//! # Submodules
//!
//! - [`native`] — circuits, indexed value containers, and claim
//!   orchestration for the native (host) field
//! - [`nested`] — circuits and claim orchestration for the nested
//!   (scalar) field, including endoscaling verification
//! - [`claims`] — generic [`claims::Builder`] for assembling revdot
//!   claims, shared by both fields
//! - [`fold_revdot`] — two-layer Horner-style folding that batch-reduces
//!   revdot claims
//! - [`endoscalar`] — endoscaling circuit and witness types for iterative
//!   curve scalar multiplication
//! - [`transcript`] — Fiat–Shamir transcript wrapper over a Poseidon
//!   sponge, with domain separation
//! - [`challenge`] — commit a polynomial and hash its commitment to derive a
//!   Fiat–Shamir challenge
//! - [`const_fns`] — compile-time helper functions for array construction

pub mod challenge;
pub mod claims;
pub mod const_fns;
pub mod endoscalar;
pub mod fold_revdot;
pub mod native;
pub mod nested;
pub mod transcript;

/// Identifies which of the two child proofs a component came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

/// The set of step shapes an application registered, in canonical order,
/// with the derived key sets the variant registries are built over.
///
/// Every count-dependent internal circuit is registered once per key value in
/// use: native walkers per ordered pair of child shapes, nested blocks per
/// (own, left, right) triple. This type owns the canonical enumeration order
/// so registration and lookup can never disagree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariantSpace {
    /// The distinct shapes, sorted — the canonical order everything else
    /// derives from.
    shapes: alloc::vec::Vec<crate::framework_hooks::HookLayout>,
}

#[allow(dead_code)] // the flip's consumer-switch commit takes these up
impl VariantSpace {
    /// Builds the space from the application's step plans (duplicates
    /// collapse; order is canonicalized by sorting).
    pub fn from_plans(plans: &[crate::framework_hooks::HookLayout]) -> Self {
        let mut shapes = plans.to_vec();
        shapes.sort();
        shapes.dedup();
        assert!(
            !shapes.is_empty(),
            "an application registers at least one step"
        );
        Self { shapes }
    }

    /// The distinct shapes, in canonical order.
    pub fn shapes(&self) -> &[crate::framework_hooks::HookLayout] {
        &self.shapes
    }

    /// Position of `shape` in the canonical order.
    ///
    /// # Panics
    ///
    /// Panics if the shape was not registered — a variant lookup for a shape
    /// no step has is a caller bug, not a runtime condition.
    pub fn shape_index(&self, shape: crate::framework_hooks::HookLayout) -> usize {
        self.shapes
            .iter()
            .position(|&s| s == shape)
            .expect("shape was registered")
    }

    /// Ordered pairs of shapes, row-major over the canonical order.
    pub fn pairs(
        &self,
    ) -> impl Iterator<
        Item = (
            crate::framework_hooks::HookLayout,
            crate::framework_hooks::HookLayout,
        ),
    > + '_ {
        self.shapes
            .iter()
            .flat_map(move |&l| self.shapes.iter().map(move |&r| (l, r)))
    }

    /// The number of ordered pairs.
    pub fn num_pairs(&self) -> usize {
        self.shapes.len() * self.shapes.len()
    }

    /// Position of `(left, right)` among [`pairs`](Self::pairs).
    pub fn pair_index(
        &self,
        left: crate::framework_hooks::HookLayout,
        right: crate::framework_hooks::HookLayout,
    ) -> usize {
        self.shape_index(left) * self.shapes.len() + self.shape_index(right)
    }

    /// Ordered triples of shapes, row-major over the canonical order.
    pub fn triples(
        &self,
    ) -> impl Iterator<
        Item = (
            crate::framework_hooks::HookLayout,
            crate::framework_hooks::HookLayout,
            crate::framework_hooks::HookLayout,
        ),
    > + '_ {
        self.shapes.iter().flat_map(move |&own| {
            self.shapes
                .iter()
                .flat_map(move |&l| self.shapes.iter().map(move |&r| (own, l, r)))
        })
    }

    /// The number of ordered triples.
    pub fn num_triples(&self) -> usize {
        self.shapes.len().pow(3)
    }

    /// Position of `(own, left, right)` among [`triples`](Self::triples).
    pub fn triple_index(
        &self,
        own: crate::framework_hooks::HookLayout,
        left: crate::framework_hooks::HookLayout,
        right: crate::framework_hooks::HookLayout,
    ) -> usize {
        (self.shape_index(own) * self.shapes.len() + self.shape_index(left)) * self.shapes.len()
            + self.shape_index(right)
    }

    /// The largest challenge count any shape uses — the number of shared
    /// per-slot challenge stage masks (slot `i`'s mask geometry is the same
    /// for every step with at least `i + 1` slots).
    pub fn max_challenges(&self) -> usize {
        self.shapes
            .iter()
            .map(|s| s.challenge.calls)
            .max()
            .unwrap_or(0)
    }

    /// The distinct challenge counts in use, sorted — one final-trace mask
    /// per entry (a step's final trace starts right after its own last
    /// challenge stage).
    pub fn distinct_challenges(&self) -> alloc::vec::Vec<usize> {
        let mut cs: alloc::vec::Vec<usize> =
            self.shapes.iter().map(|s| s.challenge.calls).collect();
        cs.sort_unstable();
        cs.dedup();
        cs
    }
}

#[cfg(test)]
pub mod tests;
