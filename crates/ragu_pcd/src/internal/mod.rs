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

/// The `Stage::values()` of a stage whose width is a property of the
/// application, not of its Rust type.
///
/// [`Stage`](ragu_circuits::staging::Stage)'s geometry is static — `values()`
/// takes no arguments, and `skip_gates()` is defined as the parent chain's
/// `values()` — so a stage sized by the application's capacity has no honest
/// answer to give. It used to give a fabricated one, which meant every rx
/// built through the typed path landed at an offset derived from a shape no
/// application had. That was invisible precisely because the tests asked the
/// same fabrication.
///
/// The value-level path never needs this: `InducedStages::rx_configured`
/// calls the stage's `witness` and takes every offset from the layout it was
/// built with. Build these stages through
/// [`InducedStages`](ragu_circuits::staging::InducedStages) and this is
/// unreachable; reach it and the mistake is loud instead of silent.
pub(crate) fn shape_dependent_stage() -> ! {
    unreachable!(
        "this stage's width depends on the application's capacity, so it has no type-level \
         geometry; build it through the chain layout (InducedStages), not the typed Stage path"
    )
}

/// Identifies which of the two child proofs a component came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

#[cfg(test)]
pub mod tests;
