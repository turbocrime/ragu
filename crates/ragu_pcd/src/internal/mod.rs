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
//! - [`challenge`] — poly-query commitments and native challenge derivation
//! - [`const_fns`] — compile-time helper functions for array construction

pub mod challenge;
pub mod claims;
pub mod const_fns;
pub mod endoscalar;
pub mod fold_revdot;
pub mod native;
pub mod nested;
pub mod transcript;

/// The typed-geometry hole for a stage that spans an induced run: its width
/// is the application's slot count, so the typed path must never reach its
/// `values()` or `witness()` — the layout and per-slot stage supply those.
pub(crate) fn shape_dependent_stage() -> ! {
    unreachable!(
        "this stage spans an induced run, so its width is the application's slot count and it \
         has no type-level geometry; build it through the chain layout (InducedStages), not the \
         typed Stage path"
    )
}

/// The span stage for an induced run, chained after `P`: one entry in the
/// typed hierarchy covering every slot, with no geometry of its own. Slot
/// boundaries come from the run's
/// [`InducedStages`](ragu_circuits::staging::InducedStages) layout.
pub struct Run<C, R, P> {
    _marker: core::marker::PhantomData<(C, R, P)>,
}

impl<C, R, P> Clone for Run<C, R, P> {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl<C, R, P> Default for Run<C, R, P> {
    fn default() -> Self {
        Self {
            _marker: core::marker::PhantomData,
        }
    }
}

impl<C: ragu_arithmetic::CurveAffine, R: ragu_circuits::polynomials::Rank, P>
    ragu_circuits::staging::Stage<C::Base, R> for Run<C, R, P>
where
    P: ragu_circuits::staging::Stage<C::Base, R>,
{
    type Parent = P;
    type Witness<'source> = ();
    type OutputKind = ();

    fn values() -> usize {
        shape_dependent_stage()
    }

    fn witness<'dr, 'source: 'dr, D: ragu_core::drivers::Driver<'dr, F = C::Base>>(
        &self,
        _dr: &mut D,
        _witness: ragu_core::drivers::DriverValue<D, Self::Witness<'source>>,
    ) -> ragu_core::Result<ragu_core::gadgets::Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        shape_dependent_stage()
    }
}

/// The wire values a run of one-point slots produces, in slot order — what
/// [`InducedStages::rx`](ragu_circuits::staging::InducedStages::rx) needs.
/// Extracted through [`Point::alloc`](ragu_primitives::Point::alloc) itself,
/// so this order is the wire order by construction.
pub(crate) fn point_run_values<C: ragu_arithmetic::CurveAffine>(
    points: &[C],
) -> ragu_core::Result<alloc::vec::Vec<C::Base>> {
    use ragu_core::{
        drivers::emulator::Emulator,
        maybe::{Always, MaybeKind},
    };

    let mut values = alloc::vec::Vec::with_capacity(points.len() * 2);
    for point in points {
        let mut dr = Emulator::extractor();
        let allocated = ragu_primitives::Point::alloc(&mut dr, Always::maybe_just(|| *point))?;
        values.extend(dr.wires(&allocated)?);
    }
    Ok(values)
}

/// Identifies which of the two child proofs a component came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

#[cfg(test)]
pub mod tests;
