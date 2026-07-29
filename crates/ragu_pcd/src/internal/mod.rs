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

/// The typed-geometry hole for a stage that spans an induced run.
///
/// A run's width is the application's slot count, which is a value rather than
/// a Rust type. The span stage exists only to hold the run's position in the
/// [`Parent`](ragu_circuits::staging::Stage::Parent) chain, so the framework
/// never reaches its `values()` or `witness()` — those come from the run's
/// [`InducedStages`](ragu_circuits::staging::InducedStages) layout and from the
/// per-slot stage. Reaching this means the span stage was built through the
/// typed path, which cannot know how wide it is.
pub(crate) fn shape_dependent_stage() -> ! {
    unreachable!(
        "this stage spans an induced run, so its width is the application's slot count and it \
         has no type-level geometry; build it through the chain layout (InducedStages), not the \
         typed Stage path"
    )
}

/// The span stage for an induced run, chained after `P`: one entry in the typed
/// hierarchy covering every slot, with no geometry of its own.
///
/// A run's slot count is a property of the application, so it cannot be a chain
/// of per-slot aliases. `Run` holds the family's position in the
/// [`Parent`](ragu_circuits::staging::Stage::Parent) chain instead, and
/// [`InducedStages`](ragu_circuits::staging::InducedStages) says where the slot
/// boundaries fall inside its span. Everything after the run — including a
/// circuit's [`Last`](ragu_circuits::staging::MultiStageCircuit::Last) — chains
/// onto it and computes the same `skip_gates` it always did, with no knowledge
/// that the span is subdivided.
///
/// One type serves every run because a run's own geometry is never reached.
/// [`configure_induced_sized`](ragu_circuits::staging::StageBuilder::configure_induced_sized)
/// reserves each slot from the layout and produces its wires from the per-slot
/// stage, so the span's [`values`](ragu_circuits::staging::Stage::values) and
/// [`witness`](ragu_circuits::staging::Stage::witness) are
/// [`shape_dependent_stage`] holes and its `Witness`/`OutputKind` are unit —
/// the only thing that distinguishes one run from another is where it chains.
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
/// [`InducedStages::rx`](ragu_circuits::staging::InducedStages::rx) needs for a
/// span the typed path can no longer supply a body for.
///
/// Every one-point slot body is a single
/// [`Point::alloc`](ragu_primitives::Point::alloc), so extracting through that
/// same call is what makes this order the wire order by construction rather
/// than by a coordinate convention restated here.
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
