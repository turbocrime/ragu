//! Claim orchestration for nested field (scalar field) rx polynomials.
//!
//! This module provides a unified interface for assembling `a` and `b`
//! polynomial vectors for nested field revdot claim verification.
//!
//! The nested claim structure is simpler than native:
//! - Circuit checks ([`EndoscalingStep`](InternalCircuitIndex::EndoscalingStep)): $k(y) = 1$
//! - Masking checks ([`EndoscalarStage`](InternalCircuitIndex::EndoscalarStage),
//!   [`PointsStage`](InternalCircuitIndex::PointsStage),
//!   `PointsFinalStaged`, and all `Bridge*` variants): $k(y) = 0$

use alloc::borrow::Cow;

use ragu_arithmetic::ff::PrimeField;
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::Result;

use super::{ChildBridgeKind, InternalCircuitIndex, RxIndex};
use crate::internal::claims::{Builder, Source, sum_polynomials};

/// Trait for processing nested claim values into accumulated outputs.
///
/// This trait defines how to process rx values from a [`Source`].
pub trait Processor<Rx> {
    /// Process an internal circuit claim whose trace is the sum of the given
    /// rxs ($k(y) = 1$ for [`EndoscalingStep`]).
    ///
    /// [`EndoscalingStep`]: InternalCircuitIndex::EndoscalingStep
    fn internal_circuit_claim(&mut self, id: InternalCircuitIndex, rxs: impl Iterator<Item = Rx>);

    /// Process a claim whose trace is the Horner fold (with $z$) of the given
    /// rxs, with one rx per fold slot ($k(y) = 0$).
    ///
    /// The default implementation wraps each rx as a single-element group and
    /// delegates to [`grouped_bonding_claim`](Self::grouped_bonding_claim).
    fn bonding_claim(
        &mut self,
        id: InternalCircuitIndex,
        rxs: impl Iterator<Item = Rx>,
    ) -> Result<()> {
        self.grouped_bonding_claim(id, rxs.map(core::iter::once))
    }

    /// Process a claim whose trace is the Horner fold (with $z$) of per-group
    /// sums, where each fold slot holds the sum of one inner iterator
    /// ($k(y) = 0$).
    fn grouped_bonding_claim(
        &mut self,
        id: InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = Rx>>,
    ) -> Result<()>;
}

impl<'m, 'rx, F: PrimeField, R: Rank> Processor<&'rx sparse::Polynomial<F, R>>
    for Builder<'m, 'rx, Cow<'rx, sparse::Polynomial<F, R>>, F, R>
{
    fn internal_circuit_claim(
        &mut self,
        id: InternalCircuitIndex,
        rxs: impl Iterator<Item = &'rx sparse::Polynomial<F, R>>,
    ) {
        let circuit_id = id.circuit_index(self.capacity.poly_query.polys);
        let rx = sum_polynomials(rxs);
        self.circuit_impl(circuit_id, rx);
    }

    fn grouped_bonding_claim(
        &mut self,
        id: InternalCircuitIndex,
        groups: impl Iterator<Item = impl Iterator<Item = &'rx sparse::Polynomial<F, R>>>,
    ) -> Result<()> {
        let circuit_id = id.circuit_index(self.capacity.poly_query.polys);
        let folded = self.fold_bonding_groups(groups);
        self.bonding_impl(circuit_id, folded);
        Ok(())
    }
}

/// Build nested claims in unified interleaved order from a source.
///
/// The ordering is:
/// 1. Circuit checks ($k(y) = 1$): [`EndoscalingStep`](InternalCircuitIndex::EndoscalingStep)
///    for each step, interleaved across proofs
/// 2. Masking checks ($k(y) = 0$): [`EndoscalarStage`](InternalCircuitIndex::EndoscalarStage),
///    [`PointsStage`](InternalCircuitIndex::PointsStage), `PointsFinalStaged`,
///    and all `Bridge*` variants
///
/// This ordering must match the ky_elements ordering from [`ky_values`].
pub fn build<S, P>(source: &S, processor: &mut P, polys: usize) -> Result<()>
where
    S: Source<RxComponent = RxIndex>,
    P: Processor<S::Rx>,
{
    for id in InternalCircuitIndex::all(polys) {
        use InternalCircuitIndex::*;
        match id {
            EndoscalingStep(step) => {
                for ((step_rx, endo_rx), pts_rx) in source
                    .rx(RxIndex::EndoscalingStep(step))
                    .zip(source.rx(RxIndex::EndoscalarStage))
                    .zip(source.rx(RxIndex::PointsStage))
                {
                    processor.internal_circuit_claim(id, [step_rx, endo_rx, pts_rx].into_iter());
                }
            }
            EndoscalarStage => {
                processor.bonding_claim(id, source.rx(RxIndex::EndoscalarStage))?;
            }
            PointsStage => {
                processor.bonding_claim(id, source.rx(RxIndex::PointsStage))?;
            }
            PointsFinalStaged => {
                let num_steps = super::num_endoscaling_steps(polys);
                let final_rxs = (0..num_steps)
                    .flat_map(|step| source.rx(RxIndex::EndoscalingStep(step as u32)));
                processor.bonding_claim(id, final_rxs)?;
            }
            BridgeClaim(slot) => {
                processor.bonding_claim(id, source.rx(RxIndex::BridgeClaim(slot)))?;
            }
            BridgePreamble => {
                processor.bonding_claim(id, source.rx(RxIndex::BridgePreamble))?;
            }
            BridgeSPrime => {
                processor.bonding_claim(id, source.rx(RxIndex::BridgeSPrime))?;
            }
            BridgeInnerError => {
                processor.bonding_claim(id, source.rx(RxIndex::BridgeInnerError))?;
            }
            BridgeOuterError => {
                processor.bonding_claim(id, source.rx(RxIndex::BridgeOuterError))?;
            }
            BridgeAB => {
                processor.bonding_claim(id, source.rx(RxIndex::BridgeAB))?;
            }
            BridgeQuery => {
                processor.bonding_claim(id, source.rx(RxIndex::BridgeQuery))?;
            }
            BridgeF => {
                processor.bonding_claim(id, source.rx(RxIndex::BridgeF))?;
            }
            BridgeEval => {
                processor.bonding_claim(id, source.rx(RxIndex::BridgeEval))?;
            }
            Loading => {
                // **Every stage the circuit configures must be supplied here.**
                // A bonding claim is checked against the *sum* of these rxs, so
                // a configured stage that is left out contributes zero wires —
                // and every constraint the circuit places over it is then
                // satisfied vacuously. `loading` configures the eval stage and
                // the claim-bridge run and enforces that they agree slot by
                // slot, so both belong in the trace that claim is checked
                // against. While they were omitted that check was vacuous;
                // `claim_bridge_stage_must_be_tied_to_the_recorded_host` in
                // `tests/recursive_claims.rs` is the regression test.
                //
                // The claim slots are an application parameter, so this arm
                // cannot be the fixed `.zip()` chain the others are. It builds
                // the same thing a chain would — one group per proof, holding
                // every stage of that proof's trace — by accumulation instead.
                let mut groups: alloc::vec::Vec<alloc::vec::Vec<S::Rx>> = source
                    .rx(RxIndex::PointsStage)
                    .map(|rx| alloc::vec![rx])
                    .collect();

                let fixed = [
                    RxIndex::BridgePreamble,
                    RxIndex::BridgeSPrime,
                    RxIndex::BridgeInnerError,
                    RxIndex::BridgeAB,
                    RxIndex::BridgeQuery,
                    RxIndex::BridgeF,
                    RxIndex::BridgeEval,
                ];
                let claim_slots = (0..polys).map(|slot| RxIndex::BridgeClaim(slot as u32));
                for component in fixed.into_iter().chain(claim_slots) {
                    for (group, rx) in groups.iter_mut().zip(source.rx(component)) {
                        group.push(rx);
                    }
                }

                processor
                    .grouped_bonding_claim(id, groups.into_iter().map(|group| group.into_iter()))?;
            }
            Copying(side) => {
                // As in `Loading`: every stage the circuit configures must be
                // supplied, or its constraints hold vacuously over zero wires.
                // `copying` configures the child's claim-bridge run, whose
                // length is the application's poly capacity, so this arm
                // accumulates per-proof groups rather than zipping a fixed
                // tuple.
                let mut groups: alloc::vec::Vec<alloc::vec::Vec<S::Rx>> = source
                    .rx(RxIndex::ChildPointsStage(side))
                    .map(|rx| alloc::vec![rx])
                    .collect();

                let fixed = [
                    RxIndex::BridgePreamble,
                    RxIndex::ChildBridge(ChildBridgeKind::SPrime, side),
                    RxIndex::ChildBridge(ChildBridgeKind::InnerError, side),
                    RxIndex::ChildBridge(ChildBridgeKind::OuterError, side),
                    RxIndex::ChildBridge(ChildBridgeKind::AB, side),
                    RxIndex::ChildBridge(ChildBridgeKind::Query, side),
                    RxIndex::ChildBridge(ChildBridgeKind::Eval, side),
                ];
                let claim_slots =
                    (0..polys).map(|slot| RxIndex::ChildBridgeClaim(slot as u32, side));
                for component in fixed.into_iter().chain(claim_slots) {
                    for (group, rx) in groups.iter_mut().zip(source.rx(component)) {
                        group.push(rx);
                    }
                }

                processor
                    .grouped_bonding_claim(id, groups.into_iter().map(|group| group.into_iter()))?;
            }
        }
    }

    Ok(())
}

/// Trait for providing $k(y)$ values for nested claim verification.
pub trait KySource {
    /// The $k(y)$ value type.
    type Ky: Clone;

    /// Returns 1 for circuit checks.
    fn one(&self) -> Self::Ky;

    /// Returns 0 for stage checks.
    fn zero(&self) -> Self::Ky;
}

/// Build an iterator over $k(y)$ values in nested claim order.
///
/// Returns:
/// - `num_steps` ones (for EndoscalingStep circuit checks, single-proof verification)
/// - Infinite zeros (for stage checks)
pub fn ky_values<S: KySource>(source: &S, polys: usize) -> impl Iterator<Item = S::Ky> {
    let num_steps = super::num_endoscaling_steps(polys);

    // Circuit checks: k(y) = 1 (for single-proof, num_circuit_claims = num_steps)
    core::iter::repeat_n(source.one(), num_steps)
        // Masking checks: k(y) = 0 (infinite, matches how native does it)
        .chain(core::iter::repeat(source.zero()))
}
