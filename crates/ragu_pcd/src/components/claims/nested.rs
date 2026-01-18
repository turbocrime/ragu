//! Claim orchestration for nested field (scalar field) rx polynomials.
//!
//! This module provides a unified interface for assembling `a` and `b`
//! polynomial vectors for nested field revdot claim verification.
//!
//! The nested claim structure is simpler than native:
//! - Circuit checks (EndoscalingStep): k(y) = 1
//! - Stage checks (EndoscalarStage, PointsStage, PointsFinalStaged): k(y) = 0

use alloc::borrow::Cow;

use ff::PrimeField;
use ragu_circuits::{
    mesh::CircuitIndex,
    polynomials::{Rank, structured},
};
use ragu_core::Result;

use super::{Builder, Source};
use crate::circuits::nested::InternalCircuitIndex;

/// Enum identifying which nested field rx polynomial to retrieve from a proof.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub enum RxComponent {
    /// EndoscalarStage rx polynomial.
    EndoscalarStage,
    /// PointsStage rx polynomial.
    PointsStage,
    /// EndoscalingStep circuit rx polynomial (indexed by step number).
    EndoscalingStep(usize),
}

/// Trait for processing nested claim values into accumulated outputs.
///
/// This trait defines how to process rx values from a [`Source`].
#[allow(dead_code)]
pub trait Processor<Rx> {
    /// Process an internal circuit claim (EndoscalingStep) - sums rxs then processes.
    fn internal_circuit(&mut self, step: usize, rxs: impl Iterator<Item = Rx>);

    /// Process a stage claim - aggregates rxs from all proofs.
    fn stage(&mut self, id: InternalCircuitIndex, rxs: impl Iterator<Item = Rx>) -> Result<()>;
}

impl<'m, 'rx, F: PrimeField, R: Rank> Processor<&'rx structured::Polynomial<F, R>>
    for Builder<'m, 'rx, F, R>
{
    fn internal_circuit(
        &mut self,
        step: usize,
        mut rxs: impl Iterator<Item = &'rx structured::Polynomial<F, R>>,
    ) {
        // EndoscalingStepStart = 3, so step N is at circuit index 3+N
        let circuit_id =
            CircuitIndex::new(InternalCircuitIndex::EndoscalingStepStart as usize + step);

        let first = rxs.next().expect("must provide at least one rx polynomial");

        let rx = match rxs.next() {
            None => Cow::Borrowed(first),
            Some(second) => {
                let mut sum = first.clone();
                sum.add_assign(second);
                for rx in rxs {
                    sum.add_assign(rx);
                }
                Cow::Owned(sum)
            }
        };

        self.circuit_impl(circuit_id, rx);
    }

    fn stage(
        &mut self,
        id: InternalCircuitIndex,
        mut rxs: impl Iterator<Item = &'rx structured::Polynomial<F, R>>,
    ) -> Result<()> {
        let first = rxs.next().expect("must provide at least one rx polynomial");

        let circuit_id = CircuitIndex::new(id as usize);
        let sy = self.mesh.circuit_y(circuit_id, self.y);

        let a = match rxs.next() {
            None => Cow::Borrowed(first),
            Some(second) => Cow::Owned(structured::Polynomial::fold(
                core::iter::once(first)
                    .chain(core::iter::once(second))
                    .chain(rxs),
                self.z,
            )),
        };

        self.a.push(a);
        self.b.push(Cow::Owned(sy));
        Ok(())
    }
}

/// Build nested claims in unified interleaved order from a source.
///
/// The ordering is:
/// 1. Circuit checks (k(y) = 1): EndoscalingStep for each step, interleaved across proofs
/// 2. Stage checks (k(y) = 0): EndoscalarStage, PointsStage, PointsFinalStaged
///
/// This ordering must match the ky_elements ordering from [`ky_values`].
pub fn build<S, P>(source: &S, processor: &mut P, num_steps: usize) -> Result<()>
where
    S: Source<RxComponent = RxComponent>,
    P: Processor<S::Rx>,
{
    use RxComponent::*;

    // 1. Circuit checks FIRST (k(y) = 1)
    // Process all EndoscalingStep circuits (interleaved across proofs)
    // Each circuit claim needs: step_rx + endoscalar_rx + points_rx
    for step in 0..num_steps {
        for ((step_rx, endo_rx), pts_rx) in source
            .rx(EndoscalingStep(step))
            .zip(source.rx(EndoscalarStage))
            .zip(source.rx(PointsStage))
        {
            processor.internal_circuit(step, [step_rx, endo_rx, pts_rx].into_iter());
        }
    }

    // 2. Stage checks SECOND (k(y) = 0)
    // EndoscalarStage (index 0)
    processor.stage(
        InternalCircuitIndex::EndoscalarStage,
        source.rx(EndoscalarStage),
    )?;

    // PointsStage (index 1)
    processor.stage(InternalCircuitIndex::PointsStage, source.rx(PointsStage))?;

    // PointsFinalStaged (index 2) - final stage check
    // Aggregates all EndoscalingStep rxs from all proofs
    {
        let final_rxs = (0..num_steps).flat_map(|step| source.rx(EndoscalingStep(step)));
        processor.stage(InternalCircuitIndex::PointsFinalStaged, final_rxs)?;
    }

    Ok(())
}

/// Trait for providing k(y) values for nested claim verification.
#[allow(dead_code)]
pub trait KySource {
    /// The k(y) value type.
    type Ky: Clone;

    /// Returns 1 for circuit checks.
    fn one(&self) -> Self::Ky;

    /// Returns 0 for stage checks.
    fn zero(&self) -> Self::Ky;

    /// Number of circuit claims (num_steps * num_proofs).
    fn num_circuit_claims(&self) -> usize;
}

/// Build an iterator over k(y) values in nested claim order.
///
/// Returns:
/// - `num_circuit_claims` ones (for EndoscalingStep circuit checks)
/// - Infinite zeros (for stage checks)
#[allow(dead_code)]
pub fn ky_values<S: KySource>(source: &S) -> impl Iterator<Item = S::Ky> {
    // Circuit checks: k(y) = 1
    core::iter::repeat_n(source.one(), source.num_circuit_claims())
        // Stage checks: k(y) = 0 (infinite, matches how native does it)
        .chain(core::iter::repeat(source.zero()))
}
