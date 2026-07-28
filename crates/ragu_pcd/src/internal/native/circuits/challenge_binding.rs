//! Circuit binding each child's derived challenges to the points they were
//! derived from.
//!
//! ## Operations
//!
//! An application circuit obtains a challenge through
//! [`StepCtx::derive_challenge`], which exposes that slot's input points and the
//! challenge on the circuit's instance. The derivation itself does **not**
//! happen in the application circuit — a step spends no permutation and commits
//! no stage for it. This circuit is where the permutations are actually paid
//! for, once per $(\text{child},\, \text{slot})$ pair, out of the framework's own
//! gate budget:
//!
//! - Witness each child's challenge records from the [`preamble`] stage.
//! - For each, absorb every input point into a fresh sponge and squeeze.
//! - Enforce that the squeezed value equals the recorded challenge.
//!
//! With the application's challenge slots, two children, and
//! [`ChallengeLayout::width`](crate::framework_hooks::ChallengeLayout::width)
//! per slot, that is
//! $2 \cdot \text{slots} \cdot \lceil 2 \cdot \text{points} / \text{RATE} \rceil$
//! permutations.
//!
//! ## Why this closes the derivation
//!
//! Without this circuit a challenge is a free witness: an interior prover picks
//! whichever value makes its argument go through, and grinds. Two links make the
//! record rigid:
//!
//! 1. A slot's points and its challenge are all written into the child's
//!    application $k(Y)$
//!    ([`application_ky`](super::super::stages::preamble::ProofInputs::application_ky)),
//!    binding them to the child's committed application rx.
//! 2. **This circuit**: $\text{challenge} = \text{Hash}(\text{points})$.
//!
//! Together they say the challenge is the hash of exactly the points the
//! application passed, so a prover cannot choose it independently of them.
//! **What those points bind is the step author's responsibility** — see
//! [`StepCtx::derive_challenge`] for the contract.
//! The prover-side counterpart is
//! [`challenge_from_points`](crate::internal::challenge::challenge_from_points),
//! which runs the identical sponge natively; the two must agree exactly.
//!
//! ## Staging
//!
//! This circuit uses [`preamble`] as its final stage, taken unenforced —
//! [`compute_v`] enforces it, and both read the same bonded stage rx.
//!
//! ## Instance
//!
//! Uses [`unified::Output`] as its instance via [`unified::InternalOutputKind`].
//! This circuit covers no unified slot: it constrains child data, not the
//! current step's transcript.
//!
//! [`StepCtx::derive_challenge`]: crate::step::StepCtx::derive_challenge
//! [`preamble`]: super::super::stages::preamble
//! [`compute_v`]: super::compute_v

use core::marker::PhantomData;

use ragu_arithmetic::Cycle;
use ragu_circuits::{
    WithAux,
    polynomials::Rank,
    staging::{MultiStage, MultiStageCircuit, StageBuilder},
};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe,
};
use ragu_primitives::{GadgetExt as _, allocator::Standard, poseidon::Sponge};

use super::super::{
    stages::preamble,
    unified::{self, OutputBuilder},
};

/// Circuit that re-derives every child challenge from its point.
///
/// See the [module-level documentation] for details on the operations
/// performed by this circuit.
///
/// [module-level documentation]: self
pub struct Circuit<
    'params,
    C: Cycle,
    R,
    const HEADER_SIZE: usize,
    const POLYS: usize,
    const CLAIMS: usize,
    const CHALLENGES: usize,
    const CHALLENGE_WIDTH: usize,
> {
    params: &'params C::Params,
    _marker: PhantomData<(R,)>,
}

impl<
    'params,
    C: Cycle,
    R: Rank,
    const HEADER_SIZE: usize,
    const POLYS: usize,
    const CLAIMS: usize,
    const CHALLENGES: usize,
    const CHALLENGE_WIDTH: usize,
> Circuit<'params, C, R, HEADER_SIZE, POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH>
{
    /// Creates a new multi-stage circuit.
    ///
    /// # Parameters
    ///
    /// - `params`: Curve cycle parameters providing Poseidon configuration.
    pub fn new(params: &'params C::Params) -> MultiStage<C::CircuitField, R, Self> {
        MultiStage::new(Circuit {
            params,
            _marker: PhantomData,
        })
    }
}

/// Witness data for the challenge binding circuit.
pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    /// The unified instance, threaded through the internal circuits.
    pub unified: unified::Instance<C>,

    /// Witness for the [`preamble`] stage (unenforced).
    ///
    /// Provides each child's `(points, challenge)` records.
    pub preamble_witness: &'a preamble::Witness<'a, C, R, HEADER_SIZE>,
}

impl<
    C: Cycle,
    R: Rank,
    const HEADER_SIZE: usize,
    const POLYS: usize,
    const CLAIMS: usize,
    const CHALLENGES: usize,
    const CHALLENGE_WIDTH: usize,
> MultiStageCircuit<C::CircuitField, R>
    for Circuit<'_, C, R, HEADER_SIZE, POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH>
{
    type Last =
        preamble::Stage<C, R, HEADER_SIZE, POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> = Witness<'source, C, R, HEADER_SIZE>;
    type Output = unified::InternalOutputKind<C>;
    type Aux<'source> = unified::Instance<C>;

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        _: &mut D,
        _: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<Bound<'dr, D, Self::Output>>
    where
        Self: 'dr,
    {
        unreachable!("instance for internal circuits is not invoked")
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        builder: StageBuilder<'a, 'dr, D, R, (), Self::Last>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, Self::Aux<'source>>>>
    where
        Self: 'dr,
    {
        let (preamble, builder) = builder.add_stage::<Self::Last>()?;
        let dr = builder.finish();

        let preamble = preamble.unenforced(dr, witness.as_ref().map(|w| w.preamble_witness))?;

        // Re-derive each child's challenges. A fresh sponge per slot, matching
        // `challenge_from_points` exactly: absorb every input point in slot
        // order, squeeze once. A fresh sponge per slot rather than one chained
        // sponge, so slot i's challenge cannot depend on slot i-1's inputs —
        // and it is no more expensive, since each squeeze costs a permutation
        // regardless.
        for child in [&preamble.left, &preamble.right] {
            for pair in child.challenges.iter() {
                let mut sponge = Sponge::new(dr, C::circuit_poseidon(self.params));
                for point in pair.points.iter() {
                    point.write(dr, &mut sponge)?;
                }
                let derived = sponge.squeeze(dr)?;
                derived.enforce_equal(dr, &pair.challenge)?;
            }
        }

        let allocator = &mut Standard::new();
        let unified_output = OutputBuilder::new(witness.map(|w| w.unified));
        let (output, aux) = unified_output.finish(dr, allocator)?;
        Ok(WithAux::new(output, aux))
    }
}
