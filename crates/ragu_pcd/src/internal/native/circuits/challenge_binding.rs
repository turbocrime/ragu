//! Circuit binding each child's derived challenges to the elements they were
//! derived from: per $(\text{child},\, \text{slot})$ pair it re-derives
//! $\text{challenge} = \text{Hash}(\text{inputs})$ from the [`preamble`]
//! challenge records and enforces equality; the sponge must match
//! [`padded_challenge`](crate::internal::challenge::padded_challenge) exactly.
//! What the input elements bind is the step author's responsibility — see
//! [`StepCtx::derive_challenge`](crate::step::StepCtx::derive_challenge).
//!
//! [`preamble`]: super::super::stages::preamble

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
    RevdotParameters,
    stages::{outer_error, preamble, slots},
    unified::{self, OutputBuilder},
};
use crate::framework_hooks::HookConfig;

/// See the [module-level documentation](self).
pub struct Circuit<'params, C: Cycle, R, const HEADER_SIZE: usize, J: HookConfig> {
    params: &'params C::Params,
    _marker: PhantomData<(R, J)>,
}

impl<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize, J: HookConfig>
    Circuit<'params, C, R, HEADER_SIZE, J>
{
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
    pub preamble_witness: &'a preamble::Witness<'a, C, R, HEADER_SIZE>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, J: HookConfig>
    MultiStageCircuit<C::CircuitField, R> for Circuit<'_, C, R, HEADER_SIZE, J>
{
    type Last = slots::ChallengesStage<C, R, HEADER_SIZE, J, RevdotParameters>;

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
        let builder = builder.skip_stage::<preamble::Stage<C, R, HEADER_SIZE, J>>()?;
        let builder =
            builder.skip_stage::<outer_error::Stage<C, R, HEADER_SIZE, J, RevdotParameters>>()?;
        let (challenges, builder) = builder.add_stage::<Self::Last>()?;
        let dr = builder.finish();

        let challenges = challenges.unenforced(dr, witness.as_ref().map(|w| w.preamble_witness))?;

        for child in [&challenges.left, &challenges.right] {
            for pair in child.iter() {
                let mut sponge = Sponge::new(dr, C::circuit_poseidon(self.params));
                for input in pair.inputs.iter() {
                    input.write(dr, &mut sponge)?;
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
