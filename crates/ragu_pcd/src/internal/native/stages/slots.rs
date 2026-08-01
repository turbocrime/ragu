//! The challenge slots, as a stage of their own rather than a region of
//! [`preamble`](super::preamble): only their readers (`outer_collapse` and
//! `challenge_binding`, both on the error branch) name the challenge counts.
//! The poly and claim slots have readers on both branches, so they stay in
//! the shared prefix.

use core::marker::PhantomData;

use ragu_arithmetic::Cycle;
use ragu_circuits::{polynomials::Rank, staging};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
    consistent::Consistent,
    vec::{CollectFixed, Len},
};

use super::preamble::{ChallengeInstance, ChallengeVec, Witness};
use crate::{Proof, framework_hooks::HookConfig};

/// The challenges both children derived, in slot order: the elements each was
/// hashed from, and the challenge itself.
#[derive(Gadget, Consistent)]
pub struct ChallengesOutput<'dr, D: Driver<'dr>, J: HookConfig> {
    /// The left child's challenge slots.
    #[ragu(gadget)]
    pub left: ChallengeVec<'dr, D, J>,
    /// The right child's challenge slots.
    #[ragu(gadget)]
    pub right: ChallengeVec<'dr, D, J>,
}

/// The challenge slots of both children.
///
/// Branches off [`outer_error`](super::outer_error) as a sibling of
/// [`inner_error`](super::inner_error), so its readers pay nothing extra.
pub struct ChallengesStage<C: Cycle, R, const HEADER_SIZE: usize, J: HookConfig, FP> {
    _marker: PhantomData<(C, R, J, FP)>,
}

impl<C: Cycle, R, const HEADER_SIZE: usize, J: HookConfig, FP> Default
    for ChallengesStage<C, R, HEADER_SIZE, J, FP>
{
    fn default() -> Self {
        ChallengesStage {
            _marker: PhantomData,
        }
    }
}

impl<
    C: Cycle,
    R: Rank,
    const HEADER_SIZE: usize,
    J: HookConfig,
    FP: crate::internal::fold_revdot::Parameters,
> staging::Stage<C::CircuitField, R> for ChallengesStage<C, R, HEADER_SIZE, J, FP>
{
    type Parent = super::outer_error::Stage<C, R, HEADER_SIZE, J, FP>;
    type Witness<'source> = &'source Witness<'source, C, R, HEADER_SIZE>;
    type OutputKind = Kind![C::CircuitField; ChallengesOutput<'_, _, J>];

    fn values() -> usize {
        // One challenge instance region per child.
        2 * J::layout().challenge_instance_len()
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        Ok(ChallengesOutput {
            left: alloc_challenges::<D, C, R, J>(dr, witness.as_ref().map(|w| w.left.proof))?,
            right: alloc_challenges::<D, C, R, J>(dr, witness.as_ref().map(|w| w.right.proof))?,
        })
    }
}

/// One child's challenge slots, in the order the application circuit's instance
/// exposes them. Shared with [`Application::verify`](crate::Application::verify).
pub(crate) fn alloc_challenges<
    'dr,
    D: Driver<'dr, F = C::CircuitField>,
    C: Cycle,
    R: Rank,
    J: HookConfig,
>(
    dr: &mut D,
    proof: DriverValue<D, &Proof<C, R>>,
) -> Result<ChallengeVec<'dr, D, J>> {
    let allocator = &mut ();
    J::ChallengeDerivations::range()
        .map(|i| {
            Ok(ChallengeInstance {
                inputs: J::ChallengeWidth::range()
                    .map(|j| {
                        Element::alloc(
                            dr,
                            allocator,
                            proof
                                .as_ref()
                                .map(|p| p.application_challenges()[i].inputs[j]),
                        )
                    })
                    .try_collect_fixed()?,
                challenge: Element::alloc(
                    dr,
                    allocator,
                    proof
                        .as_ref()
                        .map(|p| p.application_challenges()[i].challenge),
                )?,
            })
        })
        .try_collect_fixed()
}

#[cfg(test)]
mod tests {
    use ragu_pasta::Pasta;

    use super::*;
    use crate::{
        AppHooks,
        internal::tests::{HEADER_SIZE, R, assert_stage_values},
    };

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&ChallengesStage::<
            Pasta,
            R,
            { HEADER_SIZE },
            AppHooks<1, 1, 2, 2>,
            crate::internal::native::RevdotParameters,
        >::default());
    }
}
