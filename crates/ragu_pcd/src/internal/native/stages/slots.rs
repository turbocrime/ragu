//! The challenge slots, as a stage of their own rather than a region of
//! [`preamble`](super::preamble).
//!
//! ## Why a separate stage
//!
//! `preamble` is the *root* of the native chain, and
//! [`Parent`](ragu_circuits::staging::Stage::Parent) is a path: every stage is
//! downstream of the root, so a const parameter on `preamble` is named by every
//! stage below it and by every circuit naming one of those as
//! [`Last`](ragu_circuits::staging::MultiStageCircuit::Last) — whether or not it
//! reads a single slot. Holding a slot region in `preamble` therefore makes its
//! declared counts viral to the entire native side.
//!
//! Placed at the *end* of a branch instead, only the circuits that actually read
//! the region name its counts. `hashes_1`, `hashes_2` and `inner_collapse`
//! finish upstream and stay free of `CHALLENGES` and `CHALLENGE_WIDTH`.
//!
//! ## Why the poly and claim slots are not here too
//!
//! A region can leave the root only if every circuit that reads it can end on
//! one branch, because [`Last`](ragu_circuits::staging::MultiStageCircuit::Last)
//! is a single stage and sibling branches are separate commitments — a circuit
//! sees its own branch and the shared prefix above it, never a sibling's wires.
//!
//! The challenge slots qualify: `outer_collapse` and `challenge_binding` are
//! both on the error branch. The poly and claim slots do not. `application_ky`
//! folds them on the error branch, while `compute_v` reads the claim triples and
//! the eval stage reads the poly count on the query branch — so those two
//! regions have to stay in the shared prefix, and `POLYS` and `CLAIMS` stay
//! viral with them.
//!
//! ## Why the widths are ordinary type-level constants
//!
//! Every count here is declared on
//! [`ApplicationBuilder`](crate::ApplicationBuilder), so the stage's width is a
//! compile-time expression in its own consts and
//! [`values()`](ragu_circuits::staging::Stage::values) is an ordinary number.
//! Nothing here needs a value-level layout — this is ordinary typed staging.

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
    Element, Point,
    consistent::Consistent,
    vec::{CollectFixed, ConstLen, FixedVec, Len},
};

use super::preamble::{ChallengeInstance, Witness};
use crate::Proof;

/// The challenges both children derived, in slot order: the points each was
/// hashed from, and the challenge itself.
///
/// Both children present the application's shape, so one set of counts sizes
/// both.
#[derive(Gadget, Consistent)]
pub struct ChallengesOutput<
    'dr,
    D: Driver<'dr>,
    C: Cycle<CircuitField = D::F>,
    const CHALLENGES: usize,
    const CHALLENGE_WIDTH: usize,
> {
    /// The left child's challenge slots.
    #[ragu(gadget)]
    pub left: FixedVec<ChallengeInstance<'dr, D, C, CHALLENGE_WIDTH>, ConstLen<CHALLENGES>>,
    /// The right child's challenge slots.
    #[ragu(gadget)]
    pub right: FixedVec<ChallengeInstance<'dr, D, C, CHALLENGE_WIDTH>, ConstLen<CHALLENGES>>,
}

/// The challenge slots of both children.
///
/// # Where this sits, and why
///
/// `Parent` is a *tree*, not a line: `query` and `outer_error` already both
/// branch from `preamble`. This stage is a third branch, hanging off
/// [`outer_error`](super::outer_error) as a sibling of
/// [`inner_error`](super::inner_error).
///
/// That position is chosen for cost, not taste. A circuit's trace spans every
/// gate up to its last stage, so a stage placed further down the chain charges
/// every circuit that reaches it for the stages it skips on the way: placed
/// after `inner_error`, `outer_collapse` — already the largest internal
/// circuit — skips that stage's ~400 gates and exceeds the 2048-gate bound.
/// As a sibling it starts where `inner_error` does, so the two circuits that
/// reach it pay nothing extra.
///
/// The two circuits that read challenges are `outer_collapse`, which folds a
/// child's whole instance into $k(Y)$, and `challenge_binding`, which
/// re-derives each challenge from its points. Both take this as their
/// [`Last`](ragu_circuits::staging::MultiStageCircuit::Last); `hashes_1`,
/// `hashes_2` and `inner_collapse` finish on other branches and never name
/// these counts.
///
/// `HEADER_SIZE`, `POLYS` and `CLAIMS` appear here only to name the parent
/// stage; nothing in this stage reads them. They stay because their regions
/// stay in the shared prefix — see the module docs for why those two cannot
/// follow the challenges down here.
pub struct ChallengesStage<
    C: Cycle,
    R,
    const HEADER_SIZE: usize,
    const POLYS: usize,
    const CLAIMS: usize,
    const CHALLENGES: usize,
    const CHALLENGE_WIDTH: usize,
    FP,
> {
    _marker: PhantomData<(C, R, FP)>,
}

impl<
    C: Cycle,
    R,
    const HEADER_SIZE: usize,
    const POLYS: usize,
    const CLAIMS: usize,
    const CHALLENGES: usize,
    const CHALLENGE_WIDTH: usize,
    FP,
> Default for ChallengesStage<C, R, HEADER_SIZE, POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH, FP>
{
    fn default() -> Self {
        ChallengesStage {
            _marker: PhantomData,
        }
    }
}

/// This stage's wire width: per child, per slot, the input points' coordinates
/// and then the challenge.
pub const fn num_values(challenges: usize, challenge_width: usize) -> usize {
    2 * (2 * challenge_width + 1) * challenges
}

impl<
    C: Cycle,
    R: Rank,
    const HEADER_SIZE: usize,
    const POLYS: usize,
    const CLAIMS: usize,
    const CHALLENGES: usize,
    const CHALLENGE_WIDTH: usize,
    FP: crate::internal::fold_revdot::Parameters,
> staging::Stage<C::CircuitField, R>
    for ChallengesStage<C, R, HEADER_SIZE, POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH, FP>
{
    type Parent = super::outer_error::Stage<C, R, HEADER_SIZE, POLYS, CLAIMS, FP>;
    type Witness<'source> = &'source Witness<'source, C, R, HEADER_SIZE>;
    type OutputKind =
        Kind![C::CircuitField; ChallengesOutput<'_, _, C, CHALLENGES, CHALLENGE_WIDTH>];

    fn values() -> usize {
        num_values(CHALLENGES, CHALLENGE_WIDTH)
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
            left: alloc_challenges::<D, C, R, CHALLENGES, CHALLENGE_WIDTH>(
                dr,
                witness.as_ref().map(|w| w.left.proof),
            )?,
            right: alloc_challenges::<D, C, R, CHALLENGES, CHALLENGE_WIDTH>(
                dr,
                witness.as_ref().map(|w| w.right.proof),
            )?,
        })
    }
}

/// One child's challenge slots, in the order the application circuit's instance
/// exposes them.
///
/// Shared with [`Application::verify`](crate::Application::verify), which folds
/// a root proof's own $k(Y)$ natively and so needs the same slots this stage
/// witnesses.
pub(crate) fn alloc_challenges<
    'dr,
    D: Driver<'dr, F = C::CircuitField>,
    C: Cycle,
    R: Rank,
    const CHALLENGES: usize,
    const CHALLENGE_WIDTH: usize,
>(
    dr: &mut D,
    proof: DriverValue<D, &Proof<C, R>>,
) -> Result<FixedVec<ChallengeInstance<'dr, D, C, CHALLENGE_WIDTH>, ConstLen<CHALLENGES>>> {
    let allocator = &mut ();
    ConstLen::<CHALLENGES>::range()
        .map(|i| {
            Ok(ChallengeInstance {
                points: ConstLen::<CHALLENGE_WIDTH>::range()
                    .map(|j| {
                        Point::alloc(
                            dr,
                            proof
                                .as_ref()
                                .map(|p| p.application_challenges()[i].points[j]),
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
    use crate::internal::tests::{HEADER_SIZE, R, assert_stage_values};

    /// The stage is sized by its own two axes and nothing else — the property
    /// that lets it be an ordinary typed stage rather than a value-level run.
    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&ChallengesStage::<
            Pasta,
            R,
            { HEADER_SIZE },
            1,
            1,
            2,
            2,
            crate::internal::native::RevdotParameters,
        >::default());
        assert_eq!(num_values(2, 2), 2 * 5 * 2);
        assert_eq!(num_values(0, 4), 0);
    }
}
