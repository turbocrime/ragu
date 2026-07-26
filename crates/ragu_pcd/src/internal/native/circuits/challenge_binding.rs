//! Circuit binding each child's derived challenges to the points they were
//! derived from.
//!
//! ## Operations
//!
//! An application circuit obtains a challenge through
//! [`StepCtx::derive_challenge`], which exposes the pair
//! $(\text{point}_i,\, \text{challenge}_i)$ on the circuit's instance for every
//! challenge slot $i$. The derivation itself — one Poseidon permutation — does
//! **not** happen in the application circuit; that is the whole point of the
//! staged design, which spends a single gate per slot there instead of $288$.
//! This circuit is where the permutation is actually paid for, once per
//! $(\text{child},\, \text{slot})$ pair, out of the framework's own gate budget:
//!
//! - Witness each child's challenge pairs from the [`preamble`] stage.
//! - For each pair, absorb $\text{point}_i$ into a fresh sponge and squeeze.
//! - Enforce that the squeezed value equals $\text{challenge}_i$.
//!
//! With [`NUM_CHALLENGE_SLOTS`] slots and two children that is
//! $2 \cdot \text{NUM\\_CHALLENGE\\_SLOTS}$ permutations.
//!
//! ## Why this closes the derivation
//!
//! Without this circuit a challenge is a free witness: an interior prover picks
//! whichever value makes its argument go through, and grinds. The three links
//! that make the pair rigid are:
//!
//! 1. $\text{challenge}_i$ and $\text{point}_i$ are both written into the
//!    child's application $k(Y)$
//!    ([`application_ky`](super::super::stages::preamble::ProofInputs::application_ky)),
//!    binding them to the child's committed application rx.
//! 2. $\text{point}_i$ is the bridge image of slot $i$'s challenge-stage
//!    commitment, tied in the nested `loading` circuit and folded into the
//!    endoscaling — so it commits to the stage inputs the application supplied.
//! 3. **This circuit**: $\text{challenge}_i = \text{Hash}(\text{point}_i)$.
//!
//! Together they say the challenge is the hash of a commitment to its own
//! inputs, which is what makes it unpredictable to the prover that chose them.
//! The prover-side counterpart is
//! [`staged_challenge`](crate::internal::challenge::staged_challenge), which
//! runs the identical sponge natively; the two must agree exactly.
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
//! [`NUM_CHALLENGE_SLOTS`]: crate::NUM_CHALLENGE_SLOTS

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
    const MAX_WITNESSED_POLYS: usize,
    const MAX_POLY_QUERIES: usize,
> {
    params: &'params C::Params,
    _marker: PhantomData<(R,)>,
}

impl<
    'params,
    C: Cycle,
    R: Rank,
    const HEADER_SIZE: usize,
    const MAX_WITNESSED_POLYS: usize,
    const MAX_POLY_QUERIES: usize,
> Circuit<'params, C, R, HEADER_SIZE, MAX_WITNESSED_POLYS, MAX_POLY_QUERIES>
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
pub struct Witness<
    'a,
    C: Cycle,
    R: Rank,
    const HEADER_SIZE: usize,
    const MAX_WITNESSED_POLYS: usize,
    const MAX_POLY_QUERIES: usize,
> {
    /// The unified instance, threaded through the internal circuits.
    pub unified: unified::Instance<C>,

    /// Witness for the [`preamble`] stage (unenforced).
    ///
    /// Provides each child's `(point, challenge)` pairs.
    pub preamble_witness:
        &'a preamble::Witness<'a, C, R, HEADER_SIZE, MAX_WITNESSED_POLYS, MAX_POLY_QUERIES>,
}

impl<
    C: Cycle,
    R: Rank,
    const HEADER_SIZE: usize,
    const MAX_WITNESSED_POLYS: usize,
    const MAX_POLY_QUERIES: usize,
> MultiStageCircuit<C::CircuitField, R>
    for Circuit<'_, C, R, HEADER_SIZE, MAX_WITNESSED_POLYS, MAX_POLY_QUERIES>
{
    type Last = preamble::Stage<C, R, HEADER_SIZE, MAX_WITNESSED_POLYS, MAX_POLY_QUERIES>;

    type Instance<'source> = &'source unified::Instance<C>;
    type Witness<'source> =
        Witness<'source, C, R, HEADER_SIZE, MAX_WITNESSED_POLYS, MAX_POLY_QUERIES>;
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
        let (preamble, builder) = builder.add_stage::<preamble::Stage<
            C,
            R,
            HEADER_SIZE,
            MAX_WITNESSED_POLYS,
            MAX_POLY_QUERIES,
        >>()?;
        let dr = builder.finish();

        let preamble = preamble.unenforced(dr, witness.as_ref().map(|w| w.preamble_witness))?;

        // Re-derive each child's challenges. A fresh sponge per slot, matching
        // `staged_challenge` exactly: absorb the point, squeeze once. Chaining
        // the slots into one sponge would not be cheaper — each squeeze costs a
        // permutation regardless — and would make slot i's challenge depend on
        // slot i-1's inputs.
        for child in [&preamble.left, &preamble.right] {
            for pair in child.challenges.iter() {
                let mut sponge = Sponge::new(dr, C::circuit_poseidon(self.params));
                pair.point.write(dr, &mut sponge)?;
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
