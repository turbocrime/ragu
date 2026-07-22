//! Test fixtures for the *sound* polynomial oracle
//! ([`ragu_pcd::oracle::WitnessedPolynomial`]): the polynomial lives
//! in-circuit, so witnessing, challenge derivation, evaluation, and
//! enforcement are all constrained by the application circuit and inherit the
//! proof system's soundness — no native side-channels.
//!
//! [`SoundOpen`] is a seedable leaf performing the full loop in one step;
//! [`SoundMerge`] consumes two such leaves and demonstrates sound cross-node
//! chaining: it re-witnesses each child's coefficients and equates their
//! recomputed hash commitment with the child's header element, which the PCD
//! scheme binds to the child's proof.

use core::marker::PhantomData;

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pcd::{
    header::{Header, Suffix},
    oracle::WitnessedPolynomial,
    step::{Encoded, Index, Step, StepCtx},
};
use ragu_primitives::{Element, GadgetExt, allocator::Allocator};

/// Capacity of the in-circuit polynomials in these fixtures. All structural
/// quantities (wire count, hash width, evaluation cost) depend only on this.
pub const CAPACITY: usize = 8;

/// Data carried by a [`SoundHeader`]: the polynomial's in-circuit Poseidon
/// hash commitment (the only part exposed to the circuit via
/// [`Header::encode`]) and its coefficients (re-witnessed by consuming
/// steps, which recompute and equate the hash).
#[derive(Clone)]
pub struct SoundOpeningData<F: Field> {
    pub com: F,
    pub coefficients: Vec<F>,
}

pub struct SoundHeader;

impl<F: Field> Header<F> for SoundHeader {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data = SoundOpeningData<F>;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness.map(|d| d.com))
    }
}

/// Witness for [`SoundOpen`]: the polynomial's coefficients, plus an optional
/// dishonest evaluation override used by tests to demonstrate that the
/// circuit rejects false claims.
pub struct SoundOpenWitness<F: Field> {
    pub coefficients: Vec<F>,
    pub claimed_y: Option<F>,
}

/// A seedable leaf performing the full sound oracle loop in-circuit:
///
/// 1. **witness a polynomial** ([`WitnessedPolynomial::alloc`]),
/// 2. commit to it ([`WitnessedPolynomial::hash_commitment`]),
/// 3. **derive a challenge** bound to the commitment
///    ([`StepCtx::derive_challenge`]),
/// 4. **evaluate** at the challenge ([`WitnessedPolynomial::eval`]),
/// 5. **enforce the evaluation** against the claimed value
///    ([`GadgetExt::enforce_equal`]).
///
/// Every arrow is a circuit constraint; a witness violating any of them
/// cannot yield a valid proof.
pub struct SoundOpen<C>(PhantomData<C>);

impl<C> SoundOpen<C> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<C> Default for SoundOpen<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Cycle> Step<C> for SoundOpen<C> {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = SoundOpenWitness<C::CircuitField>;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = SoundHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, C>,
        witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, ()>,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let claimed_y = witness.as_ref().map(|w| w.claimed_y);
        let coefficients = witness.map(|w| w.coefficients);

        // (1) Witness the polynomial in-circuit.
        let poly = WitnessedPolynomial::alloc(ctx.dr, CAPACITY, coefficients.clone())?;

        // (2) In-circuit binding commitment.
        let com = poly.hash_commitment(ctx.dr, ctx.poseidon())?;

        // (3) Sound Fiat–Shamir challenge bound to the commitment.
        let z = ctx.derive_challenge(com.clone())?;

        // (4) Evaluate at the challenge, in-circuit.
        let y = poly.eval(ctx.dr, &z)?;

        // (5) Enforce the evaluation against the claimed value. The honest
        // claimed value *is* the evaluation; a dishonest override makes the
        // constraint unsatisfiable.
        let claimed = Element::alloc(
            ctx.dr,
            &mut ragu_primitives::allocator::Standard::new(),
            claimed_y.and_then(|claimed| y.value().map(|y| claimed.unwrap_or(*y))),
        )?;
        y.enforce_equal(ctx.dr, &claimed)?;

        let output_data = com.value().map(|com| *com).and_then(|com| {
            coefficients.map(|coefficients| SoundOpeningData { com, coefficients })
        });

        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(com),
            ),
            output_data,
            D::unit(),
        ))
    }
}

/// Merges two [`SoundOpen`] leaves with sound cross-node chaining: each
/// child's coefficients are re-witnessed and their recomputed hash commitment
/// is equated in-circuit with the child's header element (which the PCD
/// scheme binds to the child's proof). A challenge is derived over both
/// commitments and the children's evaluations at it are combined into the
/// output commitment's preimage, exercising multi-input challenges.
pub struct SoundMerge<C>(PhantomData<C>);

impl<C> SoundMerge<C> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<C> Default for SoundMerge<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Cycle> Step<C> for SoundMerge<C> {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = SoundHeader;
    type Right = SoundHeader;
    type Output = SoundHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, C>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, SoundOpeningData<C::CircuitField>>,
        right: DriverValue<D, SoundOpeningData<C::CircuitField>>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut ragu_primitives::allocator::Standard::new();
        let left_encoded = Encoded::new(ctx.dr, allocator, left.clone())?;
        let right_encoded = Encoded::new(ctx.dr, allocator, right.clone())?;

        // Re-witness each child's polynomial and bind it to the child's
        // header commitment: recompute the hash in-circuit and equate it with
        // the header element the PCD scheme vouches for.
        let left_poly = WitnessedPolynomial::alloc(ctx.dr, CAPACITY, left.map(|d| d.coefficients))?;
        let right_poly =
            WitnessedPolynomial::alloc(ctx.dr, CAPACITY, right.map(|d| d.coefficients))?;
        let left_com = left_poly.hash_commitment(ctx.dr, ctx.poseidon())?;
        let right_com = right_poly.hash_commitment(ctx.dr, ctx.poseidon())?;
        left_com.enforce_equal(ctx.dr, left_encoded.as_gadget())?;
        right_com.enforce_equal(ctx.dr, right_encoded.as_gadget())?;

        // Derive a challenge bound to both commitments, evaluate both
        // children at it, and fold the evaluations into the output
        // commitment: com_out = H(left_com, right_com, y_l, y_r).
        let z = ctx.derive_challenge((left_com.clone(), right_com.clone()))?;
        let y_left = left_poly.eval(ctx.dr, &z)?;
        let y_right = right_poly.eval(ctx.dr, &z)?;

        let mut sponge = ragu_primitives::poseidon::Sponge::new(ctx.dr, ctx.poseidon());
        sponge.absorb(ctx.dr, &left_com)?;
        sponge.absorb(ctx.dr, &right_com)?;
        sponge.absorb(ctx.dr, &y_left)?;
        sponge.absorb(ctx.dr, &y_right)?;
        let out = sponge.squeeze(ctx.dr)?;

        // The output "polynomial" is the constant polynomial [out]; its data
        // carries the digest so the header re-encodes consistently.
        let out_value = out.value().map(|v| *v);
        let output_data = out_value.map(|com| SoundOpeningData {
            com,
            coefficients: vec![com],
        });

        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(out)),
            output_data,
            D::unit(),
        ))
    }
}
