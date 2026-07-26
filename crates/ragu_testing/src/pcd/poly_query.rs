//! Test fixtures for the polynomial-query oracle: steps that witness a
//! polynomial, derive a challenge, evaluate at it, and enforce the evaluation
//! via [`StepCtx::enforce_poly_query`].
//!
//! [`CommitAndOpen`] is a seedable leaf exercising the full oracle loop in one
//! step: the prover witnesses a polynomial and its framework commitment (from
//! [`Application::commit_polynomial`]), derives a Fiat–Shamir challenge bound
//! to the commitment, evaluates the polynomial at the challenge, and raises a
//! poly-query claim for the evaluation. [`OpenAndHash`] merges two such
//! leaves, opening the left child's polynomial at a witnessed point and
//! chaining the commitment into a Poseidon-hash digest.
//!
//! The polynomial lives in [`HashedOpening`]'s `Data`, so it travels with
//! `Pcd<C, R, HashedOpening<R>>` and is reachable from `fuse(...)` via
//! [`Pcd::data`](ragu_pcd::Pcd::data) on the input children and from the
//! `application_data` produced for the resulting `Pcd`. It is **not**
//! exposed to the circuit — `Header::encode` only allocates the hash
//! digest. The commitment-and-opening claim view of the polynomial is
//! enforced natively by fuse via the claims raised through
//! [`StepCtx::enforce_poly_query`].
//!
//! [`Application::commit_polynomial`]: ragu_pcd::Application::commit_polynomial
//! [`StepCtx::enforce_poly_query`]: ragu_pcd::step::StepCtx::enforce_poly_query

use core::marker::PhantomData;

use ff::Field;
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pcd::{
    PolyCommitment,
    header::{Header, Suffix},
    step::{Encoded, Index, Step, StepCtx},
};
use ragu_primitives::{
    Element, GadgetExt,
    allocator::{Allocator, Standard},
    poseidon::Sponge,
};

/// Data carried by a [`HashedOpening`] header.
///
/// `hash` is the only field exposed to the circuit (via
/// [`Header::encode`]). `polynomial` is unstructured PCD data: it flows
/// through the tree alongside the proof but the circuit never sees it.
pub struct HashedOpeningData<F: Field, R: Rank> {
    pub hash: F,
    pub polynomial: sparse::Polynomial<F, R>,
}

impl<F: Field, R: Rank> Clone for HashedOpeningData<F, R> {
    fn clone(&self) -> Self {
        Self {
            hash: self.hash,
            polynomial: self.polynomial.clone(),
        }
    }
}

pub struct HashedOpening<R>(PhantomData<R>);

impl<F: Field, R: Rank> Header<F> for HashedOpening<R> {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data = HashedOpeningData<F, R>;
    type Output = Kind![F; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let hash = witness.map(|d| d.hash);
        Element::alloc(dr, allocator, hash)
    }
}

/// Witness for [`CommitAndOpen`]: a committed-polynomial handle.
///
/// `commitment` comes from
/// [`Application::commit_polynomial`](ragu_pcd::Application::commit_polynomial),
/// which bundles the polynomial with the commitment derived from it.
/// `claimed_y` overrides the honestly-computed evaluation when set; it exists
/// so tests can exercise the framework's rejection of dishonest evaluation
/// claims.
pub struct CommitAndOpenWitness<C: Cycle, R: Rank> {
    pub commitment: PolyCommitment<C, R>,
    pub claimed_y: Option<C::CircuitField>,
}

/// A seedable leaf step exercising the full poly-query oracle loop:
///
/// 1. **witness a polynomial** (prover-only data) and its framework
///    commitment (allocated in-circuit as a [`Point`](ragu_primitives::Point)),
/// 2. **derive a challenge** `z` bound to the commitment via
///    [`StepCtx::derive_challenge`],
/// 3. **evaluate** the polynomial at `z`,
/// 4. **enforce the evaluation** via [`StepCtx::enforce_poly_query`].
///
/// The output header carries a Poseidon digest binding the commitment, and
/// the polynomial rides along as PCD data.
pub struct CommitAndOpen<'params, C: Cycle, R> {
    pub poseidon_params: &'params C::CircuitPoseidon,
    _marker: PhantomData<R>,
}

impl<'params, C: Cycle, R> CommitAndOpen<'params, C, R> {
    pub fn new(poseidon_params: &'params C::CircuitPoseidon) -> Self {
        Self {
            poseidon_params,
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, R: Rank> Step<C> for CommitAndOpen<'_, C, R> {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = CommitAndOpenWitness<C, R>;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = HashedOpening<R>;

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
        let allocator = &mut Standard::new();

        // (1) Witness the committed polynomial: allocate its commitment
        // in-circuit and retain the polynomial for the claim.
        let claimed_y = witness.as_ref().map(|w| w.claimed_y);
        let commitment = witness.map(|w| w.commitment);
        let handle = ctx.witness_polynomial(commitment)?;

        // (2) Derive a challenge bound to the commitment.
        let z = ctx.derive_challenge(handle.commitment().clone())?;

        // (3) Evaluate the polynomial at the challenge (natively; the
        // polynomial is not in-circuit). A dishonest override, if provided,
        // takes the evaluation's place so fuse-time rejection can be tested.
        let y_value = z.value().map(|z| *z).and_then(|z| {
            handle
                .polynomial()
                .as_ref()
                .and_then(|p| claimed_y.map(|claimed| claimed.unwrap_or_else(|| p.eval(z))))
        });
        let y = Element::alloc(ctx.dr, allocator, y_value)?;

        // (4) Enforce the evaluation as a poly-query claim.
        ctx.enforce_poly_query(&handle, z, y)?;

        // (5) Open the *same* polynomial a second time, at x = 0. This is the
        // cheap direction: a repeat opening spends one query slot and no
        // polynomial slot — no second `witness_polynomial`, so no second bridge
        // stage, commitment, MSM or endoscaling point. Exercising it here means
        // every test in this fixture's suite covers it end to end.
        let zero = Element::alloc(ctx.dr, allocator, D::just(|| C::CircuitField::ZERO))?;
        let at_zero_value = handle
            .polynomial()
            .as_ref()
            .map(|p| p.eval(C::CircuitField::ZERO));
        let at_zero = Element::alloc(ctx.dr, allocator, at_zero_value)?;
        ctx.enforce_poly_query(&handle, zero, at_zero)?;

        // Output digest binds the commitment.
        let mut sponge = Sponge::new(ctx.dr, self.poseidon_params);
        handle.commitment().write(ctx.dr, &mut sponge)?;
        let output = sponge.squeeze(ctx.dr)?;
        let output_hash = output.value().map(|v| *v);
        let output_encoded = Encoded::from_gadget(output);

        let output_data = output_hash.and_then(|hash| {
            handle
                .polynomial()
                .clone()
                .map(|polynomial| HashedOpeningData { hash, polynomial })
        });

        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                output_encoded,
            ),
            output_data,
            D::unit(),
        ))
    }
}

/// Witness for [`OpenAndHash`]: an opening `(x, y)` of a committed polynomial.
pub struct OpenAndHashWitness<C: Cycle, R: Rank> {
    pub commitment: PolyCommitment<C, R>,
    pub x: C::CircuitField,
    pub y: C::CircuitField,
}

/// A step that merges two [`HashedOpening`] children: it opens a witnessed
/// polynomial commitment at a witnessed point, chains the commitment and both
/// children's digests into a Poseidon-hash digest, and threads the
/// polynomial through the PCD tree as accompanying data.
pub struct OpenAndHash<'params, C: Cycle, R> {
    pub poseidon_params: &'params C::CircuitPoseidon,
    _marker: PhantomData<R>,
}

impl<'params, C: Cycle, R> OpenAndHash<'params, C, R> {
    pub fn new(poseidon_params: &'params C::CircuitPoseidon) -> Self {
        Self {
            poseidon_params,
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, R: Rank> Step<C> for OpenAndHash<'_, C, R> {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = OpenAndHashWitness<C, R>;
    type Aux<'source> = ();
    type Left = HashedOpening<R>;
    type Right = HashedOpening<R>;
    type Output = HashedOpening<R>;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, C>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, HashedOpeningData<C::CircuitField, R>>,
        right: DriverValue<D, HashedOpeningData<C::CircuitField, R>>,
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
        let allocator = &mut Standard::new();
        let left_encoded = Encoded::new(ctx.dr, allocator, left)?;
        let right_encoded = Encoded::new(ctx.dr, allocator, right)?;

        let x_witness = witness.as_ref().map(|w| w.x);
        let y_witness = witness.as_ref().map(|w| w.y);
        let commitment = witness.map(|w| w.commitment);
        let handle = ctx.witness_polynomial(commitment)?;

        let x = Element::alloc(ctx.dr, allocator, x_witness)?;
        let y = Element::alloc(ctx.dr, allocator, y_witness)?;

        let mut sponge = Sponge::new(ctx.dr, self.poseidon_params);
        sponge.absorb(ctx.dr, left_encoded.as_gadget())?;
        sponge.absorb(ctx.dr, right_encoded.as_gadget())?;
        handle.commitment().write(ctx.dr, &mut sponge)?;
        let output = sponge.squeeze(ctx.dr)?;
        let output_hash = output.value().map(|v| *v);
        let output_encoded = Encoded::from_gadget(output);

        ctx.enforce_poly_query(&handle, x, y)?;

        let output_data = output_hash.and_then(|hash| {
            handle
                .polynomial()
                .clone()
                .map(|polynomial| HashedOpeningData { hash, polynomial })
        });

        Ok((
            (left_encoded, right_encoded, output_encoded),
            output_data,
            D::unit(),
        ))
    }
}
