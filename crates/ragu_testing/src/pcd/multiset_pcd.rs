//! PCD test fixtures that exercise [`enforce_poly_product`].
//!
//! A small multiset-accumulation proof system. Multisets are encoded as products
//! of `(X − sᵢ)`, so a union is a polynomial product:
//!
//! * [`MultisetLeaf`] — a leaf step that carries a prover-supplied polynomial
//!   and commitment as PCD data, with an in-circuit Poseidon digest of the
//!   commitment as the header.
//! * [`MultisetMerge`] — a binary step that takes the product of its two child
//!   polynomials as a witness and confirms it via [`enforce_poly_product`],
//!   surfacing the three poly-query opening claims and the in-circuit
//!   `y_prod = y_a·y_b` check.
//!
//! Both are generic over the [`Cycle`] `C`, so they can be registered in an
//! application and exercised end to end (seed two leaves, fuse via the merge
//! step, verify) without binding `ragu_testing` to a concrete curve cycle.
//!
//! Like the other fixtures here, this favours exercising the machinery over
//! rigorous binding: a node does not re-check that a child's carried commitment
//! and polynomial match its header digest — an honest prover supplies
//! consistent data.

use core::marker::PhantomData;

use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pcd::{
    header::{Header, Suffix},
    step::{Encoded, Index, Step, StepCtx},
};
use ragu_primitives::{
    Element, GadgetExt, Point,
    allocator::{Allocator, Standard},
    poseidon::Sponge,
};

use super::poly_ops::enforce_poly_product;

/// PCD data for a multiset node: the in-circuit hash digest (the header's
/// encoded state) plus the commitment and polynomial carried alongside.
pub struct MultisetData<C: Cycle, R: Rank> {
    /// Poseidon digest binding this node's commitment; the header encodes this.
    pub hash: C::CircuitField,
    /// Commitment to [`polynomial`](Self::polynomial), on the nested curve.
    pub commitment: C::NestedCurve,
    /// The committed polynomial, carried as unstructured PCD data.
    pub polynomial: sparse::Polynomial<C::CircuitField, R>,
}

impl<C: Cycle, R: Rank> Clone for MultisetData<C, R> {
    fn clone(&self) -> Self {
        Self {
            hash: self.hash,
            commitment: self.commitment,
            polynomial: self.polynomial.clone(),
        }
    }
}

/// Header for a multiset PCD node. Its in-circuit encoding is the hash digest;
/// the commitment and polynomial travel as [`MultisetData`].
pub struct MultisetHeader<C, R>(PhantomData<(C, R)>);

impl<C: Cycle, R: Rank> Header<C::CircuitField> for MultisetHeader<C, R> {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data = MultisetData<C, R>;
    type Output = Kind![C::CircuitField; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = C::CircuitField>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness.map(|d| d.hash))
    }
}

/// Witness for [`MultisetLeaf`]: the commitment and its polynomial.
pub struct MultisetLeafWitness<C: Cycle, R: Rank> {
    pub commitment: C::NestedCurve,
    pub polynomial: sparse::Polynomial<C::CircuitField, R>,
}

/// Leaf step: packages a prover-supplied polynomial + commitment into a
/// multiset, emitting a Poseidon digest of the commitment as its header.
pub struct MultisetLeaf<'params, C: Cycle, R> {
    pub poseidon_params: &'params C::CircuitPoseidon,
    _marker: PhantomData<R>,
}

impl<'params, C: Cycle, R> MultisetLeaf<'params, C, R> {
    pub fn new(poseidon_params: &'params C::CircuitPoseidon) -> Self {
        Self {
            poseidon_params,
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, R: Rank> Step<C> for MultisetLeaf<'_, C, R> {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = MultisetLeafWitness<C, R>;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = MultisetHeader<C, R>;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, C::NestedCurve>,
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
        let commitment = witness.as_ref().map(|w| w.commitment);
        let com = Point::alloc(ctx.dr, witness.as_ref().map(|w| w.commitment))?;
        let polynomial = witness.map(|w| w.polynomial);

        let mut sponge = Sponge::new(ctx.dr, self.poseidon_params);
        com.write(ctx.dr, &mut sponge)?;
        let digest = sponge.squeeze(ctx.dr)?;
        let hash = digest.value().map(|v| *v);
        let output_encoded = Encoded::from_gadget(digest);

        let output_data = hash.and_then(|hash| {
            commitment.and_then(|commitment| {
                polynomial.map(|polynomial| MultisetData {
                    hash,
                    commitment,
                    polynomial,
                })
            })
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

/// Witness for [`MultisetMerge`]: the product polynomial and its commitment —
/// the third committed polynomial in the [`enforce_poly_product`] relation.
pub struct MultisetMergeWitness<C: Cycle, R: Rank> {
    pub commitment: C::NestedCurve,
    pub polynomial: sparse::Polynomial<C::CircuitField, R>,
}

/// Binary step: confirms `product = left · right` over its two child
/// polynomials via [`enforce_poly_product`]. Its witness is the product
/// polynomial and its commitment.
pub struct MultisetMerge<'params, C: Cycle, R> {
    pub poseidon_params: &'params C::CircuitPoseidon,
    _marker: PhantomData<R>,
}

impl<'params, C: Cycle, R> MultisetMerge<'params, C, R> {
    pub fn new(poseidon_params: &'params C::CircuitPoseidon) -> Self {
        Self {
            poseidon_params,
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, R: Rank> Step<C> for MultisetMerge<'_, C, R> {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = MultisetMergeWitness<C, R>;
    type Aux<'source> = ();
    type Left = MultisetHeader<C, R>;
    type Right = MultisetHeader<C, R>;
    type Output = MultisetHeader<C, R>;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, C::NestedCurve>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, MultisetData<C, R>>,
        right: DriverValue<D, MultisetData<C, R>>,
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

        // Reconstruct each child's committed polynomial (extracting before
        // `Encoded::new` consumes the child data).
        let com_left = Point::alloc(ctx.dr, left.as_ref().map(|d| d.commitment))?;
        let poly_left = left.as_ref().map(|d| d.polynomial.clone());
        let com_right = Point::alloc(ctx.dr, right.as_ref().map(|d| d.commitment))?;
        let poly_right = right.as_ref().map(|d| d.polynomial.clone());

        let left_encoded = Encoded::new(ctx.dr, allocator, left)?;
        let right_encoded = Encoded::new(ctx.dr, allocator, right)?;

        // The product is a witness, like its two factors. Confirm the relation
        // `product = left · right` via the poly-query / Schwartz–Zippel check.
        let product_commitment = witness.as_ref().map(|w| w.commitment);
        let product_poly = witness.map(|w| w.polynomial);
        let product_com = Point::alloc(ctx.dr, product_commitment.clone())?;

        // `enforce_poly_product` needs its own transcript: it absorbs the three
        // commitments and squeezes its Schwartz–Zippel challenge from this sponge.
        let mut relation_sponge = Sponge::new(ctx.dr, self.poseidon_params);
        enforce_poly_product(
            ctx,
            &mut relation_sponge,
            (&com_left, &poly_left),
            (&com_right, &poly_right),
            (&product_com, &product_poly),
        )?;

        // The output header digest binds the two children and the product
        // commitment.
        let mut digest_sponge = Sponge::new(ctx.dr, self.poseidon_params);
        digest_sponge.absorb(ctx.dr, left_encoded.as_gadget())?;
        digest_sponge.absorb(ctx.dr, right_encoded.as_gadget())?;
        product_com.write(ctx.dr, &mut digest_sponge)?;
        let digest = digest_sponge.squeeze(ctx.dr)?;
        let hash = digest.value().map(|v| *v);
        let output_encoded = Encoded::from_gadget(digest);

        let output_data = hash.and_then(|hash| {
            product_commitment.and_then(|commitment| {
                product_poly.map(|polynomial| MultisetData {
                    hash,
                    commitment,
                    polynomial,
                })
            })
        });

        Ok((
            (left_encoded, right_encoded, output_encoded),
            output_data,
            D::unit(),
        ))
    }
}
