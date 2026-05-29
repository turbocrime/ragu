//! Single-step PCD fixtures that make plain the [`poly_ops`](super::poly_ops)
//! relations are about *polynomial relationships*, not PCD tree structure.
//!
//! Each step here is a leaf (`Left = Right = ()`): it witnesses **all** of its
//! polynomials locally — both operands and the result — confirms the relation in
//! one shot, and **outputs the result set**. There are no children to fuse and
//! no lineage to build; the operands are plain witnesses, not the outputs of
//! prior proofs.
//!
//! * [`MergeMultisets`] witnesses two multisets (encoded as root polynomials
//!   `∏(X − sᵢ)`) and their union, confirms `union = a · b` via
//!   [`enforce_poly_product`], and outputs the [`MergedMultiset`].
//! * [`ConcatenateSequences`] witnesses two sequences (encoded as coefficient
//!   polynomials `Σ sᵢXⁱ`) and their concatenation, confirms
//!   `cat = a + X^shift·b` via [`enforce_poly_shifted_sum`], and outputs the
//!   [`ConcatenatedSequence`].
//! * [`SplitSequence`] witnesses a sequence and its two parts, confirms the
//!   **same** identity `cat = low + X^shift·high` via the **same**
//!   [`enforce_poly_shifted_sum`] call, and outputs the [`SplitParts`]. Split is
//!   concatenation read backwards: with all three polynomials as witnesses the
//!   enforced relation is identical — only which polynomial we regard as the
//!   input, and what the step outputs, differ.
//!
//! Contrast with [`multiset_pcd`](super::multiset_pcd), whose merge step gets its
//! operands from two *child proofs* — that fixture exists to exercise the
//! seed/fuse recursion. The operation is identical; only the provenance of the
//! operands differs.

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
use ragu_primitives::{Element, GadgetExt, Point, allocator::Allocator, poseidon::Sponge};

use super::poly_ops::{enforce_poly_product, enforce_poly_shifted_sum};

// --- Merged multiset (the product `a · b`) ---------------------------------

/// The merged multiset produced by [`MergeMultisets`]: the union's root
/// polynomial `a · b` and its commitment. The header encodes a Poseidon digest
/// of the commitment in-circuit; the commitment and polynomial travel alongside.
pub struct MergedMultisetData<C: Cycle, R: Rank> {
    /// Poseidon digest binding the merged commitment (the header's encoded state).
    pub hash: C::CircuitField,
    /// Commitment to the union polynomial, on the nested curve.
    pub commitment: C::NestedCurve,
    /// The union's root polynomial `a · b`.
    pub polynomial: sparse::Polynomial<C::CircuitField, R>,
}

impl<C: Cycle, R: Rank> Clone for MergedMultisetData<C, R> {
    fn clone(&self) -> Self {
        Self {
            hash: self.hash,
            commitment: self.commitment,
            polynomial: self.polynomial.clone(),
        }
    }
}

/// Header for a merged multiset. Its in-circuit encoding is the digest; the
/// commitment and polynomial travel as [`MergedMultisetData`].
pub struct MergedMultiset<C, R>(PhantomData<(C, R)>);

impl<C: Cycle, R: Rank> Header<C::CircuitField> for MergedMultiset<C, R> {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data = MergedMultisetData<C, R>;
    type Output = Kind![C::CircuitField; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = C::CircuitField>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness.map(|d| d.hash))
    }
}

/// Witness for [`MergeMultisets`]: both operand multisets and their union, each
/// as a commitment plus its root polynomial.
pub struct MergeMultisetsWitness<C: Cycle, R: Rank> {
    pub a_commitment: C::NestedCurve,
    pub a_polynomial: sparse::Polynomial<C::CircuitField, R>,
    pub b_commitment: C::NestedCurve,
    pub b_polynomial: sparse::Polynomial<C::CircuitField, R>,
    pub product_commitment: C::NestedCurve,
    pub product_polynomial: sparse::Polynomial<C::CircuitField, R>,
}

/// Leaf step: witnesses two multisets and their union, confirms `union = a · b`
/// via [`enforce_poly_product`], and outputs the [`MergedMultiset`]. No children.
pub struct MergeMultisets<'params, C: Cycle, R> {
    pub poseidon_params: &'params C::CircuitPoseidon,
    _marker: PhantomData<R>,
}

impl<'params, C: Cycle, R> MergeMultisets<'params, C, R> {
    pub fn new(poseidon_params: &'params C::CircuitPoseidon) -> Self {
        Self {
            poseidon_params,
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, R: Rank> Step<C> for MergeMultisets<'_, C, R> {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = MergeMultisetsWitness<C, R>;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = MergedMultiset<C, R>;

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
        // Every polynomial is a local witness — both operands and the result.
        let a_com = Point::alloc(ctx.dr, witness.as_ref().map(|w| w.a_commitment))?;
        let a_poly = witness.as_ref().map(|w| w.a_polynomial.clone());
        let b_com = Point::alloc(ctx.dr, witness.as_ref().map(|w| w.b_commitment))?;
        let b_poly = witness.as_ref().map(|w| w.b_polynomial.clone());
        let product_commitment = witness.as_ref().map(|w| w.product_commitment);
        let product_com = Point::alloc(ctx.dr, product_commitment.clone())?;
        let product_poly = witness.map(|w| w.product_polynomial);

        // Confirm the union relation: product = a · b.
        let mut relation_sponge = Sponge::new(ctx.dr, self.poseidon_params);
        enforce_poly_product(
            ctx,
            &mut relation_sponge,
            (&a_com, &a_poly),
            (&b_com, &b_poly),
            (&product_com, &product_poly),
        )?;

        // Output the merged multiset: encode a digest of its commitment, carry
        // the commitment and polynomial as data.
        let mut digest_sponge = Sponge::new(ctx.dr, self.poseidon_params);
        product_com.write(ctx.dr, &mut digest_sponge)?;
        let digest = digest_sponge.squeeze(ctx.dr)?;
        let hash = digest.value().map(|v| *v);
        let output_encoded = Encoded::from_gadget(digest);

        let output_data = hash.and_then(|hash| {
            product_commitment.and_then(|commitment| {
                product_poly.map(|polynomial| MergedMultisetData {
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

// --- Concatenated sequence (the shifted sum `a + X^shift·b`) ----------------

/// The concatenated sequence produced by [`ConcatenateSequences`]: the joined
/// coefficient polynomial `a + X^shift·b` and its commitment. The header encodes
/// a Poseidon digest of the commitment in-circuit; the commitment and polynomial
/// travel alongside.
pub struct ConcatenatedSequenceData<C: Cycle, R: Rank> {
    /// Poseidon digest binding the concatenated commitment.
    pub hash: C::CircuitField,
    /// Commitment to the concatenated polynomial, on the nested curve.
    pub commitment: C::NestedCurve,
    /// The concatenated coefficient polynomial `a + X^shift·b`.
    pub polynomial: sparse::Polynomial<C::CircuitField, R>,
}

impl<C: Cycle, R: Rank> Clone for ConcatenatedSequenceData<C, R> {
    fn clone(&self) -> Self {
        Self {
            hash: self.hash,
            commitment: self.commitment,
            polynomial: self.polynomial.clone(),
        }
    }
}

/// Header for a concatenated sequence. Its in-circuit encoding is the digest;
/// the commitment and polynomial travel as [`ConcatenatedSequenceData`].
pub struct ConcatenatedSequence<C, R>(PhantomData<(C, R)>);

impl<C: Cycle, R: Rank> Header<C::CircuitField> for ConcatenatedSequence<C, R> {
    const SUFFIX: Suffix = Suffix::new(1);
    type Data = ConcatenatedSequenceData<C, R>;
    type Output = Kind![C::CircuitField; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = C::CircuitField>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness.map(|d| d.hash))
    }
}

/// Witness for [`ConcatenateSequences`]: both operand sequences and their
/// concatenation (each a commitment plus its coefficient polynomial), and the
/// public monomial commitment `G_shift = Com(X^shift)`.
pub struct ConcatenateSequencesWitness<C: Cycle, R: Rank> {
    pub a_commitment: C::NestedCurve,
    pub a_polynomial: sparse::Polynomial<C::CircuitField, R>,
    pub b_commitment: C::NestedCurve,
    pub b_polynomial: sparse::Polynomial<C::CircuitField, R>,
    pub cat_commitment: C::NestedCurve,
    pub cat_polynomial: sparse::Polynomial<C::CircuitField, R>,
    /// Must be the public generator `G_shift`; see [`enforce_poly_shifted_sum`].
    pub monomial_commitment: C::NestedCurve,
}

/// Leaf step: witnesses two sequences and their concatenation, confirms
/// `cat = a + X^shift·b` via [`enforce_poly_shifted_sum`], and outputs the
/// [`ConcatenatedSequence`]. `shift` is the length of the first sequence. No
/// children.
pub struct ConcatenateSequences<'params, C: Cycle, R> {
    pub poseidon_params: &'params C::CircuitPoseidon,
    pub shift: usize,
    _marker: PhantomData<R>,
}

impl<'params, C: Cycle, R> ConcatenateSequences<'params, C, R> {
    pub fn new(poseidon_params: &'params C::CircuitPoseidon, shift: usize) -> Self {
        Self {
            poseidon_params,
            shift,
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, R: Rank> Step<C> for ConcatenateSequences<'_, C, R> {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = ConcatenateSequencesWitness<C, R>;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = ConcatenatedSequence<C, R>;

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
        // Every polynomial is a local witness — both operands and the result.
        let a_com = Point::alloc(ctx.dr, witness.as_ref().map(|w| w.a_commitment))?;
        let a_poly = witness.as_ref().map(|w| w.a_polynomial.clone());
        let b_com = Point::alloc(ctx.dr, witness.as_ref().map(|w| w.b_commitment))?;
        let b_poly = witness.as_ref().map(|w| w.b_polynomial.clone());
        let monomial_com = Point::alloc(ctx.dr, witness.as_ref().map(|w| w.monomial_commitment))?;
        let cat_commitment = witness.as_ref().map(|w| w.cat_commitment);
        let cat_com = Point::alloc(ctx.dr, cat_commitment.clone())?;
        let cat_poly = witness.map(|w| w.cat_polynomial);

        // Confirm the concatenation relation: cat = a + X^shift·b.
        let mut relation_sponge = Sponge::new(ctx.dr, self.poseidon_params);
        enforce_poly_shifted_sum(
            ctx,
            &mut relation_sponge,
            (&a_com, &a_poly),
            (&b_com, &b_poly),
            (&cat_com, &cat_poly),
            self.shift,
            &monomial_com,
        )?;

        // Output the concatenated sequence: encode a digest of its commitment,
        // carry the commitment and polynomial as data.
        let mut digest_sponge = Sponge::new(ctx.dr, self.poseidon_params);
        cat_com.write(ctx.dr, &mut digest_sponge)?;
        let digest = digest_sponge.squeeze(ctx.dr)?;
        let hash = digest.value().map(|v| *v);
        let output_encoded = Encoded::from_gadget(digest);

        let output_data = hash.and_then(|hash| {
            cat_commitment.and_then(|commitment| {
                cat_poly.map(|polynomial| ConcatenatedSequenceData {
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

// --- Split (the inverse: `cat = low + X^shift·high`) ------------------------

/// The two parts produced by [`SplitSequence`]: the low part `low` (degrees
/// `< shift`) and the high part `high`, each as a commitment plus polynomial,
/// such that `cat = low + X^shift·high`. The header encodes a Poseidon digest of
/// the two commitments; both parts travel alongside.
pub struct SplitPartsData<C: Cycle, R: Rank> {
    /// Poseidon digest binding the two part-commitments.
    pub hash: C::CircuitField,
    pub low_commitment: C::NestedCurve,
    pub low_polynomial: sparse::Polynomial<C::CircuitField, R>,
    pub high_commitment: C::NestedCurve,
    pub high_polynomial: sparse::Polynomial<C::CircuitField, R>,
}

impl<C: Cycle, R: Rank> Clone for SplitPartsData<C, R> {
    fn clone(&self) -> Self {
        Self {
            hash: self.hash,
            low_commitment: self.low_commitment,
            low_polynomial: self.low_polynomial.clone(),
            high_commitment: self.high_commitment,
            high_polynomial: self.high_polynomial.clone(),
        }
    }
}

/// Header for a split's two parts. Its in-circuit encoding is the digest; the
/// two parts travel as [`SplitPartsData`].
pub struct SplitParts<C, R>(PhantomData<(C, R)>);

impl<C: Cycle, R: Rank> Header<C::CircuitField> for SplitParts<C, R> {
    const SUFFIX: Suffix = Suffix::new(2);
    type Data = SplitPartsData<C, R>;
    type Output = Kind![C::CircuitField; Element<'_, _>];

    fn encode<'dr, D: Driver<'dr, F = C::CircuitField>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness.map(|d| d.hash))
    }
}

/// Witness for [`SplitSequence`]: the sequence being split and its two parts
/// (each a commitment plus its coefficient polynomial), and the public monomial
/// commitment `G_shift = Com(X^shift)`.
pub struct SplitSequenceWitness<C: Cycle, R: Rank> {
    pub cat_commitment: C::NestedCurve,
    pub cat_polynomial: sparse::Polynomial<C::CircuitField, R>,
    pub low_commitment: C::NestedCurve,
    pub low_polynomial: sparse::Polynomial<C::CircuitField, R>,
    pub high_commitment: C::NestedCurve,
    pub high_polynomial: sparse::Polynomial<C::CircuitField, R>,
    /// Must be the public generator `G_shift`; see [`enforce_poly_shifted_sum`].
    pub monomial_commitment: C::NestedCurve,
}

/// Leaf step: witnesses a sequence `cat` and its two parts, confirms
/// `cat = low + X^shift·high` via [`enforce_poly_shifted_sum`], and outputs the
/// [`SplitParts`].
///
/// The relation — and the `enforce_poly_shifted_sum` call below — are *identical*
/// to [`ConcatenateSequences`]: same arguments in the same `(first, second,
/// whole, shift, monomial)` order. The only difference is intent: here `cat` is
/// the input we decompose and `(low, high)` are the outputs, whereas concatenation
/// regards `(a, b)` as inputs and `cat` as the output. With all three polynomials
/// witnessed, split and concat are the same enforced identity.
pub struct SplitSequence<'params, C: Cycle, R> {
    pub poseidon_params: &'params C::CircuitPoseidon,
    pub shift: usize,
    _marker: PhantomData<R>,
}

impl<'params, C: Cycle, R> SplitSequence<'params, C, R> {
    pub fn new(poseidon_params: &'params C::CircuitPoseidon, shift: usize) -> Self {
        Self {
            poseidon_params,
            shift,
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, R: Rank> Step<C> for SplitSequence<'_, C, R> {
    const INDEX: Index = Index::new(2);
    type Witness<'source> = SplitSequenceWitness<C, R>;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = SplitParts<C, R>;

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
        // Every polynomial is a local witness — the whole and both parts.
        let cat_com = Point::alloc(ctx.dr, witness.as_ref().map(|w| w.cat_commitment))?;
        let cat_poly = witness.as_ref().map(|w| w.cat_polynomial.clone());
        let low_commitment = witness.as_ref().map(|w| w.low_commitment);
        let low_com = Point::alloc(ctx.dr, low_commitment.clone())?;
        let low_poly = witness.as_ref().map(|w| w.low_polynomial.clone());
        let high_commitment = witness.as_ref().map(|w| w.high_commitment);
        let high_com = Point::alloc(ctx.dr, high_commitment.clone())?;
        let high_poly = witness.as_ref().map(|w| w.high_polynomial.clone());
        let monomial_com = Point::alloc(ctx.dr, witness.as_ref().map(|w| w.monomial_commitment))?;

        // The *same* relation as ConcatenateSequences: cat = low + X^shift·high,
        // with arguments in the same (first, second, whole, shift, monomial) order.
        let mut relation_sponge = Sponge::new(ctx.dr, self.poseidon_params);
        enforce_poly_shifted_sum(
            ctx,
            &mut relation_sponge,
            (&low_com, &low_poly),
            (&high_com, &high_poly),
            (&cat_com, &cat_poly),
            self.shift,
            &monomial_com,
        )?;

        // Output both parts: encode a digest of their commitments, carry the
        // commitments and polynomials as data.
        let mut digest_sponge = Sponge::new(ctx.dr, self.poseidon_params);
        low_com.write(ctx.dr, &mut digest_sponge)?;
        high_com.write(ctx.dr, &mut digest_sponge)?;
        let digest = digest_sponge.squeeze(ctx.dr)?;
        let hash = digest.value().map(|v| *v);
        let output_encoded = Encoded::from_gadget(digest);

        let output_data = hash.and_then(|hash| {
            low_commitment.and_then(|low_commitment| {
                low_poly.and_then(|low_polynomial| {
                    high_commitment.and_then(|high_commitment| {
                        high_poly.map(|high_polynomial| SplitPartsData {
                            hash,
                            low_commitment,
                            low_polynomial,
                            high_commitment,
                            high_polynomial,
                        })
                    })
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
