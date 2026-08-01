//! The four steps of the collections application: singleton seeds and
//! name-binding fuses. A child's header carries its output's *name* — the
//! commitment's two canonical coordinates — and the parent re-witnesses the
//! polynomial and enforces its handle's name equal to the child's header
//! wires. Multisets ([`SeedSet`], [`MergeSets`]) are monic root
//! polynomials, merged by multiplication; sequences ([`SeedSequence`],
//! [`ConcatSequences`]) are coefficient-list polynomials with a monic
//! sentinel, concatenated by shifted addition.

#![allow(clippy::type_complexity)]

use core::marker::PhantomData;

use ff::{Field, PrimeField};
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pcd::{
    PolyCommitment, PolyHandle,
    header::{Header, Suffix},
    step::{Encoded, Index, Step, StepCtx},
};
use ragu_primitives::{
    Boolean, Element, GadgetExt,
    allocator::{Allocator, Standard},
    multipack,
    vec::{CollectFixed, ConstLen, FixedVec, Len},
};

/// Data carried by a [`SetHeader`]: the set's name and its polynomial as
/// unstructured PCD data (the circuit never sees the polynomial).
pub struct SetData<F: Field, R: Rank> {
    pub coords: [F; 2],
    pub polynomial: sparse::Polynomial<F, R>,
}

impl<F: Field, R: Rank> Clone for SetData<F, R> {
    fn clone(&self) -> Self {
        Self {
            coords: self.coords,
            polynomial: self.polynomial.clone(),
        }
    }
}

/// Header carrying a set's name as two raw elements.
pub struct SetHeader<R>(PhantomData<R>);

impl<F: Field, R: Rank> Header<F> for SetHeader<R> {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data = SetData<F, R>;
    type Output = Kind![F; FixedVec<Element<'_, _>, ConstLen<2>>];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        ConstLen::<2>::range()
            .map(|i| Element::alloc(dr, allocator, witness.as_ref().map(|d| d.coords[i])))
            .try_collect_fixed()
    }
}

/// Witness for [`SeedSet`]: the one-member set as a committed polynomial.
pub struct SeedSetWitness<C: Cycle, R: Rank> {
    pub set: PolyCommitment<C>,
    pub polynomial: sparse::Polynomial<C::CircuitField, R>,
}

/// A leaf establishing a one-member set: witnesses its committed polynomial
/// and outputs the name in the header.
pub struct SeedSet<C, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C, R> SeedSet<C, R> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C, R> Default for SeedSet<C, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Cycle, R: Rank> Step<C> for SeedSet<C, R> {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = SeedSetWitness<C, R>;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = SetHeader<R>;

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
        let polynomial = witness.as_ref().map(|w| w.polynomial.clone());
        let set = witness.map(|w| w.set.clone());
        let [handle] = ctx.witness_polynomial([set])?;

        let output_data = set_data(&handle, polynomial);
        let header = name_header(&handle)?;

        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(header),
            ),
            output_data,
            D::unit(),
        ))
    }
}

/// Witness for the [`MergeSets`] fuse: the two contributing sets and the
/// claimed merged set.
pub struct MergeSetsWitness<C: Cycle, R: Rank> {
    pub a: PolyCommitment<C>,
    pub b: PolyCommitment<C>,
    pub product: PolyCommitment<C>,
    pub product_polynomial: sparse::Polynomial<C::CircuitField, R>,
}

/// The merging fuse: binds its witnessed inputs to the children's names,
/// proves `c(z) = a(z)·b(z)` at a challenge derived from all three names,
/// and outputs the merged set's name alone.
pub struct MergeSets<'params, C: Cycle, R> {
    params: &'params C::Params,
    _marker: PhantomData<R>,
}

impl<'params, C: Cycle, R> MergeSets<'params, C, R> {
    pub fn new(params: &'params C::Params) -> Self {
        Self {
            params,
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, R: Rank> Step<C> for MergeSets<'_, C, R> {
    const INDEX: Index = Index::new(2);
    type Witness<'source> = MergeSetsWitness<C, R>;
    type Aux<'source> = ();
    type Left = SetHeader<R>;
    type Right = SetHeader<R>;
    type Output = SetHeader<R>;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, C>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, SetData<C::CircuitField, R>>,
        right: DriverValue<D, SetData<C::CircuitField, R>>,
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

        let a_com = witness.as_ref().map(|w| w.a.clone());
        let b_com = witness.as_ref().map(|w| w.b.clone());
        let product_polynomial = witness.as_ref().map(|w| w.product_polynomial.clone());
        let c_com = witness.map(|w| w.product.clone());
        let handles = ctx.witness_polynomial([a_com, b_com, c_com])?;
        let left_header: &FixedVec<Element<'dr, D>, ConstLen<2>> = left_encoded.as_gadget();
        let right_header: &FixedVec<Element<'dr, D>, ConstLen<2>> = right_encoded.as_gadget();
        let ([a, b, c], z) = bind_and_challenge(
            ctx,
            self.params,
            handles,
            [&left_header[0], &left_header[1]],
            [&right_header[0], &right_header[1]],
        )?;

        let y_a = open_at(ctx, allocator, &a, &z)?;
        let y_b = open_at(ctx, allocator, &b, &z)?;
        let y_c = y_a.mul(ctx.dr, &y_b)?;
        ctx.enforce_poly_query(&c, z, y_c)?;

        let output_data = set_data(&c, product_polynomial);
        let header = name_header(&c)?;

        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(header)),
            output_data,
            D::unit(),
        ))
    }
}

/// Data carried by a [`SeqHeader`]: the sequence's name and its member list
/// as unstructured PCD data.
pub struct SeqData<F: Field> {
    pub coords: [F; 2],
    pub members: Vec<F>,
}

impl<F: Field> Clone for SeqData<F> {
    fn clone(&self) -> Self {
        Self {
            coords: self.coords,
            members: self.members.clone(),
        }
    }
}

impl<F: PrimeField> SeqData<F> {
    /// The three header elements in layout order: the name, then the length.
    fn header_element(&self, i: usize) -> F {
        match i {
            0 | 1 => self.coords[i],
            _ => F::from(self.members.len() as u64),
        }
    }
}

/// Header carrying a sequence's name (two raw elements) and its length
/// (one raw element).
pub struct SeqHeader;

impl<F: PrimeField> Header<F> for SeqHeader {
    const SUFFIX: Suffix = Suffix::new(1);
    type Data = SeqData<F>;
    type Output = Kind![F; FixedVec<Element<'_, _>, ConstLen<3>>];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        ConstLen::<3>::range()
            .map(|i| Element::alloc(dr, allocator, witness.as_ref().map(|d| d.header_element(i))))
            .try_collect_fixed()
    }
}

/// Witness for [`SeedSequence`]: the literal member and its committed
/// one-member sequence `[member, 1]`.
pub struct SeedSequenceWitness<C: Cycle> {
    pub sequence: PolyCommitment<C>,
    pub member: C::CircuitField,
}

/// A leaf establishing a one-member sequence: witnesses the committed
/// polynomial `[member, 1]` and outputs its name, with the header length
/// pinned to the constant `1`.
pub struct SeedSequence<C, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C, R> SeedSequence<C, R> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C, R> Default for SeedSequence<C, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Cycle, R: Rank> Step<C> for SeedSequence<C, R> {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = SeedSequenceWitness<C>;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = SeqHeader;

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
        let member = witness.as_ref().map(|w| w.member);
        let seq_com = witness.map(|w| w.sequence.clone());
        let [seq] = ctx.witness_polynomial([seq_com])?;

        let output_data = seq_data(&seq, member.map(|m| vec![m]));
        let header: FixedVec<Element<'dr, D>, ConstLen<3>> = seq
            .coords()
            .into_iter()
            .chain([Element::one()])
            .collect::<Vec<_>>()
            .try_into()?;

        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(header),
            ),
            output_data,
            D::unit(),
        ))
    }
}

/// Witness for the [`ConcatSequences`] fuse: the contributing sequences and
/// the claimed concatenation.
pub struct ConcatSequencesWitness<C: Cycle> {
    pub a: PolyCommitment<C>,
    pub b: PolyCommitment<C>,
    pub output: PolyCommitment<C>,
}

/// The concatenation fuse: binds its witnessed inputs to the children's
/// names and proves the shifted addition `C = A + X^{ℓa}·(B − 1)` — the
/// `− 1` removes `A`'s sentinel, which `B`'s lowest member overwrites —
/// outputting `C`'s name with length `ℓc = ℓa + ℓb`.
pub struct ConcatSequences<'params, C: Cycle, R> {
    params: &'params C::Params,
    _marker: PhantomData<R>,
}

impl<'params, C: Cycle, R> ConcatSequences<'params, C, R> {
    pub fn new(params: &'params C::Params) -> Self {
        Self {
            params,
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, R: Rank> Step<C> for ConcatSequences<'_, C, R> {
    const INDEX: Index = Index::new(3);
    type Witness<'source> = ConcatSequencesWitness<C>;
    type Aux<'source> = ();
    type Left = SeqHeader;
    type Right = SeqHeader;
    type Output = SeqHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D, C>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, SeqData<C::CircuitField>>,
        right: DriverValue<D, SeqData<C::CircuitField>>,
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

        let la = left.as_ref().map(|d| d.members.len());
        let lb = right.as_ref().map(|d| d.members.len());
        let members = D::try_just(|| {
            let mut members = left.as_ref().take().members.clone();
            members.extend(right.as_ref().take().members.iter().copied());
            Ok(members)
        })?;
        let left_encoded = Encoded::new(ctx.dr, allocator, left)?;
        let right_encoded = Encoded::new(ctx.dr, allocator, right)?;

        let a_com = witness.as_ref().map(|w| w.a.clone());
        let b_com = witness.as_ref().map(|w| w.b.clone());
        let c_com = witness.map(|w| w.output.clone());
        let handles = ctx.witness_polynomial([a_com, b_com, c_com])?;
        let ([a, b, c], z) = {
            let left_header: &FixedVec<Element<'dr, D>, ConstLen<3>> = left_encoded.as_gadget();
            let right_header: &FixedVec<Element<'dr, D>, ConstLen<3>> = right_encoded.as_gadget();
            bind_and_challenge(
                ctx,
                self.params,
                handles,
                [&left_header[0], &left_header[1]],
                [&right_header[0], &right_header[1]],
            )?
        };

        // The offset factor z^{ℓa} must not be a free witness (it could be
        // chosen after z is known): pack ℓa's bits against the header length
        // — which also proves ℓa < num_coeffs — and square-and-multiply.
        let log_coeffs = R::num_coeffs().trailing_zeros() as usize;
        let la_bits = (0..log_coeffs)
            .map(|i| Boolean::alloc(ctx.dr, allocator, la.as_ref().map(|l| (*l >> i) & 1 == 1)))
            .collect::<Result<Vec<_>>>()?;
        {
            let left_header: &FixedVec<Element<'dr, D>, ConstLen<3>> = left_encoded.as_gadget();
            multipack(ctx.dr, &la_bits)?[0].enforce_equal(ctx.dr, &left_header[2])?;
        }
        let one = Element::one();
        let mut t = Element::one();
        let mut z_pow = z.clone();
        for bit in &la_bits {
            let factor = bit.conditional_select(ctx.dr, &one, &z_pow)?;
            t = t.mul(ctx.dr, &factor)?;
            z_pow = z_pow.square(ctx.dr)?;
        }

        let y_a = open_at(ctx, allocator, &a, &z)?;
        let y_b = open_at(ctx, allocator, &b, &z)?;
        let y_b_less_sentinel = y_b.sub(ctx.dr, &one);
        let shifted = t.mul(ctx.dr, &y_b_less_sentinel)?;
        let y_c = y_a.add(ctx.dr, &shifted);
        ctx.enforce_poly_query(&c, z, y_c)?;

        // ℓc = ℓa + ℓb, packed from fresh bits so the sum is proven below
        // the rank's capacity and cannot wrap.
        let lc_value = la.as_ref().and_then(|l| lb.as_ref().map(|r| *l + *r));
        let lc_bits = (0..log_coeffs)
            .map(|i| {
                let value = lc_value.as_ref().map(|l| (*l >> i) & 1 == 1);
                Boolean::alloc(ctx.dr, allocator, value)
            })
            .collect::<Result<Vec<_>>>()?;
        let lc = multipack(ctx.dr, &lc_bits)?.remove(0);
        {
            let left_header: &FixedVec<Element<'dr, D>, ConstLen<3>> = left_encoded.as_gadget();
            let right_header: &FixedVec<Element<'dr, D>, ConstLen<3>> = right_encoded.as_gadget();
            let sum = left_header[2].add(ctx.dr, &right_header[2]);
            lc.enforce_equal(ctx.dr, &sum)?;
        }

        let output_data = seq_data(&c, members);
        let header: FixedVec<Element<'dr, D>, ConstLen<3>> = c
            .coords()
            .into_iter()
            .chain([lc])
            .collect::<Vec<_>>()
            .try_into()?;

        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(header)),
            output_data,
            D::unit(),
        ))
    }
}

/// Binds each contributor's name to its child's header-carried name, then
/// derives the challenge `z` from all three names.
fn bind_and_challenge<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle>(
    ctx: &mut StepCtx<'_, 'dr, D, C>,
    params: &C::Params,
    handles: [PolyHandle<'dr, D, C>; 3],
    left_name: [&Element<'dr, D>; 2],
    right_name: [&Element<'dr, D>; 2],
) -> Result<([PolyHandle<'dr, D, C>; 3], Element<'dr, D>)> {
    for (handle, header_name) in [(&handles[0], left_name), (&handles[1], right_name)] {
        let name = handle.coords();
        name[0].enforce_equal(ctx.dr, header_name[0])?;
        name[1].enforce_equal(ctx.dr, header_name[1])?;
    }
    let z = ctx.derive_challenge(params, &handles)?;
    Ok((handles, z))
}

/// Opens `handle` at `z` via a poly-query claim.
fn open_at<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle>(
    ctx: &mut StepCtx<'_, 'dr, D, C>,
    allocator: &mut impl Allocator<'dr, D>,
    handle: &PolyHandle<'dr, D, C>,
    z: &Element<'dr, D>,
) -> Result<Element<'dr, D>> {
    let y_value = handle.eval(z.value().map(|z| *z));
    let y = Element::alloc(ctx.dr, allocator, y_value)?;
    ctx.enforce_poly_query(handle, z.clone(), y.clone())?;
    Ok(y)
}

/// Assembles a [`SetData`] value from a handle's name and the polynomial.
fn set_data<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>, R: Rank>(
    handle: &PolyHandle<'dr, D, C>,
    polynomial: DriverValue<D, sparse::Polynomial<D::F, R>>,
) -> DriverValue<D, SetData<D::F, R>> {
    let [c0, c1] = handle.coords();
    let c0 = c0.value().map(|v| *v);
    let c1 = c1.value().map(|v| *v);
    polynomial.and_then(|polynomial| {
        c0.and_then(|c0| {
            c1.map(|c1| SetData {
                coords: [c0, c1],
                polynomial,
            })
        })
    })
}

/// Assembles a [`SeqData`] value from a handle's name and the member list.
fn seq_data<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>>(
    handle: &PolyHandle<'dr, D, C>,
    members: DriverValue<D, Vec<D::F>>,
) -> DriverValue<D, SeqData<D::F>> {
    let [c0, c1] = handle.coords();
    let c0 = c0.value().map(|v| *v);
    let c1 = c1.value().map(|v| *v);
    c0.and_then(|c0| {
        c1.and_then(|c1| {
            members.map(|members| SeqData {
                coords: [c0, c1],
                members,
            })
        })
    })
}

/// The set-name header wires: the handle's own coordinate wires.
fn name_header<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>>(
    handle: &PolyHandle<'dr, D, C>,
) -> Result<FixedVec<Element<'dr, D>, ConstLen<2>>> {
    handle.coords().into_iter().collect::<Vec<_>>().try_into()
}
