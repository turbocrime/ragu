//! Test fixtures for multiset operations over set polynomials: a multiset is
//! represented by the monic polynomial whose roots are its members (with
//! multiplicity), so merging two multisets is polynomial multiplication —
//! computed with [`ragu_arithmetic::poly_mul`], the library's FFT multiply.
//!
//! Two steps, registered into the shared
//! [`collections_app`](super::collections_app):
//!
//! * [`SeedSet`] — a leaf establishing an **initial** set from an arbitrary
//!   committed polynomial. Its output header carries the set's *name* — the
//!   commitment's two canonical coordinates — as raw header elements, so a
//!   parent can compare against it in-circuit.
//! * [`MergeSets`] — a **fuse**: the two contributing sets arrive as the
//!   children's header-carried names, the parent re-witnesses their
//!   polynomials and enforces its handles' names equal the header wires —
//!   the cross-proof identity check the canonical representation exists
//!   for — then proves the product. Downstream consumers see only the
//!   merged set: the output header carries `C`'s name alone.
//!
//! `C` occupies a polynomial slot because Pedersen commitments are not
//! multiplicative — `commit(A·B)` cannot be derived from `commit(A)` and
//! `commit(B)` — but the slot holds only the name; that `C` **is** the
//! product is *proven*: the challenge `z` is derived from all three names,
//! `A` and `B` are opened at `z`, and `C`'s claim carries the in-circuit
//! `a(z)·b(z)` as its claimed evaluation, so a wrong `C` makes the claim
//! false by Schwartz–Zippel over `z`.

use core::marker::PhantomData;

use ff::{Field, PrimeField};
use ragu_arithmetic::{CryptoRngCore, Cycle, poly_mul, poly_with_roots};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
};
use ragu_pcd::{
    Pcd, PolyCommitment,
    header::{Header, Suffix},
    step::{Encoded, Index, Step, StepCtx},
};
use ragu_primitives::{
    Element, GadgetExt,
    allocator::{Allocator, Standard},
    vec::{CollectFixed, ConstLen, FixedVec, Len},
};

use super::CollectionsApp;

/// The monic set polynomial `∏ (X − m)` over `members`, multiplicity
/// included, via the library's [`poly_with_roots`] (a product tree over the
/// FFT multiply): a multiset of `N` members is a degree-`N` polynomial with
/// `N + 1` coefficients. The empty set is the constant polynomial `1`.
///
/// Panics (via `from_coeffs`) if `members.len() + 1` exceeds the rank's
/// coefficient capacity — the size ceiling the tests pin.
pub fn set_polynomial<F: PrimeField, R: Rank>(members: &[F]) -> sparse::Polynomial<F, R> {
    sparse::Polynomial::from_coeffs(poly_with_roots(members))
}

/// A polynomial's coefficients with the zero tail dropped, for feeding
/// [`poly_mul`] without ballooning to the rank's dense width.
pub fn trimmed_coeffs<F: PrimeField, R: Rank>(poly: &sparse::Polynomial<F, R>) -> Vec<F> {
    let mut coeffs: Vec<F> = poly.iter_coeffs().collect();
    while coeffs.last() == Some(&F::ZERO) {
        coeffs.pop();
    }
    coeffs
}

/// The merged polynomial `A·B`, computed with the library's FFT multiply.
pub fn merged_polynomial<F: PrimeField, R: Rank>(
    a: &sparse::Polynomial<F, R>,
    b: &sparse::Polynomial<F, R>,
) -> sparse::Polynomial<F, R> {
    let mut out = Vec::new();
    poly_mul(&trimmed_coeffs(a), &trimmed_coeffs(b), &mut out);
    sparse::Polynomial::from_coeffs(out)
}

/// Data carried by a [`SetHeader`]: the set's name (its commitment's
/// canonical coordinates) and the set polynomial as unstructured PCD data
/// (the circuit never sees the polynomial; the name is what headers bind).
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

/// Header carrying a set's **name** as two raw elements, so a parent step
/// can `enforce_equal` its own handle's coordinates against the child's
/// header wires — polynomial identity threading across proofs as plain
/// field elements.
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

/// Witness for [`SeedSet`]: the initial set as a committed polynomial.
pub struct SeedSetWitness<C: Cycle, R: Rank> {
    pub set: PolyCommitment<C, R>,
}

/// A leaf establishing an initial set from an arbitrary committed
/// polynomial: witnesses it (binding its name to this proof's instance) and
/// outputs the name in the header.
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
        let set = witness.map(|w| w.set.clone());
        let [handle] = ctx.witness_polynomial::<R, 1>([set])?;

        // The output header is the handle's own name wires — no fresh
        // allocation, so the header and the poly slot are literally the same
        // wires at two instance positions.
        let coords = handle.coords();
        let output_data = handle.polynomial().as_ref().and_then(|polynomial| {
            let c0 = coords[0].value().map(|v| *v);
            let c1 = coords[1].value().map(|v| *v);
            c0.and_then(|c0| {
                c1.map(|c1| SetData {
                    coords: [c0, c1],
                    polynomial: polynomial.clone(),
                })
            })
        });
        let header: FixedVec<Element<'dr, D>, ConstLen<2>> =
            coords.into_iter().collect::<Vec<_>>().try_into()?;

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

/// Witness for the [`MergeSets`] fuse: the two contributing sets (which must
/// match the children's header-carried names) and the claimed merged set.
pub struct MergeSetsWitness<C: Cycle, R: Rank> {
    pub a: PolyCommitment<C, R>,
    pub b: PolyCommitment<C, R>,
    pub product: PolyCommitment<C, R>,
}

/// The merging fuse: takes two [`SetHeader`] children, binds its witnessed
/// contributing sets to the children's names in-circuit, proves the product,
/// and outputs the merged set's name alone.
pub struct MergeSets<C, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C, R> MergeSets<C, R> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C, R> Default for MergeSets<C, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Cycle, R: Rank> Step<C> for MergeSets<C, R> {
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
        let c_com = witness.map(|w| w.product.clone());
        let [a, b, c] = ctx.witness_polynomial::<R, 3>([a_com, b_com, c_com])?;

        // The cross-proof identity check: the contributing sets this step
        // witnessed are exactly the sets the children's headers name. Same
        // canonical representation on both sides, so the check is plain
        // field equality on wires.
        for (handle, child) in [(&a, &left_encoded), (&b, &right_encoded)] {
            let name = handle.coords();
            let header: &FixedVec<Element<'dr, D>, ConstLen<2>> = child.as_gadget();
            name[0].enforce_equal(ctx.dr, &header[0])?;
            name[1].enforce_equal(ctx.dr, &header[1])?;
        }

        // z binds all three names: the merged set's commitment is fixed
        // before the evaluation point is known.
        let [a0, a1] = a.coords();
        let [b0, b1] = b.coords();
        let [c0, c1] = c.coords();
        let z = ctx.derive_challenge(&[a0, a1, b0, b1, c0, c1])?;

        // Open the contributing sets at z.
        let y_a_value = z
            .value()
            .map(|z| *z)
            .and_then(|z| a.polynomial().as_ref().map(|p| p.eval(z)));
        let y_a = Element::alloc(ctx.dr, allocator, y_a_value)?;
        let y_b_value = z
            .value()
            .map(|z| *z)
            .and_then(|z| b.polynomial().as_ref().map(|p| p.eval(z)));
        let y_b = Element::alloc(ctx.dr, allocator, y_b_value)?;
        ctx.enforce_poly_query(&a, z.clone(), y_a.clone())?;
        ctx.enforce_poly_query(&b, z.clone(), y_b.clone())?;

        // The merged set's claim: its evaluation at z *is* a(z)·b(z). A
        // `product` that is not a·b makes this claim false.
        let y_c = y_a.mul(ctx.dr, &y_b)?;
        ctx.enforce_poly_query(&c, z, y_c)?;

        // The output header is the merged set's name — the contributing
        // sets do not appear.
        let coords = c.coords();
        let output_data = c.polynomial().as_ref().and_then(|polynomial| {
            let c0 = coords[0].value().map(|v| *v);
            let c1 = coords[1].value().map(|v| *v);
            c0.and_then(|c0| {
                c1.map(|c1| SetData {
                    coords: [c0, c1],
                    polynomial: polynomial.clone(),
                })
            })
        });
        let header: FixedVec<Element<'dr, D>, ConstLen<2>> =
            coords.into_iter().collect::<Vec<_>>().try_into()?;

        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(header)),
            output_data,
            D::unit(),
        ))
    }
}

/// Seed an initial set from its member list.
pub fn seed_set<C: Cycle, R: Rank, RNG: CryptoRngCore>(
    app: &CollectionsApp<'_, C, R>,
    rng: &mut RNG,
    members: &[C::CircuitField],
) -> Result<Pcd<C, R, SetHeader<R>>> {
    let (leaf, ()) = app.seed(
        rng,
        SeedSet::new(),
        SeedSetWitness {
            set: app.commit_polynomial(&set_polynomial(members))?,
        },
    )?;
    Ok(leaf)
}

/// Fuse two set children into their merge, computing the product honestly
/// from the polynomials the children carry.
pub fn fuse_merge<C: Cycle, R: Rank, RNG: CryptoRngCore>(
    app: &CollectionsApp<'_, C, R>,
    rng: &mut RNG,
    left: Pcd<C, R, SetHeader<R>>,
    right: Pcd<C, R, SetHeader<R>>,
) -> Result<Pcd<C, R, SetHeader<R>>> {
    let product = merged_polynomial(&left.data().polynomial, &right.data().polynomial);
    let witness = MergeSetsWitness {
        a: app.commit_polynomial(&left.data().polynomial)?,
        b: app.commit_polynomial(&right.data().polynomial)?,
        product: app.commit_polynomial(&product)?,
    };
    let (merged, ()) = app.fuse(rng, MergeSets::new(), witness, left, right)?;
    Ok(merged)
}
