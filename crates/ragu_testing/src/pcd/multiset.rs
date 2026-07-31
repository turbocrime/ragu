//! Test fixture for multiset merging over set polynomials: a multiset is
//! represented by the monic polynomial whose roots are its members (with
//! multiplicity), so merging two multisets is polynomial multiplication —
//! computed with [`ragu_arithmetic::util::poly_mul`], the library's FFT
//! multiply.
//!
//! [`MergeSets`] handles exactly three sets: the two contributing sets `A`
//! and `B`, and the merged set `C`. **Downstream consumers see only the
//! merged set**: the output header binds `C`'s identity alone, and `A` and
//! `B` never leave the proof. `C` occupies a polynomial slot because its
//! commitment is the single identity carried forward — Pedersen commitments
//! are not multiplicative, so `commit(A·B)` cannot be derived from
//! `commit(A)` and `commit(B)` — but what the slot holds is only the name
//! (two instance wires); that `C` **is** `A·B` is *proven*, not witnessed:
//! the challenge `z` is derived from all three names, `A` and `B` are opened
//! at `z`, and `C`'s claim uses the in-circuit product `a(z)·b(z)` as its
//! claimed evaluation, so a `C` that is not the product makes the claim
//! false by Schwartz–Zippel over `z`.
//!
//! The size ceiling is the polynomial rank: a set of `N` members is a
//! degree-`N` polynomial with `N + 1` coefficients, so at a rank providing
//! `num_coeffs` coefficients the **merged** set holds at most
//! `num_coeffs − 1` members (8,191 at `ProductionRank`). The step circuit is
//! `O(1)` in `N` — size costs only native work: the product FFT, the
//! commitment MSMs, and the fold.

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
    Application, ApplicationBuilder, Pcd, PolyCommitment,
    header::{Header, Suffix},
    step::{Encoded, Index, Step, StepCtx},
};
use ragu_primitives::{
    Element, GadgetExt,
    allocator::{Allocator, Standard},
    poseidon::Sponge,
};

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

/// Data carried by a [`MergedSet`] header: the digest binding the merged
/// set's identity, and the merged polynomial as unstructured PCD data (the
/// circuit never sees it).
pub struct MergedSetData<F: Field, R: Rank> {
    pub hash: F,
    pub product: sparse::Polynomial<F, R>,
}

impl<F: Field, R: Rank> Clone for MergedSetData<F, R> {
    fn clone(&self) -> Self {
        Self {
            hash: self.hash,
            product: self.product.clone(),
        }
    }
}

/// Header binding the merged set's identity — and nothing else: downstream
/// consumers learn `C`'s representation digest, not which sets contributed.
/// The digest is a Poseidon hash of the same two values
/// [`PolyCommitment::coords`] yields natively (the anchor pattern).
pub struct MergedSet<R>(PhantomData<R>);

impl<F: Field, R: Rank> Header<F> for MergedSet<R> {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data = MergedSetData<F, R>;
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

/// Witness for [`MergeSets`]: the two contributing sets and the claimed
/// merged set, each as a committed polynomial.
pub struct MergeSetsWitness<C: Cycle, R: Rank> {
    pub a: PolyCommitment<C, R>,
    pub b: PolyCommitment<C, R>,
    pub product: PolyCommitment<C, R>,
}

/// The compressing merge: proves `product = a · b` and outputs the merged
/// set's identity alone.
///
/// The step derives `z` from all three names, opens `a` and `b` at `z`, and
/// raises `product`'s claim with the in-circuit product `a(z)·b(z)` as the
/// claimed evaluation — the claim *is* the enforcement, no further
/// constraint needed.
pub struct MergeSets<'params, C: Cycle, R> {
    pub poseidon_params: &'params C::CircuitPoseidon,
    _marker: PhantomData<R>,
}

impl<'params, C: Cycle, R> MergeSets<'params, C, R> {
    pub fn new(poseidon_params: &'params C::CircuitPoseidon) -> Self {
        Self {
            poseidon_params,
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, R: Rank> Step<C> for MergeSets<'_, C, R> {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = MergeSetsWitness<C, R>;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = MergedSet<R>;

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

        let a_com = witness.as_ref().map(|w| w.a.clone());
        let b_com = witness.as_ref().map(|w| w.b.clone());
        let c_com = witness.map(|w| w.product.clone());
        let [a, b, c] = ctx.witness_polynomial::<R, 3>([a_com, b_com, c_com])?;

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

        // The merged set's claim: its evaluation at z *is* a(z)·b(z), as an
        // in-circuit product of the two opened values. A `product` that is
        // not a·b makes this claim false.
        let y_c = y_a.mul(ctx.dr, &y_b)?;
        ctx.enforce_poly_query(&c, z, y_c)?;

        // The output header binds the merged set's identity — the digest of
        // its representation, reproducible natively from
        // `PolyCommitment::coords()`. The contributing sets do not appear.
        let mut sponge = Sponge::new(ctx.dr, self.poseidon_params);
        for coord in c.coords() {
            coord.write(ctx.dr, &mut sponge)?;
        }
        let output = sponge.squeeze(ctx.dr)?;
        let output_hash = output.value().map(|v| *v);
        let output_encoded = Encoded::from_gadget(output);

        let output_data = output_hash.and_then(|hash| {
            c.polynomial()
                .clone()
                .map(|product| MergedSetData { hash, product })
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

/// The fixture's declared capacity: three polynomial slots (the two
/// contributing sets and the merged set), three claims, and one challenge
/// wide enough to absorb all three names (two elements each).
pub const HEADER_SIZE: usize = 4;
pub const POLYS: usize = 3;
pub const CLAIMS: usize = 3;
pub const CHALLENGES: usize = 1;
pub const CHALLENGE_WIDTH: usize = 6;

/// An [`Application`] at the fixture's declared capacity.
pub type MergeApp<'params, C, R> =
    Application<'params, C, R, HEADER_SIZE, POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH>;

/// An [`ApplicationBuilder`] at the fixture's declared capacity.
pub type MergeAppBuilder<'params, C, R> =
    ApplicationBuilder<'params, C, R, HEADER_SIZE, POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH>;

/// The fixture registered and finalized: the application every multiset test
/// proves through.
pub fn merge_app<C: Cycle, R: Rank>(params: &C::Params) -> Result<MergeApp<'_, C, R>> {
    MergeAppBuilder::<C, R>::new()
        .register(MergeSets::<C, R>::new(C::circuit_poseidon(params)))?
        .finalize(params)
}

/// The merged polynomial `A·B`, computed with the library's FFT multiply
/// ([`poly_mul`]) from the two member lists.
pub fn merged_polynomial<F: PrimeField, R: Rank>(
    a_members: &[F],
    b_members: &[F],
) -> sparse::Polynomial<F, R> {
    let mut out = Vec::new();
    poly_mul(
        &poly_with_roots(a_members),
        &poly_with_roots(b_members),
        &mut out,
    );
    sparse::Polynomial::from_coeffs(out)
}

/// Seed a [`MergeSets`] leaf merging the two member lists, computing the
/// product honestly via [`merged_polynomial`].
pub fn seed_merge<C: Cycle, R: Rank, RNG: CryptoRngCore>(
    app: &MergeApp<'_, C, R>,
    params: &C::Params,
    rng: &mut RNG,
    a_members: &[C::CircuitField],
    b_members: &[C::CircuitField],
) -> Result<Pcd<C, R, MergedSet<R>>> {
    let (leaf, ()) = app.seed(
        rng,
        MergeSets::new(C::circuit_poseidon(params)),
        MergeSetsWitness {
            a: app.commit_polynomial(&set_polynomial(a_members))?,
            b: app.commit_polynomial(&set_polynomial(b_members))?,
            product: app.commit_polynomial(&merged_polynomial(a_members, b_members))?,
        },
    )?;
    Ok(leaf)
}
