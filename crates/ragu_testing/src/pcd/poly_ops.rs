//! Enforce-only relations between committed polynomials, for use inside
//! [`Step::witness`] bodies.
//!
//! Each function takes *three* already-committed witness polynomials — passed as
//! `(commitment, polynomial)` pairs where the commitment is an in-circuit
//! [`Point`] and the polynomial is prover-only [`DriverValue`] data — and applies
//! the constraints that confirm a relation among them. Nothing is constructed;
//! the third polynomial is a witness like the other two.
//!
//! * [`enforce_poly_product`] confirms `c(X) = a(X)·b(X)`. With multisets encoded
//!   as `∏(X − sᵢ)` (members are roots), this witnesses a multiset *union*.
//! * [`enforce_poly_shifted_sum`] confirms `c(X) = a(X) + X^shift·b(X)`. With
//!   sequences encoded as `Σ sᵢXⁱ` (members are coefficients), this witnesses a
//!   *concatenation* at `shift = len(a)` — and, read in reverse, a *split*.
//!
//! # Method (pure Schwartz–Zippel)
//!
//! Both absorb the witness commitments into the caller's `sponge`, derive a
//! challenge `z` via [`StepCtx::derive_challenge`], evaluate each witness
//! polynomial at `z` (prover-side), record one [`StepCtx::enforce_poly_query`]
//! opening *claim* per commitment, and enforce a single in-circuit scalar
//! identity (`y_c = y_a·y_b`, resp. `y_c = y_a + y_n·y_b`). The in-circuit work is
//! O(1); the only field arithmetic is the identity itself, and there is no curve
//! arithmetic. Every committed polynomial is independently attested by a
//! poly-query hook, so the commitment↔polynomial binding comes entirely from the
//! openings: a `(commitment, polynomial)` pair whose polynomial does not match
//! its commitment fails its opening at `z`.
//!
//! # Soundness
//!
//! Confidence is Schwartz–Zippel: `z` is sampled after every polynomial is
//! committed, so an identity that holds at `z` holds everywhere except on a
//! negligible-probability bad set. Two caveats:
//!
//! * For [`enforce_poly_shifted_sum`], `monomial_com` **must** be the public
//!   generator `G_shift = Com(X^shift)` (the `shift`-th fixed generator), never a
//!   prover witness. Otherwise a prover could pass `Com(m)` for an arbitrary `m`,
//!   set `y_n = m(z)`, satisfy the opening, and prove the relation at the *wrong*
//!   shift. With `G_shift` public, the `z^shift` factor is itself attested by the
//!   hook (the opening of `G_shift`); the in-circuit `pow_vartime` value is never
//!   trusted, only its opening.
//! * Opening claims are batch-verified at fuse time. Until that verification is
//!   wired up (`AdapterAux.claims` TODO), these functions establish that the
//!   in-circuit relation is *satisfiable*, not that the openings hold.
//!
//! [`Step::witness`]: ragu_pcd::step::Step::witness

use ff::{Field, PrimeField};
use ragu_arithmetic::{CurveAffine, PoseidonPermutation};
use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe,
};
use ragu_pcd::step::StepCtx;
use ragu_primitives::{Element, GadgetExt, Point, allocator::Standard, poseidon::Sponge};

/// Confirms `c(X) = a(X)·b(X)` for three committed witness polynomials — the
/// product relation underlying a multiset union (`∏(X − sᵢ)` encoding).
///
/// Absorbs the three commitments into `sponge`, derives a challenge `z`, records
/// one opening claim per commitment, and enforces `y_c = y_a · y_b` at `z`. See
/// the [module docs](self) for the Schwartz–Zippel reasoning. The caller is
/// responsible for the surrounding `sponge` state: anything the challenge must be
/// bound to should be absorbed before calling; this function absorbs the three
/// commitments before squeezing.
pub fn enforce_poly_product<'dr, D, C, R, P>(
    ctx: &mut StepCtx<'_, 'dr, D, C>,
    sponge: &mut Sponge<'dr, D, P>,
    a: (&Point<'dr, D, C>, &DriverValue<D, sparse::Polynomial<D::F, R>>),
    b: (&Point<'dr, D, C>, &DriverValue<D, sparse::Polynomial<D::F, R>>),
    c: (&Point<'dr, D, C>, &DriverValue<D, sparse::Polynomial<D::F, R>>),
) -> Result<()>
where
    D: Driver<'dr>,
    C: CurveAffine<Base = D::F>,
    R: Rank,
    P: PoseidonPermutation<D::F>,
    D::F: PrimeField,
{
    let (a_com, a_poly) = a;
    let (b_com, b_poly) = b;
    let (c_com, c_poly) = c;

    // Bind every commitment, then derive z.
    a_com.write(ctx.dr, sponge)?;
    b_com.write(ctx.dr, sponge)?;
    c_com.write(ctx.dr, sponge)?;
    let z = ctx.derive_challenge(sponge)?;

    // Evaluate each witness polynomial at z (prover-side).
    let z_val = z.value().map(|v| *v);
    let eval_at = |poly: &DriverValue<D, sparse::Polynomial<D::F, R>>| {
        z_val.clone().and_then(|zv| poly.clone().map(|p| p.eval(zv)))
    };
    let alloc = &mut Standard::new();
    let y_a = Element::alloc(ctx.dr, alloc, eval_at(a_poly))?;
    let y_b = Element::alloc(ctx.dr, alloc, eval_at(b_poly))?;
    let y_c = Element::alloc(ctx.dr, alloc, eval_at(c_poly))?;

    // One opening claim per committed polynomial.
    ctx.enforce_poly_query(a_com.clone(), z.clone(), y_a.clone())?;
    ctx.enforce_poly_query(b_com.clone(), z.clone(), y_b.clone())?;
    ctx.enforce_poly_query(c_com.clone(), z, y_c.clone())?;

    // y_c == y_a · y_b at z.
    let computed = y_a.mul(ctx.dr, &y_b)?;
    y_c.enforce_equal(ctx.dr, &computed)
}

/// Confirms `c(X) = a(X) + X^shift·b(X)` for three committed witness polynomials
/// — the shifted-sum relation underlying a sequence concatenation at
/// `shift = len(a)` (`Σ sᵢXⁱ` encoding), and equivalently a split.
///
/// Absorbs the three polynomial commitments plus `monomial_com` into `sponge`,
/// derives `z`, records the four opening claims, and enforces
/// `y_c = y_a + y_n·y_b` at `z`, where `y_n` is the monomial's opening (= `z^shift`).
///
/// `monomial_com` **must** be the public generator `G_shift = Com(X^shift)`, not a
/// prover witness — see the [module docs](self) for the soundness reason. As in
/// [`enforce_poly_product`], the caller owns the surrounding `sponge` state; this
/// function absorbs the four commitments before squeezing.
pub fn enforce_poly_shifted_sum<'dr, D, C, R, P>(
    ctx: &mut StepCtx<'_, 'dr, D, C>,
    sponge: &mut Sponge<'dr, D, P>,
    a: (&Point<'dr, D, C>, &DriverValue<D, sparse::Polynomial<D::F, R>>),
    b: (&Point<'dr, D, C>, &DriverValue<D, sparse::Polynomial<D::F, R>>),
    c: (&Point<'dr, D, C>, &DriverValue<D, sparse::Polynomial<D::F, R>>),
    shift: usize,
    monomial_com: &Point<'dr, D, C>,
) -> Result<()>
where
    D: Driver<'dr>,
    C: CurveAffine<Base = D::F>,
    R: Rank,
    P: PoseidonPermutation<D::F>,
    D::F: PrimeField,
{
    let (a_com, a_poly) = a;
    let (b_com, b_poly) = b;
    let (c_com, c_poly) = c;

    // Bind every commitment (including the monomial), then derive z.
    a_com.write(ctx.dr, sponge)?;
    b_com.write(ctx.dr, sponge)?;
    c_com.write(ctx.dr, sponge)?;
    monomial_com.write(ctx.dr, sponge)?;
    let z = ctx.derive_challenge(sponge)?;

    // Evaluations at z. y_n = z^shift via prover-side native pow; its binding to
    // X^shift is the opening of the public generator `monomial_com`.
    let z_val = z.value().map(|v| *v);
    let eval_at = |poly: &DriverValue<D, sparse::Polynomial<D::F, R>>| {
        z_val.clone().and_then(|zv| poly.clone().map(|p| p.eval(zv)))
    };
    let alloc = &mut Standard::new();
    let y_a = Element::alloc(ctx.dr, alloc, eval_at(a_poly))?;
    let y_b = Element::alloc(ctx.dr, alloc, eval_at(b_poly))?;
    let y_c = Element::alloc(ctx.dr, alloc, eval_at(c_poly))?;
    let y_n = Element::alloc(
        ctx.dr,
        alloc,
        z_val.clone().map(|zv| zv.pow_vartime([shift as u64])),
    )?;

    // Four opening claims.
    ctx.enforce_poly_query(a_com.clone(), z.clone(), y_a.clone())?;
    ctx.enforce_poly_query(b_com.clone(), z.clone(), y_b.clone())?;
    ctx.enforce_poly_query(c_com.clone(), z.clone(), y_c.clone())?;
    ctx.enforce_poly_query(monomial_com.clone(), z.clone(), y_n.clone())?;

    // y_c == y_a + y_n · y_b at z.
    let scaled = y_n.mul(ctx.dr, &y_b)?;
    let computed = y_a.add(ctx.dr, &scaled);
    y_c.enforce_equal(ctx.dr, &computed)
}
