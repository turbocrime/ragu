//! Transcript routines for computing Fiat-Shamir challenges.

use arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, emulator::Emulator},
    maybe::Maybe,
};
use ragu_primitives::{Element, GadgetExt, Point, Sponge};

/// Computation of w = H(nested_preamble_commitment)
pub fn derive_w<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle>(
    dr: &mut D,
    nested_preamble_commitment: &Point<'dr, D, C::NestedCurve>,
    params: &'dr C,
) -> Result<Element<'dr, D>> {
    let mut sponge = Sponge::new(dr, params.circuit_poseidon());
    nested_preamble_commitment.write(dr, &mut sponge)?;
    sponge.squeeze(dr)
}

/// Compute $w$ challenge using the [`Emulator`] for use outside of circuit
/// contexts.
pub fn emulate_w<C: Cycle>(
    nested_preamble_commitment: C::NestedCurve,
    params: &C,
) -> Result<C::CircuitField> {
    Emulator::emulate_wireless(nested_preamble_commitment, |dr, comm| {
        let point = Point::alloc(dr, comm)?;
        Ok(*derive_w::<_, C>(dr, &point, params)?.value().take())
    })
}

/// Computation of alpha = H(nested_query_commitment)
pub fn derive_alpha<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle>(
    dr: &mut D,
    nested_query_commitment: &Point<'dr, D, C::NestedCurve>,
    params: &'dr C,
) -> Result<Element<'dr, D>> {
    let mut sponge = Sponge::new(dr, params.circuit_poseidon());
    nested_query_commitment.write(dr, &mut sponge)?;
    sponge.squeeze(dr)
}

/// Compute $\alpha$ challenge using the [`Emulator`] for use outside of circuit
/// contexts.
pub fn emulate_alpha<C: Cycle>(
    nested_query_commitment: C::NestedCurve,
    params: &C,
) -> Result<C::CircuitField> {
    Emulator::emulate_wireless(nested_query_commitment, |dr, comm| {
        let point = Point::alloc(dr, comm)?;
        Ok(*derive_alpha::<_, C>(dr, &point, params)?.value().take())
    })
}

/// Computation of u = H(alpha, nested_f_commitment)
pub fn derive_u<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle>(
    dr: &mut D,
    alpha: &Element<'dr, D>,
    nested_f_commitment: &Point<'dr, D, C::NestedCurve>,
    params: &'dr C,
) -> Result<Element<'dr, D>> {
    let mut sponge = Sponge::new(dr, params.circuit_poseidon());
    sponge.absorb(dr, alpha)?;
    nested_f_commitment.write(dr, &mut sponge)?;
    sponge.squeeze(dr)
}

/// Compute $u$ challenge using the [`Emulator`] for use outside of circuit
/// contexts.
pub fn emulate_u<C: Cycle>(
    alpha: C::CircuitField,
    nested_f_commitment: C::NestedCurve,
    params: &C,
) -> Result<C::CircuitField> {
    Emulator::emulate_wireless((alpha, nested_f_commitment), |dr, witness| {
        let (alpha, comm) = witness.cast();
        let alpha_elem = Element::alloc(dr, alpha)?;
        let point = Point::alloc(dr, comm)?;
        Ok(*derive_u::<_, C>(dr, &alpha_elem, &point, params)?
            .value()
            .take())
    })
}

/// Computation of (mu, nu) = H(nested_error_commitment)
pub fn derive_mu_nu<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle>(
    dr: &mut D,
    nested_error_commitment: &Point<'dr, D, C::NestedCurve>,
    params: &'dr C,
) -> Result<(Element<'dr, D>, Element<'dr, D>)> {
    let mut sponge = Sponge::new(dr, params.circuit_poseidon());
    nested_error_commitment.write(dr, &mut sponge)?;
    let mu = sponge.squeeze(dr)?;
    let nu = sponge.squeeze(dr)?;
    Ok((mu, nu))
}

/// Compute $(mu, nu)$ challenges using the [`Emulator`] for use outside of circuit
/// contexts.
pub fn emulate_mu_nu<C: Cycle>(
    nested_error_commitment: C::NestedCurve,
    params: &C,
) -> Result<(C::CircuitField, C::CircuitField)> {
    Emulator::emulate_wireless(nested_error_commitment, |dr, comm| {
        let point = Point::alloc(dr, comm)?;
        let (mu, nu) = derive_mu_nu::<_, C>(dr, &point, params)?;
        Ok((*mu.value().take(), *nu.value().take()))
    })
}

/// Computation of x = H(mu, nu, nested_ab_commitment)
pub fn derive_x<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle>(
    dr: &mut D,
    mu: &Element<'dr, D>,
    nested_ab_commitment: &Point<'dr, D, C::NestedCurve>,
    params: &'dr C,
) -> Result<Element<'dr, D>> {
    let mut sponge = Sponge::new(dr, params.circuit_poseidon());
    sponge.absorb(dr, mu)?;
    nested_ab_commitment.write(dr, &mut sponge)?;
    sponge.squeeze(dr)
}

/// Compute $x$ challenge using the [`Emulator`] for use outside of circuit
/// contexts.
pub fn emulate_x<C: Cycle>(
    mu: C::CircuitField,
    nested_ab_commitment: C::NestedCurve,
    params: &C,
) -> Result<C::CircuitField> {
    Emulator::emulate_wireless((mu, nested_ab_commitment), |dr, witness| {
        let (mu, comm) = witness.cast();
        let mu_elem = Element::alloc(dr, mu)?;
        let point = Point::alloc(dr, comm)?;
        Ok(*derive_x::<_, C>(dr, &mu_elem, &point, params)?
            .value()
            .take())
    })
}

/// Computation of beta = H(nested_eval_commitment)
pub fn derive_beta<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle>(
    dr: &mut D,
    nested_eval_commitment: &Point<'dr, D, C::NestedCurve>,
    params: &'dr C,
) -> Result<Element<'dr, D>> {
    let mut sponge = Sponge::new(dr, params.circuit_poseidon());
    nested_eval_commitment.write(dr, &mut sponge)?;
    sponge.squeeze(dr)
}

/// Compute $\beta$ challenge using the [`Emulator`] for use outside of circuit
/// contexts.
pub fn emulate_beta<C: Cycle>(
    nested_eval_commitment: C::NestedCurve,
    params: &C,
) -> Result<C::CircuitField> {
    Emulator::emulate_wireless(nested_eval_commitment, |dr, comm| {
        let point = Point::alloc(dr, comm)?;
        Ok(*derive_beta::<_, C>(dr, &point, params)?.value().take())
    })
}
