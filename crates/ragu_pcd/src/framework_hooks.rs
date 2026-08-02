//! Framework-side state behind the hooks a step reaches through
//! [`StepCtx`](crate::step::StepCtx). Every slot is part of the application
//! circuit's public instance, padded to the application's declared capacity
//! ([`HookLayout`]), so every step of an application exposes one instance
//! shape.
//!
//! ## The binding chain
//!
//! A claim or challenge is enforced by the **parent**, from the instance:
//!
//! 1. Every slot's wires are written into the child's application $k(Y)$
//!    (the internal `preamble` stage's `application_ky`), binding them to
//!    its committed application rx.
//! 2. A claim is folded — the quotient $(p(X) - y)/(X - x)$ into $f(X)$,
//!    $p(X)$ beta-accumulated into the PCS $(P, u, v)$ accumulator, with
//!    `compute_v` re-deriving the matching terms from the instance. A
//!    challenge is re-derived per `(child, slot)` by the internal
//!    `challenge_binding` circuit. A root proof's own slots are checked
//!    natively by [`Application::verify`](crate::Application::verify).
//!
//! Beyond that remains the framework-wide deferred PCS opening — the
//! commitment-to-carried-polynomial link that no commitment in the system
//! has yet, `bridge_f` and the endoscaling commitments included.

use alloc::vec::Vec;

use ragu_arithmetic::{Cycle, ff::Field};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::{Element, allocator::Standard, vec::Len};

use crate::{
    internal::challenge::Padding,
    poly_commitment::{PolyCommitment, PolyHandle},
};

/// The in-circuit wires of a derived challenge.
pub struct ChallengeWires<'dr, D: Driver<'dr>> {
    /// Exactly [`HookLayout::challenge_width`] elements: the caller's, then
    /// the sentinel in each position left empty.
    pub inputs: Vec<Element<'dr, D>>,
    /// The challenge, hashed from [`inputs`](Self::inputs).
    pub challenge: Element<'dr, D>,
}

/// The in-circuit wires of one opening claim.
pub struct QueryWires<'dr, D: Driver<'dr>> {
    /// The opened polynomial's embedded commitment coordinates — the same
    /// wires the polynomial's own slot holds.
    pub coords: [Element<'dr, D>; 2],
    /// The opening point.
    pub x: Element<'dr, D>,
    /// The claimed evaluation.
    pub y: Element<'dr, D>,
}

/// Accumulates hook wires during one [`Step::witness`](crate::step::Step::witness)
/// run. The adapter constructs it and drains it into a [`FrameworkAux`]; a
/// step reaches it through [`StepCtx`](crate::step::StepCtx).
pub struct FrameworkHooks<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    /// One entry per claim, in call order.
    poly_queries: Vec<QueryWires<'dr, D>>,
    /// One entry per polynomial slot, in slot order — a clone of the very
    /// handle the step body holds, so the instance names the caller's wires.
    witnessed_polys: Vec<PolyHandle<'dr, D, C>>,
    /// One `(inputs, challenge)` record per challenge slot, in slot order.
    challenge_pairs: Vec<ChallengeWires<'dr, D>>,
    /// The application's declared slot capacities.
    hook_layout: HookLayout,
    _marker: core::marker::PhantomData<C>,
}

/// Every hook's output as plain values, drained from [`FrameworkHooks`] for
/// the fuse. A step circuit's `Aux` carries one beside the step's own;
/// adding a hook means adding a field here.
pub struct FrameworkAux<C: Cycle> {
    /// The witnessed polynomials, padded to capacity, in slot order; each
    /// carries the coefficients the fuse folds into the PCS accumulator.
    pub polys: Vec<PolyCommitment<C>>,
    /// The opening claims, padded to capacity, in call order.
    pub claims: Vec<crate::proof::ClaimOpening<C::CircuitField>>,
    /// The derived-challenge records, padded to capacity, in slot order.
    pub challenges: Vec<crate::proof::ChallengeOpening<C::CircuitField>>,
}

/// Transposes per-item driver values into one driver value holding the list;
/// on structure-only drivers the closure never runs, so nothing is taken.
fn collect_values<'dr, D: Driver<'dr>, T: Send>(
    values: Vec<DriverValue<D, T>>,
) -> Result<DriverValue<D, Vec<T>>> {
    D::try_just(move || Ok(values.into_iter().map(Maybe::take).collect()))
}

/// The hook capacities of an application, as type-level lengths on a marker
/// type; usually written as [`AppHooks`](crate::AppHooks).
///
/// [`PolyWitnesses`](Self::PolyWitnesses) is the expensive axis — a bridge
/// stage, a commitment, an MSM, and an endoscaling point per child, each.
/// [`PolyQueries`](Self::PolyQueries) is the cheap axis — one instance
/// triple, one `_08_f` quotient, one `compute_v` triple; a repeat opening
/// costs a claim slot and no polynomial slot.
/// [`ChallengeWidth`](Self::ChallengeWidth) costs `⌈width / rate⌉` sponge
/// permutations per `(child, slot)`.
///
/// Unused slots are padded by the framework; a step that exceeds a capacity
/// is refused at the call that exceeds it.
pub trait HookConfig: Send + Sync + 'static {
    /// Polynomial witnesses committed per step.
    type PolyWitnesses: Len;
    /// Polynomial queries enforced per step.
    type PolyQueries: Len;
    /// Challenges derived per step.
    type ChallengeDerivations: Len;
    /// Input elements one challenge derivation may absorb.
    type ChallengeWidth: Len;

    /// The declared capacities as the value every circuit is built from.
    fn layout() -> HookLayout {
        HookLayout {
            challenge_calls: Self::ChallengeDerivations::len(),
            challenge_width: Self::ChallengeWidth::len(),
            polys: Self::PolyWitnesses::len(),
            claims: Self::PolyQueries::len(),
        }
    }
}

/// The declared slot capacities as a value: what every application circuit
/// exposes, whatever its own step used.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HookLayout {
    /// [`derive_challenge`](crate::step::StepCtx::derive_challenge) calls.
    pub challenge_calls: usize,
    /// Input elements one challenge derivation absorbs; positions a caller
    /// leaves empty take a fixed sentinel.
    pub challenge_width: usize,
    /// Polynomial slots.
    pub polys: usize,
    /// Opening claims.
    pub claims: usize,
}

impl HookLayout {
    /// Instance elements the challenge slots occupy, per proof.
    pub const fn challenge_instance_len(&self) -> usize {
        self.challenge_calls * (self.challenge_width + 1)
    }

    /// Instance elements the poly and claim slots occupy, per proof.
    pub const fn poly_query_instance_len(&self) -> usize {
        self.polys * 2 + self.claims * 4
    }
}

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> FrameworkHooks<'dr, D, C> {
    pub(crate) fn witnessed_polys(&self) -> &[PolyHandle<'dr, D, C>] {
        &self.witnessed_polys
    }

    pub(crate) fn poly_queries(&self) -> &[QueryWires<'dr, D>] {
        &self.poly_queries
    }

    pub(crate) fn challenge_pairs(&self) -> &[ChallengeWires<'dr, D>] {
        &self.challenge_pairs
    }

    /// Reads each hook's wires back out as plain values, for the fuse.
    pub(crate) fn into_values(self) -> Result<DriverValue<D, FrameworkAux<C>>> {
        let mut polys = Vec::with_capacity(self.witnessed_polys.len());
        for handle in self.witnessed_polys {
            let coefficients = handle.coefficients();
            let coords = handle.coords();
            polys.push(D::try_just(|| {
                Ok(PolyCommitment::from_parts(
                    coefficients.take(),
                    [*coords[0].value().take(), *coords[1].value().take()],
                ))
            })?);
        }
        let polys = collect_values::<D, _>(polys)?;

        let mut claims = Vec::with_capacity(self.poly_queries.len());
        for QueryWires { coords, x, y } in self.poly_queries {
            claims.push(D::try_just(|| {
                Ok(crate::proof::ClaimOpening {
                    coords: [*coords[0].value().take(), *coords[1].value().take()],
                    x: *x.value().take(),
                    y: *y.value().take(),
                })
            })?);
        }
        let claims = collect_values::<D, _>(claims)?;

        let mut challenges = Vec::with_capacity(self.challenge_pairs.len());
        for pair in self.challenge_pairs {
            challenges.push(D::try_just(|| {
                let mut inputs = Vec::with_capacity(pair.inputs.len());
                for input in &pair.inputs {
                    inputs.push(*input.value().take());
                }
                Ok(crate::proof::ChallengeOpening {
                    inputs,
                    challenge: *pair.challenge.value().take(),
                })
            })?);
        }
        let challenges = collect_values::<D, _>(challenges)?;

        // `finish_slots` padded each to the application's capacity.
        D::try_just(move || {
            Ok(FrameworkAux {
                polys: polys.take(),
                claims: claims.take(),
                challenges: challenges.take(),
            })
        })
    }
}

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> FrameworkHooks<'dr, D, C> {
    pub(crate) fn new(hook_layout: HookLayout) -> Self {
        Self {
            poly_queries: Vec::new(),
            witnessed_polys: Vec::new(),
            challenge_pairs: Vec::new(),
            hook_layout,
            _marker: core::marker::PhantomData,
        }
    }

    /// The work behind
    /// [`StepCtx::witness_polynomial`](crate::step::StepCtx::witness_polynomial).
    pub(crate) fn witness_polynomials<const N: usize>(
        &mut self,
        dr: &mut D,
        commitments: [DriverValue<D, PolyCommitment<C>>; N],
    ) -> Result<[PolyHandle<'dr, D, C>; N]> {
        if !self.witnessed_polys.is_empty() {
            return Err(Error::InvalidWitness(
                "witness_polynomial may only be called once per step".into(),
            ));
        }

        let mut handles = Vec::with_capacity(N);
        for commitment in commitments {
            handles.push(self.witness_one_polynomial(dr, commitment)?);
        }

        // `N` handles were pushed, one per element of a `[_; N]`.
        Ok(handles
            .try_into()
            .map_err(|_| ())
            .expect("one handle per commitment"))
    }

    /// Witnesses one polynomial into the next free slot; slot assignment is
    /// call order, and the call sequence is circuit structure.
    fn witness_one_polynomial(
        &mut self,
        dr: &mut D,
        commitment: DriverValue<D, PolyCommitment<C>>,
    ) -> Result<PolyHandle<'dr, D, C>> {
        if self.witnessed_polys.len() >= self.hook_layout.polys {
            return Err(Error::InvalidWitness(
                "step witnessed more polynomials than there are polynomial slots".into(),
            ));
        }
        // Plain value-filled wires, fail-closed: the accumulator and the
        // root recompute force them to be the recorded host's.
        let coord_values = commitment.as_ref().map(|c| c.coords());
        let coords = [
            Element::alloc(dr, &mut (), coord_values.as_ref().map(|c| c[0]))?,
            Element::alloc(dr, &mut (), coord_values.as_ref().map(|c| c[1]))?,
        ];
        let coefficients = commitment.map(PolyCommitment::into_coefficients);
        let handle = PolyHandle::new(coefficients, coords);
        self.witnessed_polys.push(handle.clone());
        Ok(handle)
    }

    /// The sink behind
    /// [`StepCtx::enforce_poly_query`](crate::step::StepCtx::enforce_poly_query);
    /// padding reaches it directly, naming slot 0. The call count is circuit
    /// structure.
    pub(crate) fn enforce_poly_query(
        &mut self,
        coords: [Element<'dr, D>; 2],
        x: Element<'dr, D>,
        y: Element<'dr, D>,
    ) -> Result<()> {
        if self.poly_queries.len() >= self.hook_layout.claims {
            return Err(Error::InvalidWitness(
                "step enforced more poly-queries than there are query slots".into(),
            ));
        }
        self.poly_queries.push(QueryWires { coords, x, y });
        Ok(())
    }

    /// The work behind
    /// [`StepCtx::derive_challenge`](crate::step::StepCtx::derive_challenge),
    /// which documents the caller's obligation.
    pub(crate) fn derive_challenge(
        &mut self,
        dr: &mut D,
        params: &C::Params,
        inputs: &[Element<'dr, D>],
    ) -> Result<Element<'dr, D>> {
        let width = self.hook_layout.challenge_width;
        if inputs.len() > width {
            return Err(Error::InvalidWitness(
                "derive_challenge received more elements than a challenge slot absorbs".into(),
            ));
        }
        if self.challenge_pairs.len() >= self.hook_layout.challenge_calls {
            return Err(Error::InvalidWitness(
                "step derived more challenges than there are challenge slots".into(),
            ));
        }

        let supplied = D::try_just(|| {
            let mut values = Vec::with_capacity(inputs.len());
            for input in inputs {
                values.push(*input.value().take());
            }
            Ok(values)
        })?;

        // Pad to the slot's full complement with the sentinel and hash; the
        // parent absorbs a fixed number per slot, so it must see them all.
        let derived = D::try_just(|| {
            crate::internal::challenge::padded_challenge::<C>(params, &supplied.take(), width)
        })?;

        let allocator = &mut Standard::new();
        let mut witnessed = Vec::with_capacity(width);
        for index in 0..width {
            match inputs.get(index) {
                // Reuse a supplied wire, so the instance names the very wire
                // the caller pinned.
                Some(input) => witnessed.push(input.clone()),
                None => witnessed.push(Element::alloc(
                    dr,
                    allocator,
                    derived.as_ref().map(|(padded, _)| padded[index]),
                )?),
            }
        }

        let challenge = Element::alloc(dr, allocator, derived.map(|(_, challenge)| challenge))?;
        self.challenge_pairs.push(ChallengeWires {
            inputs: witnessed,
            challenge: challenge.clone(),
        });
        Ok(challenge)
    }

    /// Pads every slot the body left unused up to declared capacity; the
    /// adapter calls this after the step body returns.
    ///
    /// Padding goes through the same doors a step body does, and the padded
    /// values are *real*: a trivially true claim (the constant polynomial
    /// $1$, opened at $0$) and the challenge the sentinel points honestly
    /// hash to — per-application constants of [`Padding`], computed at
    /// finalize and supplied as witness data.
    pub(crate) fn finish_slots(
        &mut self,
        dr: &mut D,
        padding: DriverValue<D, Padding<C>>,
    ) -> Result<()> {
        // Polynomials first, so every padding query has slot 0 to name.
        while self.witnessed_polys.len() < self.hook_layout.polys {
            let commitment = padding.as_ref().map(|p| p.poly.clone());
            self.witness_one_polynomial(dr, commitment)?;
        }

        // Every padding query is the *same* query — slot 0 at $x = 0$, true
        // whatever the slot holds — witnessed once and reused.
        let allocator = &mut Standard::new();
        let mut padding_query: Option<(Element<'dr, D>, Element<'dr, D>)> = None;
        while self.poly_queries.len() < self.hook_layout.claims {
            let slot_zero = self.witnessed_polys.first().ok_or_else(|| {
                Error::InvalidWitness("a padding claim requires a polynomial slot to name".into())
            })?;
            let coords = slot_zero.coords();
            let (x, y) = match &padding_query {
                Some((x, y)) => (x.clone(), y.clone()),
                None => {
                    let x = Element::alloc(dr, allocator, D::just(|| D::F::ZERO))?;
                    // Slot 0's value at zero is its constant term.
                    let y_value = slot_zero
                        .coefficients()
                        .map(|coefficients| coefficients.first().copied().unwrap_or(D::F::ZERO));
                    let y = Element::alloc(dr, allocator, y_value)?;
                    padding_query = Some((x.clone(), y.clone()));
                    (x, y)
                }
            };
            self.enforce_poly_query(coords, x, y)?;
        }

        // Every input position holds the sentinel and the challenge is their
        // hash; the allocation pattern matches a `derive_challenge` call
        // exactly, so the circuit is the one the body would have produced.
        while self.challenge_pairs.len() < self.hook_layout.challenge_calls {
            let allocator = &mut Standard::new();
            let mut witnessed = Vec::with_capacity(self.hook_layout.challenge_width);
            for _ in 0..self.hook_layout.challenge_width {
                witnessed.push(Element::alloc(
                    dr,
                    allocator,
                    padding.as_ref().map(|p| p.sentinel),
                )?);
            }
            let challenge = Element::alloc(
                dr,
                allocator,
                padding.as_ref().map(|p| {
                    p.challenge
                        .expect("a padded challenge slot implies a nonzero challenge width")
                }),
            )?;
            self.challenge_pairs.push(ChallengeWires {
                inputs: witnessed,
                challenge,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ragu_core::{
        drivers::emulator::{Emulator, Wireless},
        maybe::Empty,
    };
    use ragu_pasta::{Fp, Pasta};

    use super::*;

    type Dr<'dr> = Emulator<Wireless<Empty, Fp>>;

    /// The framework caps a step body at the application's challenge capacity.
    #[test]
    fn challenge_slots_are_capped() {
        let with_capacity = |calls| {
            FrameworkHooks::<Dr<'_>, Pasta>::new(HookLayout {
                challenge_calls: calls,
                challenge_width: 2,
                ..HookLayout::default()
            })
        };
        let params = Pasta::baked();

        let mut dr: Dr<'_> = Emulator::counter();
        with_capacity(1)
            .derive_challenge(&mut dr, params, &[])
            .expect("a slot is available");

        let mut dr: Dr<'_> = Emulator::counter();
        let error = with_capacity(0)
            .derive_challenge(&mut dr, params, &[])
            .err()
            .expect("a step with no challenge slots cannot derive one");
        assert!(
            alloc::format!("{error}").contains("challenge slots"),
            "unexpected error: {error}"
        );
    }
}
