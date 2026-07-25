//! Context object threaded through [`Step::witness`](super::Step::witness).
//!
//! Bundles the framework-side state — the [`Driver`] and the
//! [`FrameworkHooks`] container — so that reusable sub-components called from a
//! step body can take a single `&mut StepCtx` rather than juggling individual
//! arguments. The poly-query claim sink is
//! exposed via [`enforce_poly_query`](StepCtx::enforce_poly_query) and the
//! challenge hook via [`derive_challenge`](StepCtx::derive_challenge). New
//! framework hooks added in the future (e.g. transcript threading) belong on
//! [`FrameworkHooks`] as well.

use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe,
};
use ragu_primitives::{Element, Point};

use crate::{
    framework_hooks::{ChallengeInput, FrameworkHooks},
    poly_commitment::{PolyCommitment, PolyQueryHandle},
    step::internal::challenge_stage::ChallengeSlots,
};

/// Framework-side state threaded through [`Step::witness`](super::Step::witness).
/// The poly-query claim sink is exposed via
/// [`enforce_poly_query`](Self::enforce_poly_query) and sound Fiat–Shamir
/// challenges via [`derive_challenge`](Self::derive_challenge).
pub struct StepCtx<'a, 'dr, D, C>
where
    D: Driver<'dr>,
    C: Cycle<CircuitField = D::F>,
{
    /// The underlying driver. Components called from a step body use this for
    /// allocation and constraint emission.
    pub dr: &'a mut D,
    hooks: &'a mut FrameworkHooks<'dr, D, C>,
    /// The application circuit's reserved challenge-stage wires, lent by the
    /// adapter. `None` on the registration dry run, which has no
    /// `StageBuilder`. The concrete store is `R`-parameterized; erasing it here
    /// keeps the rank out of every `Step::witness` signature.
    ///
    /// An `Option` rather than a [`DriverValue`], unlike
    /// [`FrameworkHooks::proof_values`]: the dry run and keygen both run on
    /// structure-only drivers and differ only in whether the stages exist, so
    /// this absence is not the driver's.
    challenge_slots: Option<&'a mut dyn ChallengeSlots<'dr, D, C>>,
}

impl<'a, 'dr, D, C> StepCtx<'a, 'dr, D, C>
where
    D: Driver<'dr>,
    C: Cycle<CircuitField = D::F>,
{
    pub(crate) fn new(dr: &'a mut D, hooks: &'a mut FrameworkHooks<'dr, D, C>) -> Self {
        Self {
            dr,
            hooks,
            challenge_slots: None,
        }
    }

    /// Lends this context the adapter's reserved challenge-stage wires.
    pub(crate) fn with_challenge_slots(
        mut self,
        slots: &'a mut dyn ChallengeSlots<'dr, D, C>,
    ) -> Self {
        self.challenge_slots = Some(slots);
        self
    }

    /// Witnesses a [`PolyCommitment`] in-circuit, producing a
    /// [`PolyQueryHandle`].
    ///
    /// The commitment is allocated as an in-circuit [`Point`] (reachable via
    /// [`PolyQueryHandle::commitment`] for challenges, hashing, etc.) while the
    /// polynomial is retained for a later
    /// [`enforce_poly_query`](Self::enforce_poly_query). Because the
    /// [`PolyCommitment`] came from
    /// [`Application::commit_polynomial`](crate::Application::commit_polynomial),
    /// the commitment and the polynomial cannot be mismatched by an honest
    /// caller.
    pub fn witness_polynomial<R: Rank>(
        &mut self,
        commitment: DriverValue<D, PolyCommitment<C, R>>,
    ) -> Result<PolyQueryHandle<'dr, D, C, R>> {
        let slot = self.hooks.next_claim_slot()?;
        let host_for_com = commitment.as_ref().map(|c| c.host());
        let proof_values = self.hooks.proof_values();
        let com_value = D::try_just(move || {
            let proof_values = proof_values.take();
            let alpha = crate::internal::challenge::claim_bridge_alpha::<C>(
                proof_values.bridge_alpha,
                slot,
            );
            crate::internal::challenge::claim_bridge_commitment::<C, R>(
                proof_values.params,
                slot,
                alpha,
                host_for_com.take(),
            )
        })?;
        let com = Point::alloc(self.dr, com_value)?;
        let polynomial = commitment.map(PolyCommitment::into_polynomial);
        Ok(PolyQueryHandle::new(com, polynomial, slot))
    }

    /// Records a poly-query claim: the polynomial behind `commitment` evaluates
    /// to `y` at the point `x`.
    ///
    /// `commitment` is a [`PolyQueryHandle`] from
    /// [`witness_polynomial`](Self::witness_polynomial); it carries both the
    /// in-circuit commitment and the polynomial, so the two cannot drift apart.
    ///
    /// This is the *succinct* claim path: the polynomial stays out of the
    /// circuit, and enforcement is **recursive**. The claim wires occupy one
    /// of the circuit's [`NUM_POLY_QUERY_SLOTS`](crate::NUM_POLY_QUERY_SLOTS)
    /// instance slots, binding them to the circuit's $k(Y)$; when the
    /// resulting proof is fused as a child, the parent folds the quotient
    /// $(p(X) - y)/(X - x)$ into $f(X)$ and the polynomial (with its host
    /// commitment) into the PCS $(P, u, v)$ accumulator, and its `compute_v`
    /// circuit re-derives the matching terms from the instance-bound claim
    /// data. A root proof's own claims — not yet folded by a parent — are
    /// checked natively by [`Application::verify`](crate::Application::verify)
    /// against the carried claim polynomials.
    ///
    /// The fuse raising the claim also pre-checks it natively, so an honest
    /// prover with a dishonest witness fails early with `InvalidWitness`.
    /// That pre-check carries no soundness weight (it runs on the prover);
    /// enforcement never relies on prover behavior.
    ///
    /// Claims must be raised in the order their polynomials were witnessed —
    /// the handle's slot fixes which bridge stage its `com` commits to, and
    /// that must be the instance slot the claim occupies. Interleaving them out
    /// of order fails with `InvalidWitness`.
    ///
    /// # Soundness status
    ///
    /// A claim's `com` is the commitment of that claim's **bridge stage** — a
    /// polynomial the proof carries, whose wires are the claim's host
    /// commitment, which the `loading` circuit ties to the host point the
    /// parent folds and endoscales. That is the framework's own idiom for
    /// crossing the curve boundary (compare `bridge_f_commitment` and
    /// `bridge_f_rx`, which predate poly-query), so a claim inherits exactly
    /// its guarantees and exactly its one gap: no commitment in the system is
    /// yet bound to the polynomial it commits to, the framework-wide deferred
    /// PCS opening. A **root** proof's own claims are not affected —
    /// [`Application::verify`](crate::Application::verify) rebuilds the bridge
    /// stage and compares.
    ///
    /// The full chain, and what each link rests on, is documented once in
    /// [`framework_hooks`](crate::framework_hooks). The executable
    /// demonstration is `poly_query_com_is_not_bound_to_the_folded_polynomial`
    /// in `tests/recursive_claims.rs`, which is the acceptance gate for the
    /// deferred work.
    pub fn enforce_poly_query<R: Rank>(
        &mut self,
        commitment: &PolyQueryHandle<'dr, D, C, R>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
    ) -> Result<()> {
        self.hooks.enforce_polynomial_query(
            self.dr,
            commitment.slot(),
            commitment.commitment().clone(),
            x,
            y,
            commitment.coefficients(),
        )
    }

    /// Derives a sound Fiat–Shamir challenge from `input`.
    ///
    /// The input's elements are pinned into this slot's challenge stage; the
    /// challenge is the hash of that stage's commitment, bridged onto the
    /// nested curve. Both the bridged point and the challenge are witnessed
    /// here and written into the circuit's instance, and the parent's
    /// `challenge_binding` circuit re-derives one from the other — so no
    /// Poseidon permutation is synthesized in the application circuit, and the
    /// cost does not scale with the input's width.
    ///
    /// On a value-carrying driver the returned `Element` holds the real
    /// challenge immediately, so the step body can evaluate polynomials at it
    /// right away.
    pub fn derive_challenge<G: ChallengeInput<'dr, D>>(
        &mut self,
        input: G,
    ) -> Result<Element<'dr, D>> {
        const {
            assert!(
                G::ELEMENTS <= crate::CHALLENGE_WIDTH,
                "challenge input is wider than CHALLENGE_WIDTH",
            );
        }
        self.hooks.take_challenge_slot()?;

        let mut elements = alloc::vec::Vec::with_capacity(G::ELEMENTS);
        input.append_elements(self.dr, &mut elements)?;
        if elements.len() != G::ELEMENTS {
            return Err(ragu_core::Error::InvalidWitness(
                "challenge input serialized a different number of elements than its declared \
                 width"
                    .into(),
            ));
        }

        // Fill this slot's reserved stage wires with the input values, then pin
        // every one of them: the stage's commitment covers the whole width, so
        // an unconstrained wire would let a prover vary the commitment — and
        // with it the challenge — for free.
        let inputs = D::try_just(|| {
            let mut inputs = [<D::F as ragu_arithmetic::ff::Field>::ZERO; crate::CHALLENGE_WIDTH];
            for (cell, element) in inputs.iter_mut().zip(elements.iter()) {
                *cell = *element.value().take();
            }
            Ok(inputs)
        })?;

        let proof_values = self.hooks.proof_values();
        let Some(slots) = self.challenge_slots.as_deref_mut() else {
            // Discovery dry run: no `StageBuilder`, so no slots to fill. Only
            // the call count is read from it.
            return Element::alloc(
                self.dr,
                &mut ragu_primitives::allocator::Standard::new(),
                D::try_just(|| {
                    Err(ragu_core::Error::Initialization(
                        "derive_challenge on the registration dry run has no stage to commit"
                            .into(),
                    ))
                })?,
            );
        };
        let filled = slots.fill_next(self.dr, proof_values, inputs.clone())?;

        for (index, wire) in filled.wires.iter().enumerate() {
            match elements.get(index) {
                Some(element) => ragu_primitives::GadgetExt::enforce_equal(wire, self.dr, element)?,
                None => Element::enforce_zero(wire, self.dr)?,
            }
        }

        // The challenge is the hash of this slot's stage commitment, bridged
        // onto the nested curve so its coordinates are native. Both the point
        // and the challenge are witnessed here; the parent's binding circuit
        // re-derives one from the other, against the instance-bound pair.
        let point = Point::alloc(self.dr, filled.derived.as_ref().map(|(point, _)| *point))?;
        let challenge = Element::alloc(
            self.dr,
            &mut ragu_primitives::allocator::Standard::new(),
            filled.derived.map(|(_, challenge)| challenge),
        )?;
        self.hooks
            .record_challenge(point, challenge.clone(), inputs);
        Ok(challenge)
    }
}
