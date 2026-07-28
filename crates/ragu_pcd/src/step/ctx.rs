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
    framework_hooks::FrameworkHooks,
    poly_commitment::{PolyCommitment, PolyQueryHandle},
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
}

impl<'a, 'dr, D, C> StepCtx<'a, 'dr, D, C>
where
    D: Driver<'dr>,
    C: Cycle<CircuitField = D::F>,
{
    pub(crate) fn new(dr: &'a mut D, hooks: &'a mut FrameworkHooks<'dr, D, C>) -> Self {
        Self { dr, hooks }
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
        let slot = self.hooks.next_poly_slot()?;
        let host_for_com = commitment.as_ref().map(|c| c.host());
        let proof_values = self.hooks.proof_values();
        let capacity = self.hooks.capacity();
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
                capacity,
            )
        })?;
        let com = Point::alloc(self.dr, com_value)?;
        let polynomial = commitment.map(PolyCommitment::into_polynomial);
        let handle = PolyQueryHandle::new(com, polynomial, slot);
        self.hooks
            .record_polynomial(handle.commitment().clone(), handle.coefficients())?;
        Ok(handle)
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
    /// of the circuit's claim instance slots, binding them to the circuit's $k(Y)$; when the
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
    /// Claims may be raised in any order, and the **same handle may be used
    /// more than once**: a query names its polynomial by index rather than by
    /// position, so opening one polynomial at several points costs one
    /// claim slot each and no additional polynomial slot — no second bridge stage,
    /// no second commitment, no second MSM, no extra endoscaling point. That is
    /// the cheap direction to grow in; witnessing another polynomial is the
    /// expensive one.
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
        self.hooks
            .enforce_polynomial_query(self.dr, commitment.slot(), x, y)
    }

    /// Derives a sound Fiat–Shamir challenge from `points`.
    ///
    /// The challenge is `Hash(points)`, hashed natively and witnessed here; the
    /// points and the challenge go into the circuit's instance, and the
    /// parent's `challenge_binding` circuit re-derives the challenge from the
    /// points. **The step spends no Poseidon permutation and no committed
    /// stage** — the derivation is paid out of the framework's own budget, once
    /// per `(child, slot)`, so a step's cost does not depend on how many points
    /// it hashed.
    ///
    /// At most [`CHALLENGE_POINTS_PER_CALL`](crate::CHALLENGE_POINTS_PER_CALL)
    /// points, an application-level capacity; the remaining positions are
    /// filled with a fixed non-identity sentinel so the sponge's shape is the
    /// same for every slot.
    ///
    /// # What this binds, and what the caller must
    ///
    /// The framework guarantees only that the challenge is the hash of *these
    /// points*. A point binds whatever it commits to, so passing a commitment
    /// binds that commitment's polynomial — but passing a **freely witnessed**
    /// point binds nothing, and lets the prover grind the challenge by varying
    /// it. Every point here must be pinned: a
    /// [`PolyQueryHandle::commitment`](crate::poly_commitment::PolyQueryHandle::commitment),
    /// a header-carried point, or a point otherwise constrained in this step.
    /// This is the same discipline the framework applies to its own transcript:
    /// compress data into a binding commitment, then derive from that.
    ///
    /// On a value-carrying driver the returned `Element` holds the real
    /// challenge immediately, so the step body can evaluate polynomials at it
    /// right away.
    pub fn derive_challenge(
        &mut self,
        points: &[Point<'dr, D, C::NestedCurve>],
    ) -> Result<Element<'dr, D>> {
        if points.len() > crate::CHALLENGE_POINTS_PER_CALL {
            return Err(ragu_core::Error::InvalidWitness(
                "derive_challenge received more points than a challenge slot absorbs".into(),
            ));
        }
        self.hooks.reserve_challenge_slot()?;

        let proof_values = self.hooks.proof_values();
        let supplied = D::try_just(|| {
            let mut values = alloc::vec::Vec::with_capacity(points.len());
            for point in points {
                values.push(point.value().take());
            }
            Ok(values)
        })?;

        // Pad to the slot's full complement with the sentinel and hash. The
        // padded points are witnessed like the supplied ones: the parent
        // absorbs a fixed number per slot, so it must see them all.
        let derived = D::try_just(|| {
            let proof_values = proof_values.take();
            crate::internal::challenge::points_challenge::<C>(proof_values.params, &supplied.take())
        })?;

        let mut witnessed = alloc::vec::Vec::with_capacity(crate::CHALLENGE_POINTS_PER_CALL);
        for index in 0..crate::CHALLENGE_POINTS_PER_CALL {
            match points.get(index) {
                // A supplied point is already a wire in this circuit; reuse it
                // rather than re-witnessing, so the instance names the very
                // point the caller pinned.
                Some(point) => witnessed.push(point.clone()),
                None => witnessed.push(Point::alloc(
                    self.dr,
                    derived.as_ref().map(|(padded, _)| padded[index]),
                )?),
            }
        }

        let challenge = Element::alloc(
            self.dr,
            &mut ragu_primitives::allocator::Standard::new(),
            derived.map(|(_, challenge)| challenge),
        )?;
        self.hooks.record_challenge(witnessed, challenge.clone());
        Ok(challenge)
    }

    /// Closes out the framework's fixed-size slot layout, after the step body
    /// has run.
    ///
    /// First the determinism guard
    /// ([`FrameworkHooks::check_layout`](crate::framework_hooks::FrameworkHooks)),
    /// then padding. Every application circuit exposes exactly the
    /// application's settled capacity in claims, polynomials and challenge
    /// records, whatever the body used, so the instance shape — which the
    /// internal circuits read as a fixed-width record — never depends on
    /// *which* step produced the proof.
    ///
    /// Padding goes through the same doors a step body does:
    /// [`witness_polynomial`](Self::witness_polynomial) plus
    /// [`enforce_poly_query`](Self::enforce_poly_query) for a claim, and
    /// [`derive_challenge`](Self::derive_challenge) for a challenge. There is
    /// no second wire-allocation path to keep in step with the first, and the
    /// padded values are *real*: a claim that is trivially true (the constant
    /// polynomial $1$, opened at $0$ to $1$), and a challenge honestly derived
    /// from the sentinel points. Nothing downstream distinguishes them.
    ///
    /// An unused challenge slot is *filled*, not skipped, so the parent's
    /// binding circuit stays uniform: it re-derives every slot without knowing
    /// which the step actually used.
    ///
    /// `R` is a method parameter rather than a type parameter so the rank stays
    /// out of this context, and out of every `Step::witness` signature with it.
    pub(crate) fn finish_slots<R: Rank>(&mut self) -> Result<()> {
        self.hooks.check_layout()?;

        let allocator = &mut ragu_primitives::allocator::Standard::new();
        let capacity = self.hooks.capacity();

        // Polynomials first, so every query slot has something to name.
        let mut padding_handle = None;
        while self.hooks.polys_filled() < capacity.poly_query.polys {
            let proof_values = self.hooks.proof_values();
            let padding = D::try_just(move || {
                let (host, ..) =
                    crate::internal::challenge::padding_claim::<C>(proof_values.take().params);
                Ok(PolyCommitment::new(
                    crate::internal::challenge::padding_poly::<C, R>(),
                    host,
                ))
            })?;

            // The commitment goes through `witness_polynomial`, so the padding
            // slot's `com` is that slot's bridge-stage commitment, derived
            // exactly as a real polynomial's is.
            padding_handle = Some(self.witness_polynomial::<R>(padding)?);
        }

        // Then queries. A padding query opens a polynomial at $x = 0$, where the
        // value is that polynomial's constant term — true by construction,
        // whatever the slot holds, so no slot needs to be reserved for padding.
        //
        // Slot 0 serves every padding query: the one-hot in `compute_v` reaches
        // any polynomial equally, so no slot has to be reserved for padding.
        while self.hooks.claims_filled() < capacity.poly_query.claims {
            let slot = 0;
            let x = Element::alloc(
                self.dr,
                allocator,
                D::just(|| <D::F as ragu_arithmetic::ff::Field>::ZERO),
            )?;
            let y = Element::alloc(self.dr, allocator, self.hooks.poly_at_zero(slot))?;
            self.hooks.enforce_polynomial_query(self.dr, slot, x, y)?;
        }
        drop(padding_handle);

        // A padding challenge supplies no points at all, so every position
        // falls to `derive_challenge`'s sentinel arm.
        while self.hooks.challenges_filled() < capacity.challenge.calls {
            self.derive_challenge(&[])?;
        }

        Ok(())
    }
}
