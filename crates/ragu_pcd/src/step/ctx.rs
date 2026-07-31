//! Context object threaded through [`Step::witness`](super::Step::witness).
//!
//! Bundles the framework-side state — the [`Driver`] and the
//! [`FrameworkHooks`] container — so that reusable sub-components called from a
//! step body can take a single `&mut StepCtx` rather than juggling individual
//! arguments. The three hooks are exposed as
//! [`witness_polynomial`](StepCtx::witness_polynomial),
//! [`enforce_poly_query`](StepCtx::enforce_poly_query) and
//! [`derive_challenge`](StepCtx::derive_challenge). New framework hooks added in
//! the future (e.g. transcript threading) belong on [`FrameworkHooks`] as well.

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
    poly_commitment::{PolyCommitment, PolyHandle},
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

    /// Witnesses this step's polynomials in-circuit, producing one
    /// [`PolyHandle`] per [`PolyCommitment`].
    ///
    /// The polynomial is handled **abstractly, by its commitment**: what is
    /// allocated is the commitment [`Point`] and the two coordinate instance
    /// wires, and the coefficients ride along as a [`DriverValue`] —
    /// prover-side data, absent on a verifying driver — so witnessing costs a
    /// handful of allocations regardless of the polynomial's size. Anything
    /// added here must preserve that: allocate the commitment, retain the
    /// coefficients as a value.
    ///
    /// The bridge commitment point is reachable via
    /// [`PolyHandle::bridge_commitment`] for challenges, hashing and the like;
    /// the retained polynomial is what a later
    /// [`enforce_poly_query`](Self::enforce_poly_query) opens. A
    /// [`PolyCommitment`] can only come from
    /// [`Application::commit_polynomial`](crate::Application::commit_polynomial),
    /// which derives the commitment from the polynomial.
    ///
    /// A step witnesses *all* its polynomials in a single call, and the
    /// handles come back in the same order: slot `i` is index `i`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWitness`](ragu_core::Error::InvalidWitness) if
    /// called more than once, or if `N` exceeds the application's polynomial
    /// capacity.
    pub fn witness_polynomial<R: Rank, const N: usize>(
        &mut self,
        commitments: [DriverValue<D, PolyCommitment<C, R>>; N],
    ) -> Result<[PolyHandle<'dr, D, C, R>; N]> {
        if self.hooks.polys_filled() > 0 {
            return Err(ragu_core::Error::InvalidWitness(
                "witness_polynomial may only be called once per step".into(),
            ));
        }

        let mut handles = alloc::vec::Vec::with_capacity(N);
        for commitment in commitments {
            handles.push(self.witness_one_polynomial::<R>(commitment)?);
        }

        // `N` handles were pushed, one per element of a `[_; N]`.
        Ok(handles
            .try_into()
            .map_err(|_| ())
            .expect("one handle per commitment"))
    }

    /// Witnesses one polynomial into the next free slot.
    fn witness_one_polynomial<R: Rank>(
        &mut self,
        commitment: DriverValue<D, PolyCommitment<C, R>>,
    ) -> Result<PolyHandle<'dr, D, C, R>> {
        let slot = self.hooks.next_poly_slot()?;
        let host = commitment.as_ref().map(|c| c.host());
        let host_retained = commitment.as_ref().map(|c| c.host());
        // The slot's two coordinate instance wires: the host commitment's
        // affine coordinates, canonically embedded. Allocated here so they
        // exist for the whole step body; `poly_limbs` ties its constrained
        // bits to them, and slots never opened stay bound through the
        // accumulator and the root recompute.
        let coord_values = D::try_just(|| {
            crate::internal::challenge::host_coords::<C>(commitment.as_ref().take().host())
        })?;
        let coords = [
            Element::alloc(self.dr, &mut (), coord_values.as_ref().map(|c| c[0]))?,
            Element::alloc(self.dr, &mut (), coord_values.as_ref().map(|c| c[1]))?,
        ];
        let proof_values = self.hooks.proof_values();
        let capacity = self.hooks.capacity();
        let bridge_com_value = D::try_just(move || {
            let proof_values = proof_values.take();
            let alpha = crate::internal::challenge::claim_bridge_alpha::<C>(
                proof_values.bridge_alpha,
                slot,
            );
            crate::internal::challenge::claim_bridge_commitment::<C, R>(
                proof_values.params,
                slot,
                alpha,
                host.take(),
                capacity.poly_query.polys,
            )
        })?;
        let bridge_com = Point::alloc(self.dr, bridge_com_value)?;
        let polynomial = commitment.map(PolyCommitment::into_polynomial);
        let handle = PolyHandle::new(bridge_com, polynomial, host_retained, slot);
        self.hooks.record_polynomial(
            slot,
            handle.bridge_commitment().clone(),
            handle.coefficients(),
            coords,
        );
        Ok(handle)
    }

    /// Hands the step the four 128-bit limbs of `handle`'s **host**
    /// commitment — the real, canonical `commit(polynomial)` on the host
    /// curve — as circuit-field elements, provably.
    ///
    /// The limbs are witnessed here as constrained booleans and packed; what
    /// binds them to the commitment is the accumulator: the same bits pack
    /// into the slot's coordinate instance wires, bound to this circuit's
    /// $k(Y)$, and the framework polynomial $q$ — with the recorded hosts'
    /// embedded coordinates as coefficients — is folded against them.
    ///
    /// The values are bit-identical to splitting each coordinate's canonical
    /// little-endian bytes into 16-byte halves, so hashing them reproduces
    /// exactly the digest a consumer computes natively from the same
    /// commitment.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWitness`](ragu_core::Error::InvalidWitness) if
    /// called twice for the same handle.
    pub fn poly_limbs<R: Rank>(
        &mut self,
        handle: &PolyHandle<'dr, D, C, R>,
    ) -> Result<crate::step::HostLimbs<'dr, D>>
    where
        D::F: ragu_arithmetic::ff::PrimeField,
    {
        let host = handle.host_value();
        let limbs = D::try_just(|| crate::internal::challenge::host_limbs(host.take()))?;
        let (limbs, coords) = crate::step::limbs::witness_host_limbs(self.dr, limbs)?;
        self.hooks.tie_coords(self.dr, handle.slot(), coords)?;
        Ok(limbs)
    }

    /// Records a poly-query claim: the polynomial behind `commitment` evaluates
    /// to `y` at the point `x`.
    ///
    /// `commitment` is a [`PolyHandle`] from
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
    /// prover with a dishonest witness fails early with `InvalidWitness`;
    /// that pre-check runs on the prover and carries no soundness weight.
    ///
    /// Claims may be raised in any order, and the **same handle may be used
    /// more than once**: a claim carries the commitment of the polynomial it
    /// opens, so a repeat opening costs one claim slot and no polynomial
    /// slot. The commitment it carries is the very [`Point`] the handle
    /// holds.
    ///
    /// # Soundness status
    ///
    /// A claim's `bridge_com` is the commitment of that claim's **bridge
    /// stage** — a polynomial the proof carries, whose wires are the claim's
    /// host commitment, tied by the `loading` circuit to the host point the
    /// parent folds and endoscales. That is the framework's own idiom for
    /// crossing the curve boundary (compare `bridge_f_commitment` and
    /// `bridge_f_rx`), so a claim inherits exactly its guarantees, including
    /// the framework-wide deferred PCS opening; a **root** proof's own claims
    /// are checked natively by
    /// [`Application::verify`](crate::Application::verify). See
    /// [`framework_hooks`](crate::framework_hooks) for the chain.
    pub fn enforce_poly_query<R: Rank>(
        &mut self,
        commitment: &PolyHandle<'dr, D, C, R>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
    ) -> Result<()> {
        self.hooks
            .enforce_polynomial_query(commitment.bridge_commitment().clone(), x, y)
    }

    /// Derives a sound Fiat–Shamir challenge from `points`.
    ///
    /// The challenge is `Hash(points)`, hashed natively and witnessed here;
    /// the points and the challenge go into the circuit's instance, and the
    /// parent's `challenge_binding` circuit re-derives the challenge from the
    /// points. **The step spends no Poseidon permutation and no committed
    /// stage** — the derivation is paid out of the framework's own budget,
    /// once per `(child, slot)`.
    ///
    /// At most
    /// [`ChallengeLayout::width`](crate::framework_hooks::ChallengeLayout::width)
    /// points; the remaining positions are filled with a fixed non-identity
    /// sentinel so the sponge's shape is the same for every slot.
    ///
    /// # The caller's obligation
    ///
    /// The framework guarantees only that the challenge is the hash of *these
    /// points*. Every point must be one this step has pinned — a
    /// [`PolyHandle::bridge_commitment`](crate::poly_commitment::PolyHandle::bridge_commitment),
    /// a header-carried point, or a point otherwise constrained — since a
    /// freely witnessed point lets the prover grind the challenge by varying
    /// it.
    ///
    /// On a value-carrying driver the returned `Element` holds the real
    /// challenge immediately, so the step body can evaluate polynomials at it
    /// right away.
    pub fn derive_challenge(
        &mut self,
        points: &[Point<'dr, D, C::NestedCurve>],
    ) -> Result<Element<'dr, D>> {
        let width = self.hooks.capacity().challenge.width;
        if points.len() > width {
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
            crate::internal::challenge::points_challenge::<C>(
                proof_values.params,
                &supplied.take(),
                width,
            )
        })?;

        let mut witnessed = alloc::vec::Vec::with_capacity(width);
        for index in 0..width {
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

    /// Pads every slot the step body left unused, up to the application's
    /// declared capacity — the instance shape the internal circuits read as a
    /// fixed-width record.
    ///
    /// Padding goes through the same doors a step body does
    /// ([`witness_polynomial`](Self::witness_polynomial),
    /// [`enforce_poly_query`](Self::enforce_poly_query),
    /// [`derive_challenge`](Self::derive_challenge)), and the padded values
    /// are *real*: a trivially true claim (the constant polynomial $1$,
    /// opened at $0$ to $1$) and a challenge honestly derived from the
    /// sentinel points, so the parent's circuits treat every slot uniformly.
    ///
    /// `R` is a method parameter so the rank stays out of this context, and
    /// out of every `Step::witness` signature with it.
    pub(crate) fn finish_slots<R: Rank>(&mut self) -> Result<()> {
        let allocator = &mut ragu_primitives::allocator::Standard::new();
        let capacity = self.hooks.capacity();

        // Polynomials first, so every query slot has something to name.
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

            // The per-slot path: padding runs after the body, past the
            // step-facing array call's once-only rule. The handle is
            // discarded — the slot is recorded, and every padding query
            // names slot 0.
            self.witness_one_polynomial::<R>(padding)?;
        }

        // Then queries. Every padding query is the *same* query — slot 0
        // opened at $x = 0$, where the value is the constant term, true
        // whatever the slot holds — so it is witnessed once and its wires are
        // reused for every unused slot, keeping the step's circuit
        // independent of the claim capacity.
        let mut padding_query: Option<(Element<'dr, D>, Element<'dr, D>)> = None;
        while self.hooks.claims_filled() < capacity.poly_query.claims {
            let (x, y) = match &padding_query {
                Some((x, y)) => (x.clone(), y.clone()),
                None => {
                    let x = Element::alloc(
                        self.dr,
                        allocator,
                        D::just(|| <D::F as ragu_arithmetic::ff::Field>::ZERO),
                    )?;
                    let y = Element::alloc(self.dr, allocator, self.hooks.first_poly_at_zero()?)?;
                    padding_query = Some((x.clone(), y.clone()));
                    (x, y)
                }
            };
            self.hooks.enforce_padding_query(x, y)?;
        }

        // A padding challenge supplies no points at all, so every position
        // falls to `derive_challenge`'s sentinel arm.
        while self.hooks.challenges_filled() < capacity.challenge.calls {
            self.derive_challenge(&[])?;
        }

        Ok(())
    }
}
