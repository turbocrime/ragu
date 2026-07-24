//! Context object threaded through [`Step::witness`](super::Step::witness).
//!
//! Bundles the framework-side state — the [`Driver`], the [`FrameworkHooks`]
//! container, and the cycle's Poseidon parameters — so that reusable
//! sub-components called from a step body can take a single `&mut StepCtx`
//! rather than juggling individual arguments. The poly-query claim sink is
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
    hooks: &'a mut FrameworkHooks<'dr, D, C::NestedCurve>,
    poseidon: &'dr C::CircuitPoseidon,
    /// Cycle params and the proof's shared bridge-alpha source, needed to build
    /// a claim's bridge stage. `None` on structure-only passes, where no
    /// witness values exist and the commitment is never computed.
    claim_bridge: Option<(&'dr C::Params, C::ScalarField)>,
}

impl<'a, 'dr, D, C> StepCtx<'a, 'dr, D, C>
where
    D: Driver<'dr>,
    C: Cycle<CircuitField = D::F>,
{
    pub(crate) fn new(
        dr: &'a mut D,
        hooks: &'a mut FrameworkHooks<'dr, D, C::NestedCurve>,
        poseidon: &'dr C::CircuitPoseidon,
    ) -> Self {
        Self {
            dr,
            hooks,
            poseidon,
            claim_bridge: None,
        }
    }

    /// Like [`new`](Self::new), for the proving path: `params` and
    /// `bridge_alpha` let [`witness_polynomial`](Self::witness_polynomial)
    /// build each claim's bridge stage, whose commitment becomes that claim's
    /// `com`.
    pub(crate) fn proving(
        dr: &'a mut D,
        hooks: &'a mut FrameworkHooks<'dr, D, C::NestedCurve>,
        poseidon: &'dr C::CircuitPoseidon,
        params: &'dr C::Params,
        bridge_alpha: C::ScalarField,
    ) -> Self {
        Self {
            dr,
            hooks,
            poseidon,
            claim_bridge: Some((params, bridge_alpha)),
        }
    }

    /// The cycle's Poseidon parameters, for step bodies that hash in-circuit
    /// (e.g. via [`Sponge`](ragu_primitives::poseidon::Sponge) or the
    /// [`oracle`](crate::oracle) gadgets) without threading parameters through
    /// their own state.
    pub fn poseidon(&self) -> &'dr C::CircuitPoseidon {
        self.poseidon
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
        let claim_bridge = self.claim_bridge;
        let com_value = D::try_just(move || {
            let (params, bridge_alpha) = claim_bridge.ok_or_else(|| {
                ragu_core::Error::Initialization(
                    "witness_polynomial requires the proving adapter".into(),
                )
            })?;
            let alpha = crate::internal::challenge::claim_bridge_alpha::<C>(bridge_alpha, slot);
            crate::internal::challenge::claim_bridge_commitment::<C, R>(
                params,
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
    /// parent folds and endoscales. That puts claims at parity with every
    /// other cross-curve commitment in the framework (compare
    /// `bridge_f_commitment` and `bridge_f_rx`).
    ///
    /// The one remaining link — a commitment to the polynomial it commits to —
    /// is the framework-wide deferred PCS opening, which **no** commitment in
    /// the system currently has. Until that lands, an interior claim is not
    /// binding against a malicious prover; a **root** proof is safe, because
    /// [`Application::verify`](crate::Application::verify) rebuilds the bridge
    /// stage and compares. See `POLY_QUERY_SOUNDNESS.md`, and the executable
    /// demonstration in `tests/recursive_claims.rs`
    /// (`poly_query_com_is_not_bound_to_the_folded_polynomial`), which is the
    /// gate for that work.
    pub fn enforce_poly_query<R: Rank>(
        &mut self,
        commitment: &PolyQueryHandle<'dr, D, C, R>,
        x: Element<'dr, D>,
        y: Element<'dr, D>,
    ) -> Result<()> {
        self.hooks.enforce_polynomial_query(
            self.dr,
            commitment.slot(),
            commitment.com(),
            x,
            y,
            commitment.coefficients(),
        )
    }

    /// Derives a sound Fiat–Shamir challenge from `input`: the in-circuit
    /// Poseidon sponge hash of the input's elements. The returned `Element`
    /// is constrained to equal that hash, and on a value-carrying driver it
    /// holds the real challenge value immediately, so the step body can
    /// evaluate polynomials at it right away.
    pub fn derive_challenge<G: ChallengeInput<'dr, D>>(
        &mut self,
        input: G,
    ) -> Result<Element<'dr, D>> {
        self.hooks.derive_challenge(self.dr, self.poseidon, input)
    }
}
