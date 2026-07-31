//! The hook capacity an application declares, as one type.
//!
//! An application's circuits expose a fixed instance width:
//!
//! ```text
//! 3·HEADER_SIZE + 2·POLYS + 4·CLAIMS + CHALLENGES·(CHALLENGE_WIDTH + 1) + 2·POLYS
//! ```
//!
//! `HEADER_SIZE` rides [`Application`](crate::Application) as a const
//! generic, as it always has — it threads through
//! [`Step`](crate::step::Step) signatures, where only a const parameter can
//! carry it on stable Rust. The four hook capacities ride as **one type**:
//! [`AppHooks`], written inline —
//!
//! ```text
//! Application<'params, C, R, HEADER_SIZE, AppHooks<3, 3, 1, 6>>
//! ```
//!
//! — and two applications with different capacities are two different
//! [`Application`](crate::Application) types. Generic code accepts any
//! capacity through the [`AppHooksLayout`] trait, which [`AppHooks`]
//! implements; an application that prefers self-documenting numbers may
//! implement [`AppHooksLayout`] on its own named marker type instead.
//!
//! Every capacity is required — each one prices instance wires (and the
//! challenge width additionally prices absorb permutations per child and
//! slot), so an application declares what it pays for rather than
//! inheriting a default it never chose.

use ragu_primitives::vec::{ConstLen, Len};

use crate::framework_hooks::{ChallengeLayout, HookLayout, PolyQueryLayout};

/// The hook capacities of an application, as type-level lengths on a marker
/// type. Usually written as [`AppHooks`] rather than implemented by hand.
///
/// Each member is a [`Len`], so it slots directly into the `FixedVec`s the
/// framework sizes with it; the plain numbers are read back through the
/// provided accessors ([`polys`](Self::polys), [`claims`](Self::claims),
/// [`challenges`](Self::challenges),
/// [`challenge_width`](Self::challenge_width)).
///
/// [`PolyCount`](Self::PolyCount) is how many
/// [`witness_polynomial`](crate::step::StepCtx::witness_polynomial) slots
/// any one step may fill — the expensive axis: a bridge stage, a
/// commitment, an MSM, and an endoscaling point per child, each.
/// [`ClaimCount`](Self::ClaimCount) is how many
/// [`enforce_poly_query`](crate::step::StepCtx::enforce_poly_query) claims
/// it may raise — the cheap axis: one instance triple, one `_08_f`
/// quotient, one `compute_v` triple. A repeat opening costs a claim slot
/// and no polynomial slot.
///
/// [`ChallengeCount`](Self::ChallengeCount) is how many
/// [`derive_challenge`](crate::step::StepCtx::derive_challenge) calls any
/// one step may make, and [`ChallengeWidth`](Self::ChallengeWidth) the
/// widest input one call may pass, in field elements — a
/// [`coords`](crate::PolyHandle::coords) pair is two; the width's cost is
/// [`ChallengeLayout::permutations`](crate::framework_hooks::ChallengeLayout::permutations),
/// paid by the internal `challenge_binding` circuit per `(child, slot)`.
///
/// Every step of an application exposes exactly these counts, whatever it
/// uses; unused slots are padded by the framework, and a step that asks for
/// more than the declared capacity is refused at the call that exceeds it.
pub trait AppHooksLayout: Send + Sync + 'static {
    /// Polynomial slots per step, as a type-level length.
    type PolyCount: Len;
    /// Poly-query claim slots per step, as a type-level length.
    type ClaimCount: Len;
    /// Challenge derivations per step, as a type-level length.
    type ChallengeCount: Len;
    /// Input elements one challenge derivation may absorb, as a type-level
    /// length.
    type ChallengeWidth: Len;

    /// Polynomial slots per step.
    fn polys() -> usize {
        Self::PolyCount::len()
    }

    /// Poly-query claim slots per step.
    fn claims() -> usize {
        Self::ClaimCount::len()
    }

    /// Challenge derivations per step.
    fn challenges() -> usize {
        Self::ChallengeCount::len()
    }

    /// Input elements one challenge derivation may absorb.
    fn challenge_width() -> usize {
        Self::ChallengeWidth::len()
    }

    /// The declared capacities as the value every circuit is built from —
    /// the [`framework_hooks`](crate::framework_hooks) form of this layout.
    fn hook_layout() -> HookLayout {
        HookLayout::declared(
            Self::polys(),
            Self::claims(),
            Self::challenges(),
            Self::challenge_width(),
        )
    }

    /// The challenge layout for this application.
    fn challenge_layout() -> ChallengeLayout {
        ChallengeLayout {
            calls: Self::challenges(),
            width: Self::challenge_width(),
        }
    }

    /// The poly-query layout for this application.
    fn poly_query_layout() -> PolyQueryLayout {
        PolyQueryLayout {
            polys: Self::polys(),
            claims: Self::claims(),
        }
    }
}

/// The usual way to declare an application's hook capacity:
///
/// ```rust
/// use ragu_circuits::polynomials::ProductionRank;
/// use ragu_pasta::Pasta;
/// use ragu_pcd::{AppHooks, Application};
///
/// type MyApp<'params> = Application<'params, Pasta, ProductionRank, 4, AppHooks<3, 3, 1, 6>>;
/// ```
pub struct AppHooks<
    const POLYS: usize,
    const CLAIMS: usize,
    const CHALLENGES: usize,
    const CHALLENGE_WIDTH: usize,
>;

impl<const POLYS: usize, const CLAIMS: usize, const CHALLENGES: usize, const CHALLENGE_WIDTH: usize>
    AppHooksLayout for AppHooks<POLYS, CLAIMS, CHALLENGES, CHALLENGE_WIDTH>
{
    type PolyCount = ConstLen<POLYS>;
    type ClaimCount = ConstLen<CLAIMS>;
    type ChallengeCount = ConstLen<CHALLENGES>;
    type ChallengeWidth = ConstLen<CHALLENGE_WIDTH>;
}
