//! The real limbs of a real polynomial commitment, held by a step.
//!
//! A step cannot hold a host-curve point — its coordinates live in the other
//! field — but it can hold the coordinates' 128-bit *limbs*, because a 128-bit
//! integer is the same number in both fields. This module holds the step-side
//! piece: allocating the limbs as real booleans (booleanity is constrained
//! *here*, where it costs ~1 gate per bit), packing them into the four field
//! elements a consumer hashes, and lifting them into the instance-bound form
//! the accumulator consumes.
//!
//! # Soundness
//!
//! What makes the witnessed limbs *provably* the commitment's is a chain in
//! which every link is either an in-circuit constraint or the accumulator:
//!
//! 1. **Limbs → lifts.** The limbs are allocated as boolean-constrained bits
//!    and both the packed elements and their [`Endoscalar::lift`]s are derived
//!    from the *same* bits, in this circuit. `lift` is injective on 128-bit
//!    inputs (`qa/lean/Ragu/Contrib/EndoscalarProof.lean`), so equal lifts
//!    mean equal limbs.
//! 2. **Lifts → the proof.** Each lift is an instance wire in the
//!    application circuit's trailing lift region, folded into its $k(Y)$ —
//!    enforced against the committed application rx by `outer_collapse` at
//!    every fuse and natively at root.
//! 3. **Lifts → the recorded hosts.** The claim-lift polynomial $q$ has the
//!    *recorded* host commitments' canonical limb lifts as coefficients
//!    ([`claim_lift_poly`](crate::internal::challenge::claim_lift_poly), a
//!    deterministic function — never carried, rebuilt everywhere). At root,
//!    `verify` recomputes every slot's lifts from the recorded host and
//!    compares. At every fuse, the parent's `compute_v` Horner-walks the
//!    child's lift wires to $q(u)$ and enforces it against the eval stage's
//!    carried value, which the $(P, u, v)$ accumulator folds alongside $q$
//!    itself.
//! 4. **Recorded hosts → the folded polynomials.** `verify` recomputes each
//!    `commit(claim_polys[slot])` natively at root; recursively, the hosts
//!    are stashed, endoscaled into $P$, and folded with their polynomials by
//!    `_10_p` (with the claim-bridge stages tied to them by `loading` and
//!    `copying`).
//!
//! The binding rests on the discrete-log-relation assumption over the
//! commitment generators (`book/src/protocol/prelim/assumptions.md`). The
//! generators are nothing-up-my-sleeve: hash-to-curve under the domain
//! `"Ragu-Parameters"` over an index counter (`ragu_pasta`'s
//! `params_for_curve`), so no party can know a relation among them.
//!
//! **Parity.** Link 3's fuse-time leg compares $q(u)$ *as folded* — the
//! commitment-to-carried-polynomial link for the accumulated $q$ is the
//! framework-wide deferred PCS opening, the same link `bridge_f`, `native_p`
//! and every commitment in the system rest on. The limb capability is
//! therefore exactly as strong as the framework's own bridges: fail-closed at
//! root today, and it inherits the deferred work whenever that lands, with no
//! further change here.
//!
//! **Canonicity.** [`host_limbs`](crate::internal::challenge::host_limbs)
//! rejects coordinates at or above `2^254`, so a commitment has exactly one
//! limb decomposition and the in-circuit values are bit-identical to the
//! native split of `to_repr()` into 16-byte halves — the same split consumers
//! outside the proof compute. One digest per commitment, in and out of
//! circuit.

use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe,
};
use ragu_primitives::{Element, Endoscalar, io::Write, multipack};

/// A host commitment's four 128-bit limbs, as circuit-field elements.
///
/// `x_lo` is `u128::from_le_bytes(x.to_repr()[..16])` and so on — bit-identical
/// to the split a consumer computes natively, so hashing these four elements
/// reproduces exactly the digest computed outside the proof.
///
/// Derives [`Write`] so the limbs feed a
/// [`Sponge`](ragu_primitives::poseidon::Sponge) directly.
#[derive(Gadget, Write)]
pub struct HostLimbs<'dr, D: Driver<'dr>> {
    /// Low 128 bits of the `x` coordinate.
    #[ragu(gadget)]
    pub x_lo: Element<'dr, D>,
    /// High 126 bits of the `x` coordinate (bits 128..254).
    #[ragu(gadget)]
    pub x_hi: Element<'dr, D>,
    /// Low 128 bits of the `y` coordinate.
    #[ragu(gadget)]
    pub y_lo: Element<'dr, D>,
    /// High 126 bits of the `y` coordinate (bits 128..254).
    #[ragu(gadget)]
    pub y_hi: Element<'dr, D>,
}

/// Witnesses four limbs as constrained booleans, returning the packed limb
/// elements alongside their lifts.
///
/// The bits are allocated through [`Endoscalar::alloc`], so every bit carries
/// a real booleanity constraint; [`multipack`] (free) recomposes each limb's
/// bits into its integer as a field element, and [`Endoscalar::lift`] produces
/// the instance-bound form. One `u128` means one number in both fields, which
/// is what lets the same bits serve the anchor (this field) and the
/// accumulator's `q` coefficients (whose commitment lives on the host curve).
pub(crate) fn witness_host_limbs<'dr, D: Driver<'dr>>(
    dr: &mut D,
    limbs: DriverValue<D, [u128; 4]>,
) -> Result<(HostLimbs<'dr, D>, [Element<'dr, D>; 4])>
where
    D::F: ragu_arithmetic::ff::WithSmallOrderMulGroup<3>,
{
    let mut packed = alloc::vec::Vec::with_capacity(4);
    let mut lifts = alloc::vec::Vec::with_capacity(4);

    for k in 0..4 {
        let endo = Endoscalar::alloc(dr, limbs.as_ref().map(|limbs| limbs[k]))?;

        let bits = endo.bits().collect::<alloc::vec::Vec<_>>();
        let mut elements = multipack(dr, &bits)?;
        // 128 bits fit any supported circuit field's capacity in one chunk.
        assert_eq!(elements.len(), 1, "a limb is one multipack chunk");
        packed.push(elements.pop().expect("one element"));

        lifts.push(endo.lift(dr)?);
    }

    let [x_lo, x_hi, y_lo, y_hi] = <[Element<'dr, D>; 4]>::try_from(packed)
        .map_err(|_| ())
        .expect("four limbs");
    let lifts = <[Element<'dr, D>; 4]>::try_from(lifts)
        .map_err(|_| ())
        .expect("four lifts");

    Ok((
        HostLimbs {
            x_lo,
            x_hi,
            y_lo,
            y_hi,
        },
        lifts,
    ))
}
