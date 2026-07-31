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
//! What makes the witnessed limbs the commitment's is enforced elsewhere:
//! the lifts are instance wires folded into the application circuit's $k(Y)$;
//! at every fuse the parent's `compute_v` re-derives the claim-lift
//! polynomial's $q(u)$ from them and enforces it against the folded value;
//! at root, `verify` recomputes them from the recorded host commitment.

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
