//! The real limbs of a real polynomial commitment, held by a step.
//!
//! A step cannot hold a host-curve point natively — its coordinates live in
//! the other field — but a coordinate bounded below $2^{254}$ is the same
//! integer in both fields, and both Pasta moduli exceed $2^{254}$. This module
//! holds the step-side piece: allocating each coordinate's 254 bits as real
//! booleans (booleanity is constrained *here*, where it costs ~1 gate per
//! bit), packing them into the four 128-bit limb elements a consumer hashes,
//! and packing the same bits whole into the two embedded-coordinate elements
//! the instance carries.
//!
//! The high half of each coordinate is 126 bits, not 128: at 254 total bits
//! the maximum recomposable value is $2^{254} - 1$, below the field modulus,
//! so the packed coordinate cannot wrap and the instance tie pins the bits
//! exactly — the same bound the native split enforces.
//!
//! What makes the witnessed bits the commitment's is enforced elsewhere: the
//! embedded coordinates are instance wires folded into the application
//! circuit's $k(Y)$; at every fuse the parent's `compute_v` re-derives the
//! claim-coordinate polynomial's $q(u)$ from them and enforces it against the
//! folded value; at root, `verify` recomputes them from the recorded host
//! commitment.

use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe,
};
use ragu_primitives::{Boolean, Element, io::Write, multipack};

/// Bits in a coordinate's low limb.
const LO_BITS: usize = 128;
/// Bits in a coordinate's high limb; see the module docs for why not 128.
const HI_BITS: usize = 126;

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

/// Witnesses the four limbs as constrained booleans, returning the packed limb
/// elements alongside the two packed whole coordinates.
///
/// Every bit is allocated through [`Boolean::alloc`], so it carries a real
/// booleanity constraint; [`multipack`] (free) recomposes each limb's bits
/// into its integer, and each coordinate's full 254 bits into the embedded
/// coordinate — one multipack chunk, since 254 is the circuit field's
/// capacity. The limbs and the embedded coordinate are linear functions of
/// the same bits, which is what lets one witnessing serve the anchor (the
/// limbs) and the instance (the coordinates).
pub(crate) fn witness_host_limbs<'dr, D: Driver<'dr>>(
    dr: &mut D,
    limbs: DriverValue<D, [u128; 4]>,
) -> Result<(HostLimbs<'dr, D>, [Element<'dr, D>; 2])>
where
    D::F: ragu_arithmetic::ff::PrimeField,
{
    let mut packed = alloc::vec::Vec::with_capacity(4);
    let mut coords = alloc::vec::Vec::with_capacity(2);

    for coordinate in 0..2 {
        let mut bits = alloc::vec::Vec::with_capacity(LO_BITS + HI_BITS);
        for (limb, width) in [(2 * coordinate, LO_BITS), (2 * coordinate + 1, HI_BITS)] {
            for i in 0..width {
                bits.push(Boolean::alloc(
                    dr,
                    &mut (),
                    limbs.as_ref().map(|limbs| (limbs[limb] >> i) & 1 == 1),
                )?);
            }
        }

        for range in [0..LO_BITS, LO_BITS..LO_BITS + HI_BITS] {
            let mut elements = multipack(dr, &bits[range])?;
            // 128 bits fit any supported circuit field's capacity in one chunk.
            assert_eq!(elements.len(), 1, "a limb is one multipack chunk");
            packed.push(elements.pop().expect("one element"));
        }

        let mut elements = multipack(dr, &bits)?;
        // 254 bits are exactly the supported circuit fields' capacity.
        assert_eq!(elements.len(), 1, "a coordinate is one multipack chunk");
        coords.push(elements.pop().expect("one element"));
    }

    let [x_lo, x_hi, y_lo, y_hi] = <[Element<'dr, D>; 4]>::try_from(packed)
        .map_err(|_| ())
        .expect("four limbs");
    let coords = <[Element<'dr, D>; 2]>::try_from(coords)
        .map_err(|_| ())
        .expect("two coordinates");

    Ok((
        HostLimbs {
            x_lo,
            x_hi,
            y_lo,
            y_hi,
        },
        coords,
    ))
}
