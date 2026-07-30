//! Per-claim bridge stages: one committed stage per poly-query claim slot.
//!
//! A poly-query claim's nested-curve commitment `com_i` is what the *step*
//! sees — its Fiat–Shamir challenges and header hashes are derived from it.
//! For `com_i` to be bound to the polynomial the parent actually folds, it must
//! be the commitment of a polynomial the proof carries, whose wires determine
//! the claim's host commitment. That is the shape of every other cross-curve
//! commitment in the framework (see [`super::f`], whose rx's wires *are*
//! `native_f`, tied to the endoscaling by the
//! [`loading`](super::super::circuits::loading) circuit).
//!
//! Each slot gets its own stage — and therefore its own commitment — because
//! the consumer needs a per-polynomial handle. Committing all slots in one
//! stage (as [`super::eval`] does for its stashed copies) would yield a single
//! commitment that cannot identify an individual claim.
//!
//! ## Why the wires are bits, and not the point
//!
//! Every other bridge family carries its host point as two coordinate wires.
//! This one carries the coordinates' *bits*, because a step has to be able to
//! read the commitment it is holding.
//!
//! A step is a circuit over `CircuitField`; a host commitment's coordinates are
//! `ScalarField`. No constraint spans two circuits, so a step cannot be handed
//! the coordinates — it can only be handed something it can *recompute*. What
//! it can recompute is this stage's commitment: `commit(rx) = α·G₀ + Σ wᵢ·Gᵢ`,
//! where the `Gᵢ` are nested generators, which are native to a step. With the
//! wires as bits, the step witnesses those bits, recomputes the sum with
//! [`ragu_primitives::Point`] arithmetic, and enforces it equals the
//! `bridge_com` it already holds. Pedersen binding then forces its bits to be
//! *these* wires, and the ties below force these wires to be the real
//! coordinates. Coordinate wires admit no such opening: recovering them would
//! need full-width scalar multiplication in-circuit, which the framework does
//! not have.
//!
//! The bits are never constrained to be bits *here* — booleanity arrives from
//! the step's side, through that same binding. What this stage's own consumers
//! need is only that the wires *determine* the host point, which the
//! recomposition ties in [`loading`](super::super::circuits::loading) and
//! [`copying`](super::super::circuits::copying) establish. A slot no step ever
//! opens may therefore hold non-bit wires satisfying the same linear form; that
//! is harmless, because the linear form still names exactly one host point.
//!
//! ## Canonicity is structural
//!
//! Only [`HIGH_BITS`] wires carry a coordinate's high half, so the largest
//! representable value is `2^254 - 1`. Both Pasta moduli exceed that, so no
//! wrapped second representation of a coordinate exists and the decomposition
//! is unique — no comparison against the modulus is needed. The cost is a
//! completeness bound rather than a soundness one: a coordinate at or above
//! `2^254` cannot be witnessed at all, which is roughly a `2^-129` fraction of
//! the field.
//!
//! The layout is little-endian per coordinate, low half then high half, so a
//! limb read out of these wires is bit-identical to the one a consumer computes
//! natively by splitting `to_repr()` into two 16-byte halves.
//!
//! ## Why this family is a run
//!
//! How many claim slots exist is a property of the application being built, not
//! of any Rust type, so this family cannot be a chain of per-slot aliases. It
//! is a [`crate::internal::Run`] of [`Slot`] instead: one stage in the typed
//! hierarchy spanning every slot, subdivided by a [`layout`] that says where
//! each slot's wires begin.
//!
//! The subdivision is exact: [`VALUES`] is even, so each slot spans a whole
//! number of gates with nothing wasted to padding, and a run of `n` slots
//! occupies precisely the gates a chain of `n` aliases would.
//!
//! Nothing downstream has to care: the loading circuit's `Last` is still an
//! ordinary stage type.

use core::marker::PhantomData;

use ragu_arithmetic::{CurveAffine, ff::PrimeField};
use ragu_circuits::{polynomials::Rank, staging::InducedStages};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Boolean, Element, GadgetExt, Point, multipack,
    promotion::Demoted,
    vec::{CollectFixed, ConstLen, FixedVec},
};

/// Bits carried for a coordinate's low half.
///
/// The endoscalar width, and the width a consumer splitting `to_repr()` into
/// 16-byte halves produces.
pub const LOW_BITS: usize = 128;

/// Bits carried for a coordinate's high half.
///
/// Two short of [`LOW_BITS`], which is what makes the decomposition canonical:
/// see the module docs.
pub const HIGH_BITS: usize = 126;

/// Bits carried per coordinate.
pub const COORD_BITS: usize = LOW_BITS + HIGH_BITS;

/// Wires in one claim-bridge slot: both coordinates, in bits.
pub const VALUES: usize = 2 * COORD_BITS;

/// The claim-bridge family: every slot, as one stage chained after
/// [`super::eval`].
///
/// How many slots there are is the application's poly capacity — a value, read
/// from [`layout`] — so it appears nowhere in this type.
pub type Run<C, R> = crate::internal::Run<C, R, super::eval::Stage<C, R>>;

/// The witness for a single claim slot: the host commitment it names.
///
/// The same input every other bridge family takes. What differs is how this
/// stage stores it.
pub struct Witness<C: CurveAffine> {
    pub host: C,
}

/// Prover-internal output gadget for one claim slot: a host commitment's
/// coordinates, in little-endian bits, low half then high half.
///
/// Stage communication data, not part of the circuit's public instance. The
/// bits ride as [`Demoted`] booleans, exactly as
/// [`Endoscalar`](ragu_primitives::Endoscalar) carries its bits through
/// [`EndoscalarStage`](crate::internal::endoscalar::EndoscalarStage): the
/// booleanity constraints [`Boolean::alloc`] emits in [`Slot::witness`] reach
/// no configuring circuit — `configure_stage` runs a stage witness under a
/// counting emulator and allocates plain stage wires — and `Demoted` is the
/// framework's type for a boolean-shaped wire whose constraints are not
/// carried with it. Where booleanity does come from is the module docs' story.
#[derive(Gadget)]
pub struct Output<'dr, D: Driver<'dr>> {
    /// All [`VALUES`] bits, in wire order.
    #[ragu(gadget)]
    bits: FixedVec<Demoted<'dr, D, Boolean<'dr, D>>, ConstLen<{ VALUES }>>,

    /// The four 128-bit limbs `[x_lo, x_hi, y_lo, y_hi]`, for re-promotion.
    #[ragu(value)]
    limbs: DriverValue<D, [u128; 4]>,
}

impl<'dr, D: Driver<'dr>> Output<'dr, D> {
    /// Returns an iterator over the bits, promoted with their values —
    /// [`Endoscalar::bits`](ragu_primitives::Endoscalar::bits)'s shape.
    pub fn bits(&self) -> impl Iterator<Item = Boolean<'dr, D>> {
        let mut values = self.limbs.as_ref().map(|limbs| limb_bits(*limbs));

        self.bits.iter().map(move |demoted| {
            demoted.promote(
                values
                    .as_mut()
                    .map(|bits| bits.next().expect("VALUES bits")),
            )
        })
    }
}

impl<'dr, D: Driver<'dr>> Output<'dr, D>
where
    D::F: PrimeField,
{
    /// The host commitment's coordinates, recomposed from the wires.
    ///
    /// Literally [`multipack`]: [`COORD_BITS`] does not exceed the field's
    /// capacity, so each coordinate is exactly one chunk — one linear
    /// combination, no gates, no constraints, and therefore legal inside the
    /// bonding circuits that reach this through [`enforce_names`]. The step
    /// side packs its bits with the same function, which is what makes the two
    /// sides' limb semantics identical by construction.
    pub fn coordinates(&self, dr: &mut D) -> Result<(Element<'dr, D>, Element<'dr, D>)> {
        assert!(
            COORD_BITS <= D::F::CAPACITY as usize,
            "a coordinate must recompose as a single multipack chunk"
        );

        let bits = self.bits().collect::<alloc::vec::Vec<_>>();
        let x = multipack(dr, &bits[..COORD_BITS])?;
        let y = multipack(dr, &bits[COORD_BITS..])?;

        match (&x[..], &y[..]) {
            ([x], [y]) => Ok((x.clone(), y.clone())),
            _ => unreachable!("COORD_BITS fits one chunk, as asserted above"),
        }
    }
}

/// Enforces that a claim slot's wires name `host`.
///
/// The tie both [`loading`](super::super::circuits::loading) (for this proof's
/// own slots) and [`copying`](super::super::circuits::copying) (for a child's,
/// one generation up) make. One function, because the two must state the same
/// relation: a fuse establishes about its immediate children exactly what the
/// child's own proof establishes about itself.
///
/// Two constraints per slot, over linear combinations. Nothing here is a gate,
/// so it is legal in the bonding circuits that are the only callers.
pub(crate) fn enforce_names<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>>(
    dr: &mut D,
    bridge: &Output<'dr, D>,
    host: &Point<'dr, D, C>,
) -> Result<()>
where
    D::F: PrimeField,
{
    // A point's coordinates are reached through its `Write` impl, as
    // `compute_v`'s claim selection does.
    let mut written = alloc::vec::Vec::with_capacity(2);
    host.write(dr, &mut written)?;
    let [host_x, host_y] = <[Element<'dr, D>; 2]>::try_from(written)
        .map_err(|_| Error::MalformedEncoding("a point is two wires".into()))?;

    let (x, y) = bridge.coordinates(dr)?;
    x.sub(dr, &host_x).enforce_zero(dr)?;
    y.sub(dr, &host_y).enforce_zero(dr)
}

/// The bits of the four limbs in wire order: little-endian within each limb,
/// low limbs full-width, high limbs [`HIGH_BITS`] wide.
fn limb_bits(limbs: [u128; 4]) -> impl Iterator<Item = bool> {
    [
        (limbs[0], LOW_BITS),
        (limbs[1], HIGH_BITS),
        (limbs[2], LOW_BITS),
        (limbs[3], HIGH_BITS),
    ]
    .into_iter()
    .flat_map(|(limb, width)| (0..width).map(move |index| (limb >> index) & 1 == 1))
}

/// The four 128-bit limbs `[x_lo, x_hi, y_lo, y_hi]` of a host commitment's
/// coordinates — the consumer's own split of `to_repr()` into 16-byte halves.
///
/// Errors rather than truncating when a coordinate does not fit: see the
/// module docs on canonicity, which is what the width bound buys.
fn host_limbs<C: CurveAffine>(host: C) -> Result<[u128; 4]> {
    let coordinates = host.coordinates().into_option().ok_or_else(|| {
        Error::InvalidWitness(
            "the identity has no coordinates and cannot be witnessed in-circuit".into(),
        )
    })?;

    let mut limbs = [0u128; 4];
    for (coordinate, pair) in [*coordinates.x(), *coordinates.y()]
        .into_iter()
        .zip(limbs.chunks_mut(2))
    {
        let repr = coordinate.to_repr();
        let (lo, hi) = split_coordinate(repr.as_ref())?;
        pair[0] = lo;
        pair[1] = hi;
    }

    Ok(limbs)
}

/// Splits a coordinate's canonical little-endian bytes into 16-byte halves,
/// rejecting values at or above `2^254`.
fn split_coordinate(bytes: &[u8]) -> Result<(u128, u128)> {
    if bytes.len() < 32 {
        return Err(Error::InvalidWitness(
            "a coordinate narrower than 32 bytes is not a supported cycle's".into(),
        ));
    }

    let lo = u128::from_le_bytes(bytes[..16].try_into().expect("16 bytes"));
    let hi = u128::from_le_bytes(bytes[16..32].try_into().expect("16 bytes"));

    if hi >> HIGH_BITS != 0 || bytes[32..].iter().any(|byte| *byte != 0) {
        return Err(Error::InvalidWitness(
            "a polynomial commitment with a coordinate at or above 2^254 cannot be \
             decomposed canonically and so cannot be witnessed in-circuit"
                .into(),
        ));
    }

    Ok((lo, hi))
}

/// One claim slot's stage body.
///
/// Its own chain position is unused — where a slot's wires land comes from
/// [`layout`], not from this type — so one type serves every slot.
pub struct Slot<C, R> {
    _marker: PhantomData<(C, R)>,
}

impl<C, R> Clone for Slot<C, R> {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl<C, R> Default for Slot<C, R> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<C: CurveAffine, R: Rank> ragu_circuits::staging::Stage<C::Base, R> for Slot<C, R> {
    /// Unused: a run's slots are placed by [`layout`], not by the typed chain.
    type Parent = ();
    type Witness<'source> = &'source Witness<C>;
    type OutputKind = Kind![C::Base; Output<'_, _>];

    fn values() -> usize {
        VALUES
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::Base>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        let limbs = D::try_just(|| host_limbs::<C>(witness.snag().host))?;
        let mut values = limbs.as_ref().map(|limbs| limb_bits(*limbs));

        let bits = (0..VALUES)
            .map(|_| {
                let bit = Boolean::alloc(
                    dr,
                    &mut (),
                    values
                        .as_mut()
                        .map(|bits| bits.next().expect("VALUES bits")),
                )?;
                Demoted::new(&bit)
            })
            .try_collect_fixed()?;

        Ok(Output { bits, limbs })
    }
}

/// The layout subdividing [`Run`] into one slot per claim.
///
/// A free function taking `capacity` rather than a method on
/// [`ProofBuilder`](crate::proof::ProofBuilder), because it has two callers
/// holding different state and both must produce a bit-identical commitment:
/// `ProofBuilder::claim_bridge_rx` has the builder, while
/// `StepCtx::witness_polynomial` runs during witnessing with no builder at all,
/// only the capacity off its hooks. Caching this on the builder would fix one
/// path and reintroduce the divergence this shape prevents.
///
/// Builds only the claims run. `NestedLayouts::new` would eagerly build the
/// chain plus all four runs — points, preamble, eval, claims — and discard
/// three; `claim_run_layout` takes the chain and produces just this one.
pub fn layout<C: CurveAffine, R: Rank>(polys: usize) -> InducedStages {
    use crate::internal::nested::{chain_layout, claim_run_layout};

    claim_run_layout::<C, R>(&chain_layout::<C, R>(polys), polys)
}

#[cfg(test)]
mod tests {
    use ragu_pasta::EqAffine;

    use super::*;
    use crate::internal::tests::{R, assert_stage_values};

    #[test]
    fn stage_values_matches_wire_count() {
        // Only the slot has a type-level width. The run's is the application's
        // poly capacity, so it is checked as a layout below, not as a `Stage`.
        assert_stage_values(&Slot::<EqAffine, R>::default());
    }

    /// A slot spans a whole number of gates, which is what makes the run's
    /// subdivision exact rather than approximate.
    #[test]
    fn a_slot_is_a_whole_number_of_gates() {
        assert_eq!(VALUES % 2, 0, "a slot would waste a wire to padding");
    }

    /// The layout tiles the run: one slot per claim, each [`VALUES`] wires
    /// wide, anchored where the nested chain ends — at whatever capacity it is
    /// asked for, not at one blessed shape.
    #[test]
    fn layout_tiles_the_run() {
        let gates_per_slot = VALUES.div_ceil(2);

        for polys in [1, 3, 8] {
            let layout = layout::<EqAffine, R>(polys);

            assert_eq!(layout.len(), polys, "one slot per polynomial");
            assert_eq!(
                layout.skip_gates(0),
                crate::internal::nested::chain_layout::<EqAffine, R>(polys).final_skip_gates(),
                "the first slot does not start where the chain ends"
            );
            for slot in 0..polys {
                assert_eq!(
                    layout.skip_gates(slot),
                    layout.skip_gates(0) + slot * gates_per_slot,
                    "slot {slot} does not start one slot past its predecessor"
                );
            }
        }
    }

    /// The limbs are the coordinates: `lo + 2^128·hi`, recomposed in the
    /// field, is the coordinate itself.
    ///
    /// Longhand on purpose — the shift is built by doubling, and the expected
    /// value never calls the code under test, so the assertion checks that the
    /// split really is the inverse of recomposition rather than restating it.
    #[test]
    fn limbs_recompose_to_the_coordinates() {
        use ragu_arithmetic::{
            ff::{Field, PrimeField},
            group::Group as _,
            pasta_curves::group::Curve,
        };
        use ragu_pasta::Fp;

        // The host curve's scalars are the *circuit* field — the fact this
        // whole stage exists to exploit.
        let host = (<EqAffine as CurveAffine>::CurveExt::generator() * Fp::from(7)).to_affine();
        let limbs = host_limbs(host).expect("the generator's multiple is decomposable");

        let mut shift = <EqAffine as CurveAffine>::Base::ONE;
        for _ in 0..LOW_BITS {
            shift = shift.double();
        }

        let coordinates = host.coordinates().unwrap();
        for (coordinate, pair) in [*coordinates.x(), *coordinates.y()]
            .into_iter()
            .zip(limbs.chunks(2))
        {
            let recomposed = <EqAffine as CurveAffine>::Base::from_u128(pair[0])
                + <EqAffine as CurveAffine>::Base::from_u128(pair[1]) * shift;
            assert_eq!(recomposed, coordinate, "the limbs are not the coordinate");
        }
    }

    /// The wire order is the module docs' order: little-endian within each
    /// limb, `x` before `y`, low half before high half.
    #[test]
    fn wire_order_is_low_then_high_little_endian() {
        let bits = limb_bits([1, 2, 4, 8]).collect::<alloc::vec::Vec<_>>();

        assert_eq!(bits.len(), VALUES);
        assert_eq!(bits.iter().filter(|bit| **bit).count(), 4);
        assert!(bits[0], "x_lo = 1 sets wire 0");
        assert!(bits[LOW_BITS + 1], "x_hi = 2 sets its wire 1");
        assert!(bits[COORD_BITS + 2], "y_lo = 4 sets its wire 2");
        assert!(bits[COORD_BITS + LOW_BITS + 3], "y_hi = 8 sets its wire 3");
    }

    /// A high half with bit 126 or 127 set encodes a value at or above
    /// `2^254`, which has no canonical decomposition and is refused.
    #[test]
    fn a_coordinate_at_2_254_is_rejected() {
        let mut bytes = [0u8; 32];

        bytes[31] = 0x40; // bit 254
        assert!(split_coordinate(&bytes).is_err());

        bytes[31] = 0x20; // bit 253, the top admissible bit
        assert!(split_coordinate(&bytes).is_ok());
    }

    /// The identity has no coordinates, so it cannot be witnessed — the same
    /// rejection [`Point::alloc`](ragu_primitives::Point::alloc) makes.
    #[test]
    fn the_identity_is_rejected() {
        use ragu_arithmetic::group::CurveAffine as _;

        assert!(host_limbs(EqAffine::identity()).is_err());
    }
}
