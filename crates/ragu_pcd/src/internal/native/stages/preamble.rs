//! Preamble stage for native fuse operations.
//!
//! Verifies child proof headers and computes the Ky term.

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_arithmetic::Cycle;
use ragu_circuits::{horner::Horner, polynomials::Rank, staging};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Boolean, Element, GadgetExt, Point,
    allocator::Allocator,
    consistent::Consistent,
    vec::{CollectFixed, ConstLen, FixedVec},
};

use crate::{
    NUM_CHALLENGE_SLOTS, NUM_POLY_SLOTS, NUM_QUERY_SLOTS, Proof, header::Header,
    internal::native::unified, slot_vec::SlotVec, step::internal::padded,
};

type HeaderVec<'dr, D, const HEADER_SIZE: usize> = FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>>;

/// A single poly-query claim instance witnessed from a child proof: the
/// claimed nested-curve commitment point and the $(x, y)$ opening. The wire
/// layout (com.x, com.y, x, y) matches the claim-slot region of the
/// application circuit's instance, so writing these into the
/// [`application_ky`](ProofInputs::application_ky) Horner binds them to the
/// child's committed application rx.
#[derive(Gadget, Consistent)]
pub struct ClaimInstance<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    pub poly_slot: Element<'dr, D>,
    #[ragu(gadget)]
    pub x: Element<'dr, D>,
    #[ragu(gadget)]
    pub y: Element<'dr, D>,
}

/// A single witnessed polynomial as the application circuit's instance exposes
/// it: its nested-curve commitment. The wire layout (com.x, com.y) matches the
/// polynomial-slot region of that instance.
///
/// One per polynomial, not one per query — see
/// [`InstanceLen`](crate::step::internal::adapter::InstanceLen).
#[derive(Gadget, Consistent)]
pub struct PolyInstance<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    #[ragu(gadget)]
    pub com: Point<'dr, D, C::NestedCurve>,
}

/// A single derived-challenge pair witnessed from a child proof: the bridged
/// commitment to that slot's challenge stage, and the challenge hashed from it.
/// The wire layout (point.x, point.y, challenge) matches the challenge-slot
/// region of the application circuit's instance.
#[derive(Gadget, Consistent)]
pub struct ChallengeInstance<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>> {
    #[ragu(gadget)]
    pub point: Point<'dr, D, C::NestedCurve>,
    #[ragu(gadget)]
    pub challenge: Element<'dr, D>,
}

/// Witness data for a single child proof in the preamble stage.
pub struct ChildWitness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    /// Output header for this child proof.
    pub output_header: FixedVec<C::CircuitField, ConstLen<HEADER_SIZE>>,
    /// Reference to the child proof.
    pub proof: &'a Proof<C, R>,
}

/// Witness for the native preamble stage.
///
/// Contains references to the left and right proofs, plus output headers
/// computed outside the circuit.
pub struct Witness<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    /// Left child proof witness.
    pub left: ChildWitness<'a, C, R, HEADER_SIZE>,
    /// Right child proof witness.
    pub right: ChildWitness<'a, C, R, HEADER_SIZE>,
}

impl<'a, C: Cycle, R: Rank, const HEADER_SIZE: usize> Witness<'a, C, R, HEADER_SIZE> {
    /// Create a witness from child proof references and pre-computed output headers.
    pub fn new(
        left: &'a Proof<C, R>,
        right: &'a Proof<C, R>,
        left_output_header: &[C::CircuitField],
        right_output_header: &[C::CircuitField],
    ) -> Result<Self> {
        Ok(Witness {
            left: ChildWitness {
                output_header: FixedVec::try_from(left_output_header.to_vec())?,
                proof: left,
            },
            right: ChildWitness {
                output_header: FixedVec::try_from(right_output_header.to_vec())?,
                proof: right,
            },
        })
    }
}

/// Headers claimed by a child proof for its own left and right children.
#[derive(Gadget, Consistent)]
pub struct ChildHeaders<'dr, D: Driver<'dr>, const HEADER_SIZE: usize> {
    /// Left child header (grandchild from current perspective).
    #[ragu(gadget)]
    pub left: HeaderVec<'dr, D, HEADER_SIZE>,
    /// Right child header (grandchild from current perspective).
    #[ragu(gadget)]
    pub right: HeaderVec<'dr, D, HEADER_SIZE>,
}

/// Processed inputs from a single child proof in the preamble stage.
#[derive(Gadget, Consistent)]
pub struct ProofInputs<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>, const HEADER_SIZE: usize>
{
    /// Headers this child proof claimed for its own children.
    #[ragu(gadget)]
    pub children: ChildHeaders<'dr, D, HEADER_SIZE>,
    /// Output header of this child proof.
    #[ragu(gadget)]
    pub output_header: HeaderVec<'dr, D, HEADER_SIZE>,
    /// The poly-query claim instances this child proof raised, in slot order.
    /// Length is the configuring query-slot count; unused slots hold the
    /// canonical padding claim.
    #[ragu(gadget)]
    pub claims: SlotVec<ClaimInstance<'dr, D>>,
    /// The polynomials this child proof witnessed, in slot order. Length is
    /// the configuring poly-slot count; unused slots hold the canonical
    /// padding polynomial. A claim above names one of these by index.
    #[ragu(gadget)]
    pub polys: SlotVec<PolyInstance<'dr, D, C>>,
    /// The derived-challenge pairs the child's circuit exposed, in slot order.
    /// Length is the configuring challenge-slot count.
    #[ragu(gadget)]
    pub challenges: SlotVec<ChallengeInstance<'dr, D, C>>,
    #[ragu(gadget)]
    pub circuit_id: Element<'dr, D>,
    #[ragu(gadget)]
    pub unified: unified::Output<'dr, D, C>,
}

impl<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle, const HEADER_SIZE: usize>
    ProofInputs<'dr, D, C, HEADER_SIZE>
{
    /// Compute unified k(y) and unified+bridged k(y) values simultaneously,
    /// sharing computation.
    ///
    /// Returns `(unified_ky, unified_bridge_ky)` where:
    /// - `unified_ky` = k(y) for `(unified, 0)`
    /// - `unified_bridge_ky` = k(y) for `(unified, children.left, children.right, 0)`
    ///
    /// The Horner evaluation order and trailing zero here define the numerical
    /// values that [`ky_values`](super::super::claims::ky_values) must produce
    /// in matching positions.
    pub fn unified_ky_values(
        &self,
        dr: &mut D,
        y: &Element<'dr, D>,
    ) -> Result<(Element<'dr, D>, Element<'dr, D>)> {
        let mut ky = Horner::new(y);
        self.unified.write(dr, &mut ky)?;

        Ok((
            ({
                let mut ky = ky.clone();
                Element::zero(dr).write(dr, &mut ky)?;
                ky.finish_ky(dr)?
            }),
            ({
                self.children.left.write(dr, &mut ky)?;
                self.children.right.write(dr, &mut ky)?;
                Element::zero(dr).write(dr, &mut ky)?;
                ky.finish_ky(dr)?
            }),
        ))
    }

    /// Compute k(y) for the application circuit instance.
    ///
    /// Returns `application_ky` = k(y) for `(children.left, children.right,
    /// output_header, polys, claims)` — the polynomial slots follow the
    /// headers and the query slots follow those, matching the instance layout
    /// the adapter writes (`step::internal::adapter::InstanceLen`). This is
    /// what binds the witnessed polynomials and claim instances to the child's
    /// committed application rx.
    pub fn application_ky(&self, dr: &mut D, y: &Element<'dr, D>) -> Result<Element<'dr, D>> {
        let mut ky = Horner::new(y);
        self.children.left.write(dr, &mut ky)?;
        self.children.right.write(dr, &mut ky)?;
        self.output_header.write(dr, &mut ky)?;
        for poly in self.polys.iter() {
            poly.com.write(dr, &mut ky)?;
        }
        for claim in self.claims.iter() {
            claim.poly_slot.write(dr, &mut ky)?;
            claim.x.write(dr, &mut ky)?;
            claim.y.write(dr, &mut ky)?;
        }
        for pair in self.challenges.iter() {
            pair.point.write(dr, &mut ky)?;
            pair.challenge.write(dr, &mut ky)?;
        }
        ky.finish_ky(dr)
    }

    /// Returns true if this child proof is a trivial proof (output header suffix == 1).
    pub fn is_trivial(
        &self,
        dr: &mut D,
        allocator: &mut impl Allocator<'dr, D>,
    ) -> Result<Boolean<'dr, D>> {
        let suffix = &self.output_header[HEADER_SIZE - 1];
        suffix.is_equal(dr, allocator, &Element::one())
    }
}

impl<'dr, D: Driver<'dr, F = C::CircuitField>, C: Cycle, const HEADER_SIZE: usize>
    ProofInputs<'dr, D, C, HEADER_SIZE>
{
    /// Allocate ProofInputs from a proof reference and pre-computed output
    /// header. The slot counts are circuit-construction parameters (from the
    /// configuring plan): they fix the wire shape regardless of whether a
    /// witness is present, and the proof's own slot lists are checked against
    /// them.
    pub fn alloc<R: Rank>(
        dr: &mut D,
        proof: DriverValue<D, &Proof<C, R>>,
        output_header: DriverValue<D, &FixedVec<D::F, ConstLen<HEADER_SIZE>>>,
        num_polys: usize,
        num_queries: usize,
        num_challenges: usize,
    ) -> Result<Self> {
        fn alloc_header<'dr, D: Driver<'dr>, const N: usize>(
            dr: &mut D,
            allocator: &mut (),
            data: DriverValue<D, &[D::F]>,
        ) -> Result<FixedVec<Element<'dr, D>, ConstLen<N>>> {
            D::try_just(|| {
                if data.as_ref().take().len() != N {
                    return Err(Error::MalformedEncoding(
                        "Header data length does not match HEADER_SIZE".into(),
                    ));
                }

                Ok(())
            })?;

            (0..N)
                .map(|i| Element::alloc(dr, allocator, data.as_ref().map(|d| d[i])))
                .try_collect_fixed()
        }

        let allocator = &mut ();
        Ok(ProofInputs {
            children: ChildHeaders {
                left: alloc_header(dr, allocator, proof.as_ref().map(|p| p.left_header()))?,
                right: alloc_header(dr, allocator, proof.as_ref().map(|p| p.right_header()))?,
            },
            output_header: alloc_header(dr, allocator, output_header.as_ref().map(|h| &h[..]))?,
            polys: {
                D::try_just(|| {
                    if proof.as_ref().take().application_polys().len() != num_polys {
                        return Err(Error::MalformedEncoding(
                            "proof does not carry exactly the configured number of polynomial \
                             commitments"
                                .into(),
                        ));
                    }
                    Ok(())
                })?;
                (0..num_polys)
                    .map(|i| {
                        Ok(PolyInstance {
                            com: Point::alloc(
                                dr,
                                proof.as_ref().map(|p| p.application_polys()[i]),
                            )?,
                        })
                    })
                    .collect::<Result<_>>()?
            },
            claims: {
                D::try_just(|| {
                    if proof.as_ref().take().application_claims().len() != num_queries {
                        return Err(Error::MalformedEncoding(
                            "proof does not carry exactly the configured number of claim instances"
                                .into(),
                        ));
                    }
                    Ok(())
                })?;
                (0..num_queries)
                    .map(|i| {
                        Ok(ClaimInstance {
                            poly_slot: Element::alloc(
                                dr,
                                allocator,
                                proof.as_ref().map(|p| p.application_claims()[i].poly_slot),
                            )?,
                            x: Element::alloc(
                                dr,
                                allocator,
                                proof.as_ref().map(|p| p.application_claims()[i].x),
                            )?,
                            y: Element::alloc(
                                dr,
                                allocator,
                                proof.as_ref().map(|p| p.application_claims()[i].y),
                            )?,
                        })
                    })
                    .collect::<Result<_>>()?
            },
            challenges: {
                D::try_just(|| {
                    if proof.as_ref().take().application_challenges().len() != num_challenges {
                        return Err(Error::MalformedEncoding(
                            "proof does not carry exactly the configured number of challenge \
                             pairs"
                                .into(),
                        ));
                    }
                    Ok(())
                })?;
                (0..num_challenges)
                    .map(|i| {
                        Ok(ChallengeInstance {
                            point: Point::alloc(
                                dr,
                                proof.as_ref().map(|p| p.application_challenges()[i].point),
                            )?,
                            challenge: Element::alloc(
                                dr,
                                allocator,
                                proof
                                    .as_ref()
                                    .map(|p| p.application_challenges()[i].challenge),
                            )?,
                        })
                    })
                    .collect::<Result<_>>()?
            },
            circuit_id: Element::alloc(
                dr,
                allocator,
                proof.as_ref().map(|p| p.circuit_id().omega_j()),
            )?,
            unified: unified::Output::alloc_from_proof(dr, allocator, proof)?,
        })
    }

    /// Allocate ProofInputs from a proof reference and some unprocessed header
    /// data. Slot counts as in [`alloc`](Self::alloc).
    pub fn alloc_for_verify<R: Rank, H: Header<C::CircuitField>>(
        dr: &mut D,
        proof: DriverValue<D, &Proof<C, R>>,
        header_data: DriverValue<D, H::Data>,
        num_polys: usize,
        num_queries: usize,
        num_challenges: usize,
    ) -> Result<Self> {
        let header_data = D::try_just(|| {
            use ragu_core::drivers::emulator::{Emulator, Wireless};
            let emulator = &mut Emulator::<Wireless<D::MaybeKind, D::F>>::wireless();

            let output = H::encode(emulator, &mut (), header_data)?;
            let output = padded::for_header::<H, HEADER_SIZE, _>(emulator, output)?;

            let mut header_data = Vec::with_capacity(HEADER_SIZE);
            output.write(emulator, &mut header_data)?;

            header_data
                .into_iter()
                .map(|e| *e.value().take())
                .collect_fixed()
        })?;

        Self::alloc(
            dr,
            proof,
            header_data.as_ref(),
            num_polys,
            num_queries,
            num_challenges,
        )
    }
}

/// Prover-internal output of the native preamble stage.
///
/// This is stage communication data, not part of the circuit's public instance.
/// The verifier never sees these values directly.
#[derive(Gadget, Consistent)]
pub struct Output<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>, const HEADER_SIZE: usize> {
    #[ragu(gadget)]
    pub left: ProofInputs<'dr, D, C, HEADER_SIZE>,
    #[ragu(gadget)]
    pub right: ProofInputs<'dr, D, C, HEADER_SIZE>,
}

impl<'dr, D: Driver<'dr>, C: Cycle<CircuitField = D::F>, const HEADER_SIZE: usize>
    Output<'dr, D, C, HEADER_SIZE>
{
    /// Returns true if both child proofs are trivial proofs.
    pub fn is_base_case(
        &self,
        dr: &mut D,
        allocator: &mut impl Allocator<'dr, D>,
    ) -> Result<Boolean<'dr, D>> {
        let left_is_trivial = self.left.is_trivial(dr, allocator)?;
        let right_is_trivial = self.right.is_trivial(dr, allocator)?;
        left_is_trivial.and(dr, &right_is_trivial)
    }
}

pub struct Stage<C: Cycle, R, const HEADER_SIZE: usize> {
    /// Number of polynomial slots each child carries.
    num_polys: usize,
    /// Number of poly-query claim slots each child carries.
    num_queries: usize,
    /// Number of challenge slots each child carries.
    num_challenges: usize,
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R, const HEADER_SIZE: usize> Default for Stage<C, R, HEADER_SIZE> {
    fn default() -> Self {
        Stage {
            num_polys: NUM_POLY_SLOTS,
            num_queries: NUM_QUERY_SLOTS,
            num_challenges: NUM_CHALLENGE_SLOTS,
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> staging::Stage<C::CircuitField, R>
    for Stage<C, R, HEADER_SIZE>
{
    type Parent = ();
    type Witness<'source> = &'source Witness<'source, C, R, HEADER_SIZE>;
    type OutputKind = Kind![C::CircuitField; Output<'_, _, C, HEADER_SIZE>];

    fn values() -> usize {
        // 2 proofs * (3 headers * HEADER_SIZE + polynomial slots (2 wires each)
        //             + query slots (3 wires each)
        //             + challenge slots (3 wires each)
        //             + 1 circuit_id + unified instance wires)
        2 * (3 * HEADER_SIZE
            + 2 * NUM_POLY_SLOTS
            + 3 * NUM_QUERY_SLOTS
            + 3 * NUM_CHALLENGE_SLOTS
            + 1
            + unified::NUM_WIRES)
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<Bound<'dr, D, Self::OutputKind>>
    where
        Self: 'dr,
    {
        let left = ProofInputs::alloc(
            dr,
            witness.as_ref().map(|w| w.left.proof),
            witness.as_ref().map(|w| &w.left.output_header),
            self.num_polys,
            self.num_queries,
            self.num_challenges,
        )?;

        let right = ProofInputs::alloc(
            dr,
            witness.as_ref().map(|w| w.right.proof),
            witness.as_ref().map(|w| &w.right.output_header),
            self.num_polys,
            self.num_queries,
            self.num_challenges,
        )?;

        Ok(Output { left, right })
    }
}

#[cfg(test)]
mod tests {
    use ragu_pasta::Pasta;

    use super::*;
    use crate::internal::tests::{HEADER_SIZE, R, assert_stage_values};

    #[test]
    fn stage_values_matches_wire_count() {
        assert_stage_values(&Stage::<Pasta, R, { HEADER_SIZE }>::default());
    }
}
