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
    Boolean, Element, GadgetExt,
    allocator::Allocator,
    consistent::Consistent,
    vec::{CollectFixed, ConstLen, FixedVec},
};

use crate::{
    Proof, header::Header, hook_layout::AppHooksLayout, internal::native::unified,
    step::internal::padded,
};

type HeaderVec<'dr, D, const HEADER_SIZE: usize> = FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>>;

/// One child's polynomial slots, in slot order — the [`HeaderVec`] of the
/// poly-slot region.
pub type PolyVec<'dr, D, J> = FixedVec<PolyInstance<'dr, D>, <J as AppHooksLayout>::PolyCount>;

/// One child's poly-query claim slots, in slot order.
pub type ClaimVec<'dr, D, J> = FixedVec<ClaimInstance<'dr, D>, <J as AppHooksLayout>::ClaimCount>;

/// One child's challenge slots, in slot order.
pub type ChallengeVec<'dr, D, J> =
    FixedVec<ChallengeInstance<'dr, D, J>, <J as AppHooksLayout>::ChallengeCount>;

/// A single poly-query claim instance witnessed from a child proof: the opened
/// polynomial's embedded commitment coordinates and the $(x, y)$ opening. The
/// wire layout (coords, x, y) matches the claim-slot region of the application
/// circuit's instance, so writing these into the
/// [`application_ky`](ProofInputs::application_ky) Horner binds them to the
/// child's committed application rx.
///
/// `coords` are the same values one of [`ProofInputs::polys`] holds — in the
/// child's own circuit literally the same wires, since the pair is allocated
/// once and written at both instance positions. The parent does not have to
/// enforce that: a trace satisfying the child's registered wiring cannot have
/// them differ, and the revdot identity is what carries it here.
#[derive(Gadget, Consistent)]
pub struct ClaimInstance<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    pub coords: FixedVec<Element<'dr, D>, ConstLen<2>>,
    #[ragu(gadget)]
    pub x: Element<'dr, D>,
    #[ragu(gadget)]
    pub y: Element<'dr, D>,
}

/// A single witnessed polynomial as the application circuit's instance exposes
/// it: its host commitment's affine coordinates, canonically embedded in the
/// circuit field. The wire layout matches the polynomial-slot region of that
/// instance.
///
/// One per polynomial, not one per query — see
/// [`instance_len`](crate::step::internal::adapter::instance_len).
#[derive(Gadget, Consistent)]
pub struct PolyInstance<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    pub coords: FixedVec<Element<'dr, D>, ConstLen<2>>,
}

/// A single derived challenge witnessed from a child proof: the field
/// elements it was hashed from, and the challenge itself. The wire layout
/// (every input element, then the challenge) matches the challenge-slot
/// region of the application circuit's instance.
#[derive(Gadget, Consistent)]
pub struct ChallengeInstance<'dr, D: Driver<'dr>, J: AppHooksLayout> {
    #[ragu(gadget)]
    pub inputs: FixedVec<Element<'dr, D>, J::ChallengeWidth>,
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
pub struct ProofInputs<
    'dr,
    D: Driver<'dr>,
    C: Cycle<CircuitField = D::F>,
    const HEADER_SIZE: usize,
    J: AppHooksLayout,
> {
    /// Headers this child proof claimed for its own children.
    #[ragu(gadget)]
    pub children: ChildHeaders<'dr, D, HEADER_SIZE>,
    /// Output header of this child proof.
    #[ragu(gadget)]
    pub output_header: HeaderVec<'dr, D, HEADER_SIZE>,
    /// The poly-query claim instances this child proof raised, in slot order.
    /// Unused slots hold the canonical padding claim.
    #[ragu(gadget)]
    pub claims: ClaimVec<'dr, D, J>,
    /// The polynomials this child proof witnessed, in slot order. Unused slots
    /// hold the canonical padding polynomial. Each claim above carries the
    /// embedded commitment coordinates of one of these.
    #[ragu(gadget)]
    pub polys: PolyVec<'dr, D, J>,
    #[ragu(gadget)]
    pub circuit_id: Element<'dr, D>,
    #[ragu(gadget)]
    pub unified: unified::Output<'dr, D, C>,
}

impl<
    'dr,
    D: Driver<'dr, F = C::CircuitField>,
    C: Cycle,
    const HEADER_SIZE: usize,
    J: AppHooksLayout,
> ProofInputs<'dr, D, C, HEADER_SIZE, J>
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
    /// output_header, polys, claims, challenges)` — the polynomial slots follow
    /// the headers, the query slots follow those, and the challenge slots
    /// follow those, matching the instance layout the adapter writes
    /// (`step::internal::adapter::instance_len`). This is what binds the
    /// witnessed polynomials, claim instances and derived challenges to the
    /// child's committed application rx.
    ///
    /// `challenges` comes in as an argument because the challenge slots are
    /// their own stage
    /// ([`ChallengesStage`](super::slots::ChallengesStage)) rather than a field
    /// here. The fold still walks one contiguous instance; only which stage
    /// each region's wires live in differs, and that is deliberate — see that
    /// module for why the slot regions do not belong on the chain's root.
    pub fn application_ky(
        &self,
        dr: &mut D,
        y: &Element<'dr, D>,
        challenges: &ChallengeVec<'dr, D, J>,
    ) -> Result<Element<'dr, D>> {
        let mut ky = Horner::new(y);
        self.children.left.write(dr, &mut ky)?;
        self.children.right.write(dr, &mut ky)?;
        self.output_header.write(dr, &mut ky)?;
        for poly in self.polys.iter() {
            poly.coords.write(dr, &mut ky)?;
        }
        for claim in self.claims.iter() {
            claim.coords.write(dr, &mut ky)?;
            claim.x.write(dr, &mut ky)?;
            claim.y.write(dr, &mut ky)?;
        }
        for pair in challenges.iter() {
            for input in pair.inputs.iter() {
                input.write(dr, &mut ky)?;
            }
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

impl<
    'dr,
    D: Driver<'dr, F = C::CircuitField>,
    C: Cycle,
    const HEADER_SIZE: usize,
    J: AppHooksLayout,
> ProofInputs<'dr, D, C, HEADER_SIZE, J>
{
    /// Allocate ProofInputs from a proof reference and pre-computed output
    /// header. The slot counts are circuit-construction parameters: they fix
    /// the wire shape regardless of whether a witness is present, and the
    /// proof's own slot lists are checked against them.
    pub fn alloc<R: Rank>(
        dr: &mut D,
        proof: DriverValue<D, &Proof<C, R>>,
        output_header: DriverValue<D, &FixedVec<D::F, ConstLen<HEADER_SIZE>>>,
    ) -> Result<Self> {
        let num_polys = J::polys();
        let num_queries = J::claims();
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
                    if proof.as_ref().take().application_poly_coords().len() != num_polys * 2 {
                        return Err(Error::MalformedEncoding(
                            "proof does not carry exactly two coordinate values per polynomial \
                             slot"
                                .into(),
                        ));
                    }
                    Ok(())
                })?;
                (0..num_polys)
                    .map(|i| {
                        Ok(PolyInstance {
                            coords: (0..2)
                                .map(|k| {
                                    Element::alloc(
                                        dr,
                                        allocator,
                                        proof
                                            .as_ref()
                                            .map(|p| p.application_poly_coords()[2 * i + k]),
                                    )
                                })
                                .try_collect_fixed()?,
                        })
                    })
                    .try_collect_fixed()?
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
                            coords: (0..2)
                                .map(|k| {
                                    Element::alloc(
                                        dr,
                                        allocator,
                                        proof.as_ref().map(|p| p.application_claims()[i].coords[k]),
                                    )
                                })
                                .try_collect_fixed()?,
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
                    .try_collect_fixed()?
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
    /// data. Shape as in [`alloc`](Self::alloc).
    pub fn alloc_for_verify<R: Rank, H: Header<C::CircuitField>>(
        dr: &mut D,
        proof: DriverValue<D, &Proof<C, R>>,
        header_data: DriverValue<D, H::Data>,
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

        Self::alloc(dr, proof, header_data.as_ref())
    }
}

/// Prover-internal output of the native preamble stage.
///
/// This is stage communication data, not part of the circuit's public instance.
/// The verifier never sees these values directly.
#[derive(Gadget, Consistent)]
pub struct Output<
    'dr,
    D: Driver<'dr>,
    C: Cycle<CircuitField = D::F>,
    const HEADER_SIZE: usize,
    J: AppHooksLayout,
> {
    #[ragu(gadget)]
    pub left: ProofInputs<'dr, D, C, HEADER_SIZE, J>,
    #[ragu(gadget)]
    pub right: ProofInputs<'dr, D, C, HEADER_SIZE, J>,
}

impl<
    'dr,
    D: Driver<'dr>,
    C: Cycle<CircuitField = D::F>,
    const HEADER_SIZE: usize,
    J: AppHooksLayout,
> Output<'dr, D, C, HEADER_SIZE, J>
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

/// Both children present the application's shape, so one set of slot counts
/// sizes both.
pub struct Stage<C: Cycle, R, const HEADER_SIZE: usize, J: AppHooksLayout> {
    _marker: PhantomData<(C, R, J)>,
}

impl<C: Cycle, R, const HEADER_SIZE: usize, J: AppHooksLayout> Default
    for Stage<C, R, HEADER_SIZE, J>
{
    fn default() -> Self {
        Stage {
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize, J: AppHooksLayout>
    staging::Stage<C::CircuitField, R> for Stage<C, R, HEADER_SIZE, J>
{
    type Parent = ();
    type Witness<'source> = &'source Witness<'source, C, R, HEADER_SIZE>;
    type OutputKind = Kind![
        C::CircuitField;
        Output<'_, _, C, HEADER_SIZE, J>
    ];

    fn values() -> usize {
        // Four wires per claim: the opened polynomial's name, then the
        // $(x, y)$ opening. Two per polynomial slot for its name — the host
        // commitment's embedded affine coordinates. The challenge slots are
        // their own stage — see [`slots`](super::slots) for why the chain's
        // root does not hold them.
        2 * (3 * HEADER_SIZE + 2 * J::polys() + 4 * J::claims() + 1 + unified::NUM_WIRES)
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
        )?;

        let right = ProofInputs::alloc(
            dr,
            witness.as_ref().map(|w| w.right.proof),
            witness.as_ref().map(|w| &w.right.output_header),
        )?;

        Ok(Output { left, right })
    }
}

#[cfg(test)]
mod tests {
    use ragu_pasta::Pasta;

    use super::*;
    use crate::{
        hook_layout::AppHooks,
        internal::tests::{HEADER_SIZE, R, assert_stage_values},
    };

    /// `values()` predicts the wire count at every slot count, not just one.
    /// This is what lets the stage's position in the chain come off its type.
    #[test]
    fn stage_values_matches_wire_count() {
        fn check<const POLYS: usize>() {
            assert_stage_values(
                &Stage::<Pasta, R, { HEADER_SIZE }, AppHooks<POLYS, 1, 0, 0>>::default(),
            );
        }
        check::<0>();
        check::<1>();
        check::<4>();
        check::<8>();
    }
}
