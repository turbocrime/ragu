use alloc::vec::Vec;
use arithmetic::Cycle;
use ragu_circuits::{polynomials::Rank, staging};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
    maybe::Maybe,
};
use ragu_primitives::{
    Element,
    vec::{ConstLen, FixedVec},
};

use core::marker::PhantomData;

pub const STAGING_ID: usize = crate::internal_circuits::NATIVE_PREAMBLE_STAGING_ID;

type Header<'dr, D, const HEADER_SIZE: usize> = FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>>;

/// Headers from a single proof's k(Y) polynomial.
pub struct ProofHeaders<F, const HEADER_SIZE: usize> {
    pub right_header: [F; HEADER_SIZE],
    pub left_header: [F; HEADER_SIZE],
    pub output_header: [F; HEADER_SIZE],
}

/// Witness for the native preamble stage.
pub struct Witness<F, const HEADER_SIZE: usize> {
    pub left: ProofHeaders<F, HEADER_SIZE>,
    pub right: ProofHeaders<F, HEADER_SIZE>,

    pub left_circuit_id: F,
    pub right_circuit_id: F,

    pub left_w: F,
    pub left_c: F,
    pub left_mu: F,
    pub left_nu: F,
    pub right_w: F,
    pub right_c: F,
    pub right_mu: F,
    pub right_nu: F,
}

/// Unified instance data from a single proof: ((w, c), (mu, nu))
type ProofUnified<'dr, D> = (
    (Element<'dr, D>, Element<'dr, D>),
    (Element<'dr, D>, Element<'dr, D>),
);

/// Output of the native preamble stage.
#[allow(type_alias_bounds)]
pub type Output<'dr, D: Driver<'dr>, const HEADER_SIZE: usize> = (
    // Headers: ((left_right, (left_left, left_output)), (right_right, (right_left, right_output)))
    (
        (
            Header<'dr, D, HEADER_SIZE>,
            (Header<'dr, D, HEADER_SIZE>, Header<'dr, D, HEADER_SIZE>),
        ),
        (
            Header<'dr, D, HEADER_SIZE>,
            (Header<'dr, D, HEADER_SIZE>, Header<'dr, D, HEADER_SIZE>),
        ),
    ),
    // Circuit IDs and unified instance data: ((left_id, right_id), (left_unified, right_unified))
    (
        (Element<'dr, D>, Element<'dr, D>),
        (ProofUnified<'dr, D>, ProofUnified<'dr, D>),
    ),
);

pub struct Stage<C: Cycle, R, const HEADER_SIZE: usize> {
    _marker: PhantomData<(C, R)>,
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> staging::Stage<C::CircuitField, R>
    for Stage<C, R, HEADER_SIZE>
{
    type Parent = ();
    type Witness<'source> = &'source Witness<C::CircuitField, HEADER_SIZE>;
    type OutputKind = Kind![C::CircuitField; Output<'_, _, HEADER_SIZE>];

    fn values() -> usize {
        2 * 3 * HEADER_SIZE + 10
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<<Self::OutputKind as GadgetKind<C::CircuitField>>::Rebind<'dr, D>>
    where
        Self: 'dr,
    {
        fn alloc_header<'dr, D: Driver<'dr>, const HEADER_SIZE: usize>(
            dr: &mut D,
            data: DriverValue<D, &[D::F; HEADER_SIZE]>,
        ) -> Result<FixedVec<Element<'dr, D>, ConstLen<HEADER_SIZE>>> {
            let mut v = Vec::with_capacity(HEADER_SIZE);
            for i in 0..HEADER_SIZE {
                v.push(Element::alloc(dr, data.view().map(|d| d[i]))?);
            }
            Ok(FixedVec::new(v).expect("length"))
        }

        // Allocation following adapter's reversed k(Y): right, left, output
        let left_right = alloc_header(dr, witness.view().map(|w| &w.left.right_header))?;
        let left_left = alloc_header(dr, witness.view().map(|w| &w.left.left_header))?;
        let left_output = alloc_header(dr, witness.view().map(|w| &w.left.output_header))?;

        let right_right = alloc_header(dr, witness.view().map(|w| &w.right.right_header))?;
        let right_left = alloc_header(dr, witness.view().map(|w| &w.right.left_header))?;
        let right_output = alloc_header(dr, witness.view().map(|w| &w.right.output_header))?;

        // Circuit IDs
        let left_circuit_id = Element::alloc(dr, witness.view().map(|w| w.left_circuit_id))?;
        let right_circuit_id = Element::alloc(dr, witness.view().map(|w| w.right_circuit_id))?;

        // Unified instance data from left proof
        let left_w = Element::alloc(dr, witness.view().map(|w| w.left_w))?;
        let left_c = Element::alloc(dr, witness.view().map(|w| w.left_c))?;
        let left_mu = Element::alloc(dr, witness.view().map(|w| w.left_mu))?;
        let left_nu = Element::alloc(dr, witness.view().map(|w| w.left_nu))?;

        // Unified instance data from right proof
        let right_w = Element::alloc(dr, witness.view().map(|w| w.right_w))?;
        let right_c = Element::alloc(dr, witness.view().map(|w| w.right_c))?;
        let right_mu = Element::alloc(dr, witness.view().map(|w| w.right_mu))?;
        let right_nu = Element::alloc(dr, witness.view().map(|w| w.right_nu))?;

        Ok((
            // Headers
            (
                (left_right, (left_left, left_output)),
                (right_right, (right_left, right_output)),
            ),
            // Circuit IDs and unified instance data
            (
                (left_circuit_id, right_circuit_id),
                (
                    ((left_w, left_c), (left_mu, left_nu)),
                    ((right_w, right_c), (right_mu, right_nu)),
                ),
            ),
        ))
    }
}
