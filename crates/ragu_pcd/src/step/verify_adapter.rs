//! A dummy step used only for verification to compute k(Y) via the Adapter.

use arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
};

use core::marker::PhantomData;

use super::{Encoded, Encoder, Header, Index, Step};

/// A dummy step that is only used in verification to compute k(Y) via the
/// Adapter's instance method. This step is never registered; it exists solely
/// to provide the correct associated types for the Adapter.
pub(crate) struct VerifyAdapter<H> {
    _marker: PhantomData<H>,
}

impl<H> VerifyAdapter<H> {
    pub fn new() -> Self {
        VerifyAdapter {
            _marker: PhantomData,
        }
    }
}

impl<C: Cycle, H: Header<C::CircuitField>> Step<C> for VerifyAdapter<H> {
    // This step is never registered, so we use a sentinel index.
    const INDEX: Index = Index::new(usize::MAX);

    type Witness<'source> = ();
    type Aux<'source> = ();

    // The left and right headers don't matter for the instance method;
    // we use () as a placeholder.
    type Left = ();
    type Right = ();
    type Output = H;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        _dr: &mut D,
        _witness: DriverValue<D, Self::Witness<'source>>,
        _left: Encoder<'dr, 'source, D, Self::Left, HEADER_SIZE>,
        _right: Encoder<'dr, 'source, D, Self::Right, HEADER_SIZE>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        unreachable!("VerifyAdapter::witness should never be called")
    }
}
