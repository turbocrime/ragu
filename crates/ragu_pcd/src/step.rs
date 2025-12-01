//! Merging operations defined for the proof-carrying data computational graph.

use arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
};

use super::header::Header;
pub use encoder::{Encoded, Encoder};

pub(crate) mod adapter;
mod encoder;
pub(crate) mod padded;
pub(crate) mod rerandomize;

/// Internal representation of a [`Step`] index distinguishing internal vs.
/// application steps.
enum StepIndex {
    Internal(usize),
    Application(usize),
}

/// The number of internal steps used by Ragu for things like rerandomization or
/// proof decompression.
///
/// * `0` is used for the rerandomization step (see [`rerandomize`]).
pub(crate) const NUM_INTERNAL_STEPS: usize = 1;

/// The index of a [`Step`] in an application.
///
/// All steps added to an application have a unique index and must be inserted
/// sequentially so that their location (and other metadata) can be identified
/// during proof generation and at other times.
pub struct Index {
    index: StepIndex,
}

impl Index {
    /// Creates a new application-defined [`Step`] index.
    pub const fn new(value: usize) -> Self {
        Index {
            index: StepIndex::Application(value),
        }
    }

    /// Returns the circuit index for this step.
    ///
    /// Pass `None` when the number of application steps is not yet known, or
    /// `Some(n)` to validate and compute the final index. Returns an error if
    /// an application step index exceeds `n`.
    ///
    /// ## Panics
    ///
    /// Panics if called on an internal step with `None`, since internal steps
    /// are indexed after application steps.
    pub(crate) fn circuit_index(&self, num_application_steps: Option<usize>) -> Result<usize> {
        match self.index {
            StepIndex::Internal(i) => Ok(num_application_steps.unwrap() + i),
            StepIndex::Application(i) => {
                if let Some(num_application_steps) = num_application_steps {
                    if i >= num_application_steps {
                        return Err(ragu_core::Error::Initialization(
                            "attempted to use application Step index that exceeds Application registered steps".into(),
                        ));
                    }
                }

                Ok(i)
            }
        }
    }

    /// Creates a new internal-defined [`Step`] index. Only called internally by
    /// Ragu.
    pub(crate) const fn internal(value: usize) -> Self {
        if value >= NUM_INTERNAL_STEPS {
            panic!("invalid internal step index");
        }

        Index {
            index: StepIndex::Internal(value),
        }
    }
}

#[test]
fn test_index_map() -> Result<()> {
    let num_application_steps = Some(10);

    assert_eq!(Index::internal(0).circuit_index(num_application_steps)?, 10);
    assert_eq!(Index::new(0).circuit_index(num_application_steps)?, 0);
    assert_eq!(Index::new(1).circuit_index(num_application_steps)?, 1);
    assert_eq!(Index::new(999).circuit_index(None)?, 999);
    assert!(Index::new(10).circuit_index(num_application_steps).is_err());

    Ok(())
}

/// Represents a node in the computational graph (or the proof-carrying data
/// tree) that represents the merging of two pieces of proof-carrying data.
pub trait Step<C: Cycle>: Sized + Send + Sync {
    /// Each unique [`Step`] implementation within a provided context must have
    /// a unique index.
    const INDEX: Index;

    /// The witness data needed to construct a proof for this step.
    type Witness<'source>: Send;

    /// Auxillary information produced during circuit synthesis. This may be
    /// necessary to construct the [`Header::Data`] for the resulting proof.
    type Aux<'source>: Send;

    /// The "left" header expected during this step.
    type Left: Header<C::CircuitField>;

    /// The "right" header expected during this step.
    type Right: Header<C::CircuitField>;

    /// The header produced during this step.
    type Output: Header<C::CircuitField>;

    /// The main synthesis method that checks the validity of this merging step.
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: Encoder<'dr, 'source, D, Self::Left, HEADER_SIZE>,
        right: Encoder<'dr, 'source, D, Self::Right, HEADER_SIZE>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr;
}
