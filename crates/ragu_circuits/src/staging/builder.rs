use arithmetic::Coeff;
use ff::Field;
use ragu_core::{
    Result,
    drivers::{
        Driver, DriverValue, FromDriver, LinearExpression,
        emulator::{Emulator, Wireless},
    },
    gadgets::{Gadget, GadgetKind},
    maybe::{Always, Maybe, MaybeKind},
};

use core::marker::PhantomData;

use super::{Stage, StageExt};
use crate::polynomials::Rank;
use alloc::vec::Vec;

/// Builder object for synthesizing a staged circuit witness.
pub struct StageBuilder<
    'a,
    'dr,
    D: Driver<'dr>,
    R: Rank,
    Current: Stage<D::F, R>,
    Target: Stage<D::F, R>,
> {
    driver: &'a mut D,
    _marker: PhantomData<(&'dr (), R, Current, Target)>,
}

impl<'a, 'dr, D: Driver<'dr>, R: Rank, Target: Stage<D::F, R>>
    StageBuilder<'a, 'dr, D, R, (), Target>
{
    /// Creates a new `StageBuilder` given an underlying `driver`.
    pub fn new(driver: &'a mut D) -> Self {
        StageBuilder {
            driver,
            _marker: PhantomData,
        }
    }
}

/// Allocates stage wires on the underlying driver and collects
/// them for later use by `StageGuard`.
struct StageWireAllocator<'a, 'dr, D: Driver<'dr>, F: ff::Field> {
    underlying: &'a mut D,
    stage_wires: Vec<D::Wire>,
    _marker: PhantomData<F>,
}

impl<'dr, D: Driver<'dr>, F: ff::Field> FromDriver<'_, 'dr, Emulator<Wireless<Always<()>, F>>>
    for StageWireAllocator<'_, 'dr, D, F>
where
    D: Driver<'dr, F = F>,
{
    type NewDriver = D;

    /// For every stage wire conversion, allocate a zero on the underlying driver.
    fn convert_wire(&mut self, _: &()) -> Result<D::Wire> {
        let stage_wire = self.underlying.alloc(|| Ok(Coeff::Zero))?;
        self.stage_wires.push(stage_wire.clone());
        Ok(stage_wire)
    }
}

/// `FromDriver` that enforces equality between live wires and stage wires.
struct EnforcingInjector<'a, 'dr, D: Driver<'dr>> {
    driver: &'a mut D,
    stage_wires: core::slice::Iter<'a, D::Wire>,
    _marker: PhantomData<&'dr ()>,
}

impl<'dr, D: Driver<'dr>> FromDriver<'dr, 'dr, D> for EnforcingInjector<'_, 'dr, D> {
    type NewDriver = D;

    fn convert_wire(&mut self, live_wire: &D::Wire) -> Result<D::Wire> {
        let stage_wire = self
            .stage_wires
            .next()
            .ok_or_else(|| ragu_core::Error::InvalidWitness("not enough stage wires".into()))?;

        // Constraint enforcement: live_wire - stage_wire = 0.
        self.driver
            .enforce_zero(|lc| lc.add(live_wire).sub(stage_wire))?;

        Ok(stage_wire.clone())
    }
}

/// `FromDriver` that injects pre-allocated stage wires into a gadget.
/// Used by `StageGuard::unenforced` to substitute stage wires without enforcement.
struct StageWireInjector<'a, 'dr, D: Driver<'dr>, M: MaybeKind, F: Field> {
    stage_wires: core::slice::Iter<'a, D::Wire>,
    _marker: PhantomData<(&'dr (), M, F)>,
}

impl<'dr, D: Driver<'dr, F = F>, M: MaybeKind, F: Field>
    FromDriver<'_, 'dr, Emulator<Wireless<M, F>>> for StageWireInjector<'_, 'dr, D, M, F>
{
    type NewDriver = D;

    fn convert_wire(&mut self, _: &()) -> Result<D::Wire> {
        self.stage_wires
            .next()
            .cloned()
            .ok_or_else(|| ragu_core::Error::InvalidWitness("not enough stage wires".into()))
    }
}

/// Guard type returned by `add_stage` that holds pre-allocated stage wires.
///
/// The stage wires are allocated at the correct positions, but the actual
/// witness computation is deferred until either [`unenforced`](Self::unenforced)
/// or [`enforced`](Self::enforced) is called.
///
/// Dropping this guard without calling either method effectively "skips" the
/// stage, where the wire positions are reserved but no gadget is returned.
pub struct StageGuard<'dr, D: Driver<'dr>, R: Rank, Next: Stage<D::F, R>> {
    stage_wires: Vec<D::Wire>,
    _marker: PhantomData<(&'dr (), R, Next)>,
}

impl<'dr, D: Driver<'dr>, R: Rank, Next: Stage<D::F, R>> StageGuard<'dr, D, R, Next> {
    /// Enforce constraints and inject stage wires.
    ///
    /// Runs the stage's witness method on the real driver (enforcing all
    /// internal constraints), then enforces equality between the computed
    /// wires and the pre-allocated stage wires.
    pub fn enforced<'a, 'source: 'dr>(
        self,
        driver: &'a mut D,
        witness: DriverValue<D, Next::Witness<'source>>,
    ) -> Result<<Next::OutputKind as GadgetKind<D::F>>::Rebind<'dr, D>>
    where
        Next: 'dr,
    {
        // Run witness on the real driver, enforcing all constraints.
        let computed_gadget = Next::witness(driver, witness)?;

        // Map the computed gadget, enforcing equality and substituting stage wires.
        let mut injector = EnforcingInjector {
            driver,
            stage_wires: self.stage_wires.iter(),
            _marker: PhantomData,
        };

        computed_gadget.map(&mut injector)
    }

    /// Inject stage wires without enforcing constraints.
    ///
    /// Runs the stage's witness method on a wireless emulator (not on the
    /// underlying driver), then substitutes the pre-allocated stage wires
    /// into the resulting gadget.
    pub fn unenforced<'source: 'dr>(
        self,
        witness: DriverValue<D, Next::Witness<'source>>,
    ) -> Result<<Next::OutputKind as GadgetKind<D::F>>::Rebind<'dr, D>>
    where
        Next: 'dr,
    {
        let mut emulator: Emulator<Wireless<D::MaybeKind, D::F>> = Emulator::wireless();
        let computed_gadget = Next::witness(&mut emulator, witness)?;

        // Inject stage wires into the gadget.
        let mut injector = StageWireInjector::<D, D::MaybeKind, D::F> {
            stage_wires: self.stage_wires.iter(),
            _marker: PhantomData,
        };

        computed_gadget.map(&mut injector)
    }
}

impl<'a, 'dr, D: Driver<'dr>, R: Rank, Current: Stage<D::F, R>, Target: Stage<D::F, R>>
    StageBuilder<'a, 'dr, D, R, Current, Target>
{
    /// Add the next stage to the builder, allocating stage wire positions.
    ///
    /// This method allocates the stage wires at the correct positions but does
    /// not compute the witness. Call [`StageGuard::unenforced`] or
    /// [`StageGuard::enforced`] on the returned guard to provide the witness
    /// and obtain the output gadget.
    pub fn add_stage<Next: Stage<D::F, R, Parent = Current> + 'dr>(
        self,
    ) -> Result<(
        StageGuard<'dr, D, R, Next>,
        StageBuilder<'a, 'dr, D, R, Next, Target>,
    )>
    where
        for<'s> Next::Witness<'s>: Default,
    {
        // Invoke wireless emulator with dummy witness to get gadget structure.
        // The emulator never actually reads the witness values.
        let mut emulator: Emulator<Wireless<Always<()>, D::F>> = Emulator::wireless();
        let dummy_witness =
            <Always<Next::Witness<'_>> as Maybe<Next::Witness<'_>>>::just(Default::default);
        let dummy_gadget = Next::witness(&mut emulator, dummy_witness)?;

        // Map the dummy gadget, allocating stage wires on the underlying driver.
        let mut allocator = StageWireAllocator {
            underlying: self.driver,
            stage_wires: Vec::new(),
            _marker: PhantomData,
        };

        let _mapped_gadget = dummy_gadget.map(&mut allocator)?;

        if allocator.stage_wires.len() > Next::values() {
            return Err(ragu_core::Error::MultiplicationBoundExceeded(
                Next::num_multiplications(),
            ));
        };

        while allocator.stage_wires.len() < Next::values() {
            let wire = allocator.underlying.alloc(|| Ok(Coeff::Zero))?;
            allocator.stage_wires.push(wire);
        }

        if allocator.stage_wires.len() % 2 == 1 {
            let wire = allocator.underlying.alloc(|| Ok(Coeff::Zero))?;
            allocator.stage_wires.push(wire);
        };

        assert_eq!(allocator.stage_wires.len() / 2, Next::num_multiplications());

        Ok((
            StageGuard {
                stage_wires: allocator.stage_wires,
                _marker: PhantomData,
            },
            StageBuilder {
                driver: allocator.underlying,
                _marker: PhantomData,
            },
        ))
    }
}

impl<'a, 'dr, D: Driver<'dr>, R: Rank, Finished: Stage<D::F, R>>
    StageBuilder<'a, 'dr, D, R, Finished, Finished>
{
    /// Obtain the underlying driver after finishing the last stage.
    pub fn finish(self) -> &'a mut D {
        self.driver
    }
}
