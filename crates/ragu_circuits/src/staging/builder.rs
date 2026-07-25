//! Multi-stage circuit witness computation with staged wire allocation.
//!
//! The staging system separates witness computation into explicit **stage
//! polynomials** ($a(X)$, $b(X)$, ...) that can be committed independently,
//! and an implicit **final trace** ($r'(X)$) that consumes their outputs.
//! Together these form the full trace polynomial:
//!
//! $$
//! r(X) = r'(X) + a(X) + b(X) + \cdots
//! $$
//!
//!
//! Staged polynomials enable the prover to commit to portions of the witness
//! before computing the full circuit.
//!
//! ## Two-Phase Builder Pattern
//!
//! The [`StageBuilder`] uses a two-phase protocol:
//!
//! 1. **Wire reservation** — Call [`configure_stage`](StageBuilder::configure_stage)
//!    (or [`add_stage`](StageBuilder::add_stage) for stages implementing
//!    [`Default`]) for each stage polynomial. This reserves non-overlapping
//!    wire positions without computing values yet, ensuring all provers agree
//!    on wire layout.
//!
//! 2. **Witness computation** — Call [`finish`](StageBuilder::finish) to get
//!    the driver, then populate each stage via [`StageGuard::enforced`] or
//!    [`StageGuard::unenforced`]. The remaining code computes $r'(X)$.
//!
//! After phase 1, the trace polynomial has a fixed structure:
//!
//! $$
//! r(X) = \underbrace{a(X)}\_{\text{wires 0--99}} + \underbrace{b(X)}\_{\text{wires 100--101}} + \underbrace{r'(X)}\_{\text{wires 102+}}
//! $$
//!
//! ## Example
//!
//! See the `compute_v` module in `ragu_pcd` crate for a real-world multi-stage
//! circuit, or the [staging chapter] in the book.
//!
//! See the parent module's [gadget invariants] section for what
//! [`Stage::witness`] does and doesn't guarantee about the wires inside the
//! gadget it returns, and how [`StageGuard::enforced`]/[`unenforced`] differ
//! in how they treat those wires.
//!
//! [staging chapter]: https://tachyon.z.cash/ragu/implementation/staging
//! [gadget invariants]: super#gadget-invariants
//! [`unenforced`]: StageGuard::unenforced

use alloc::vec::Vec;
use core::marker::PhantomData;

use ragu_arithmetic::Coeff;
use ragu_core::{
    Result,
    convert::WireMap,
    drivers::{
        Driver, DriverValue,
        emulator::{Emulator, Wireless},
    },
    gadgets::{Bound, Gadget},
    maybe::Empty,
};
use ragu_primitives::{
    allocator::{Allocator, Standard},
    consistent::Consistent,
};

use super::{Stage, StageExt};
use crate::polynomials::Rank;

/// Builder object for synthesizing a multi-stage circuit witness.
pub struct StageBuilder<
    'a,
    'dr,
    D: Driver<'dr>,
    R: Rank,
    Current: Stage<D::F, R>,
    Target: Stage<D::F, R>,
> {
    driver: &'a mut D,
    on_finish: fn(&mut D),
    _marker: PhantomData<(&'dr (), R, Current, Target)>,
}

impl<'a, 'dr, D: Driver<'dr>, R: Rank, Target: Stage<D::F, R>>
    StageBuilder<'a, 'dr, D, R, (), Target>
{
    /// Creates a new [`StageBuilder`] with the given [`Driver`].
    pub(crate) fn new(driver: &'a mut D, on_finish: fn(&mut D)) -> Self {
        StageBuilder {
            driver,
            on_finish,
            _marker: PhantomData,
        }
    }
}

/// Injects pre-allocated stage wires into a gadget, without enforcing constraints.
struct StageWireInjector<'a, 'dr, D: Driver<'dr>> {
    stage_wires: core::slice::Iter<'a, D::Wire>,
    _marker: PhantomData<&'dr ()>,
}

impl<'dr, D: Driver<'dr>> WireMap<D::F> for StageWireInjector<'_, 'dr, D> {
    type Src = Emulator<Wireless<D::MaybeKind, D::F>>;
    type Dst = D;

    fn convert_wire(&mut self, _: &()) -> Result<D::Wire> {
        self.stage_wires
            .next()
            .cloned()
            .ok_or_else(|| ragu_core::Error::InvalidWitness("not enough stage wires".into()))
    }
}

/// A guard type returned by [`add_stage`](StageBuilder::add_stage) that holds
/// pre-allocated stage wires.
///
/// The stage wires are allocated at the correct positions, but the actual
/// witness computation is deferred until one of the consuming methods is called:
///
/// - [`enforced`](Self::enforced) - run witness and enforce constraints
/// - [`unenforced`](Self::unenforced) - run witness without constraints
///
/// To skip a stage without producing a gadget, use [`StageBuilder::skip_stage`]
/// instead of [`add_stage`](StageBuilder::add_stage).
#[must_use = "StageGuard must be consumed via `enforced` or `unenforced`"]
pub struct StageGuard<'dr, D: Driver<'dr>, R: Rank, S: Stage<D::F, R>> {
    stage: S,
    stage_wires: Vec<D::Wire>,
    _marker: PhantomData<(&'dr (), R, S)>,
}

impl<'dr, D: Driver<'dr>, R: Rank, S: Stage<D::F, R> + 'dr> StageGuard<'dr, D, R, S> {
    /// Inject pre-allocated stage wires into the gadget produced by
    /// [`Stage::witness`], then provide the guarantee that the gadget is
    /// [`Consistent`] by calling
    /// [`enforce_consistent`](Consistent::enforce_consistent) on the real
    /// driver.
    ///
    /// See the parent module's [gadget invariants](super#gadget-invariants)
    /// section for what this guarantee does and does not cover.
    pub fn enforced<'source: 'dr>(
        self,
        dr: &mut D,
        witness: DriverValue<D, S::Witness<'source>>,
    ) -> Result<Bound<'dr, D, S::OutputKind>>
    where
        Bound<'dr, D, S::OutputKind>: Consistent<'dr, D>,
    {
        let output = self.unenforced_inner(witness)?;
        output.enforce_consistent(dr)?;
        Ok(output)
    }

    /// Internal helper that injects stage wires without enforcing constraints.
    fn unenforced_inner<'source: 'dr>(
        self,
        witness: DriverValue<D, S::Witness<'source>>,
    ) -> Result<Bound<'dr, D, S::OutputKind>> {
        let mut emulator: Emulator<Wireless<D::MaybeKind, D::F>> = Emulator::wireless();
        let computed_gadget = self.stage.witness(&mut emulator, witness)?;

        let mut injector = StageWireInjector::<D> {
            stage_wires: self.stage_wires.iter(),
            _marker: PhantomData,
        };

        computed_gadget.map(&mut injector)
    }

    /// Inject pre-allocated stage wires into the gadget produced by
    /// [`Stage::witness`] without any further guarantee about the wires.
    ///
    /// Takes the prover at their word, or relies on a different
    /// [`enforced`](Self::enforced) call to check the gadget's invariants.
    /// See the parent module's [gadget invariants](super#gadget-invariants)
    /// section.
    pub fn unenforced<'source: 'dr>(
        self,
        _dr: &mut D,
        witness: DriverValue<D, S::Witness<'source>>,
    ) -> Result<Bound<'dr, D, S::OutputKind>> {
        self.unenforced_inner(witness)
    }
}

/// A [`StageGuard`] for a stage whose position came from a value-level layout
/// rather than a `Parent` type chain.
///
/// Produced by [`StageBuilder::configure_induced`], which documents the
/// obligation the caller takes on. Consumed exactly like a [`StageGuard`].
#[must_use = "InducedGuard must be consumed via `enforced` or `unenforced`"]
pub struct InducedGuard<'dr, D: Driver<'dr>, R: Rank, S: Stage<D::F, R>> {
    stage: S,
    stage_wires: Vec<D::Wire>,
    _marker: PhantomData<(&'dr (), R, S)>,
}

impl<'dr, D: Driver<'dr>, R: Rank, S: Stage<D::F, R> + 'dr> InducedGuard<'dr, D, R, S> {
    /// As [`StageGuard::enforced`].
    pub fn enforced<'source: 'dr>(
        self,
        dr: &mut D,
        witness: DriverValue<D, S::Witness<'source>>,
    ) -> Result<Bound<'dr, D, S::OutputKind>>
    where
        Bound<'dr, D, S::OutputKind>: Consistent<'dr, D>,
    {
        let output = self.into_guard().unenforced_inner(witness)?;
        output.enforce_consistent(dr)?;
        Ok(output)
    }

    /// As [`StageGuard::unenforced`].
    pub fn unenforced<'source: 'dr>(
        self,
        _dr: &mut D,
        witness: DriverValue<D, S::Witness<'source>>,
    ) -> Result<Bound<'dr, D, S::OutputKind>> {
        self.into_guard().unenforced_inner(witness)
    }

    /// Wire injection is identical once the wires are reserved; only where the
    /// geometry came from differs.
    fn into_guard(self) -> StageGuard<'dr, D, R, S> {
        StageGuard {
            stage: self.stage,
            stage_wires: self.stage_wires,
            _marker: PhantomData,
        }
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
    pub fn configure_stage<Next: Stage<D::F, R, Parent = Current> + 'dr>(
        self,
        stage: Next,
    ) -> Result<(
        StageGuard<'dr, D, R, Next>,
        StageBuilder<'a, 'dr, D, R, Next, Target>,
    )> {
        // Invoke wireless emulator with dummy witness to get gadget structure.
        // The emulator never actually reads the witness values.
        let mut emulator = Emulator::counter();
        let mut num_wires = stage.witness(&mut emulator, Empty)?.num_wires()?;

        // Check bounds
        if num_wires > Next::values() {
            return Err(ragu_core::Error::GateBoundExceeded {
                limit: Next::num_gates(),
            });
        }

        // Collect stage wires
        let allocator = &mut Standard::new();
        let mut wires = Vec::with_capacity(num_wires);
        for _ in 0..num_wires {
            wires.push(allocator.alloc(self.driver, || Ok(Coeff::Zero))?);
        }

        // Padding
        while (num_wires / 2) < Next::num_gates() {
            allocator.alloc(self.driver, || Ok(Coeff::Zero))?;
            num_wires += 1;
        }

        Ok((
            StageGuard {
                stage,
                stage_wires: wires,
                _marker: PhantomData,
            },
            StageBuilder {
                driver: self.driver,
                on_finish: self.on_finish,
                _marker: PhantomData,
            },
        ))
    }

    /// Reserves one stage's wires from a **value-level** layout rather than
    /// from a `Parent` type chain.
    ///
    /// [`configure_stage`](Self::configure_stage) reads its geometry from
    /// `Next::values()` and `Next::num_gates()`, which the `Parent = Current`
    /// bound places in the chain. When a circuit's stage *count* is a property
    /// of the application being built rather than of any Rust type, that chain
    /// cannot be written down, and the geometry comes from
    /// [`InducedStages`](super::InducedStages) instead — the same numbers,
    /// folded over recorded widths.
    ///
    /// `stage` supplies only the witness body, so one concrete type serves
    /// every slot of a family: `values` and `num_gates` are taken from the
    /// layout, not from the type, and the type's own chain position is
    /// ignored.
    ///
    /// # The invariant this moves
    ///
    /// The typed path guarantees by construction that a stage occupies the
    /// positions its mask covers. Here that guarantee becomes the caller's:
    /// **the `values` and `num_gates` passed here must come from the same
    /// [`InducedStages`](super::InducedStages) that produced the stage's
    /// [`mask`](super::InducedStages::mask), and no typed stage may follow an
    /// induced run** — a later `Parent` chain would compute `skip_gates` from
    /// types and miss the induced wires entirely. Stage positions determine
    /// where committed values live, so this is a soundness-relevant
    /// obligation, not a style rule.
    ///
    /// `Current` deliberately does not advance: an induced run has no
    /// type-level position to advance to.
    pub fn configure_induced<S: Stage<D::F, R> + 'dr>(
        &mut self,
        stage: S,
        values: usize,
        num_gates: usize,
    ) -> Result<InducedGuard<'dr, D, R, S>> {
        let mut emulator = Emulator::counter();
        let mut num_wires = stage.witness(&mut emulator, Empty)?.num_wires()?;

        if num_wires > values {
            return Err(ragu_core::Error::GateBoundExceeded { limit: num_gates });
        }

        let allocator = &mut Standard::new();
        let mut wires = Vec::with_capacity(num_wires);
        for _ in 0..num_wires {
            wires.push(allocator.alloc(self.driver, || Ok(Coeff::Zero))?);
        }

        while (num_wires / 2) < num_gates {
            allocator.alloc(self.driver, || Ok(Coeff::Zero))?;
            num_wires += 1;
        }

        Ok(InducedGuard {
            stage,
            stage_wires: wires,
            _marker: PhantomData,
        })
    }

    /// Adds the next stage to the builder using [`Self::configure_stage`],
    /// assuming the stage implements [`Default`].
    pub fn add_stage<Next>(
        self,
    ) -> Result<(
        StageGuard<'dr, D, R, Next>,
        StageBuilder<'a, 'dr, D, R, Next, Target>,
    )>
    where
        Next: Stage<D::F, R, Parent = Current> + Default + 'dr,
    {
        self.configure_stage(Next::default())
    }

    /// Skips the next stage without producing a gadget.
    ///
    /// This allocates the stage wire positions but does not return a guard,
    /// so it's used when you need to reserve the wire positions for a stage
    /// but don't need to compute its witness or produce its output gadget.
    pub fn skip_stage<Next: Stage<D::F, R, Parent = Current> + Default + 'dr>(
        self,
    ) -> Result<StageBuilder<'a, 'dr, D, R, Next, Target>> {
        let (_, builder) = self.add_stage::<Next>()?;
        Ok(builder)
    }
}

impl<'a, 'dr, D: Driver<'dr>, R: Rank, Finished: Stage<D::F, R>>
    StageBuilder<'a, 'dr, D, R, Finished, Finished>
{
    /// Obtains the underlying driver after finishing the last stage.
    ///
    /// If the builder was constructed with an `on_finish` hook, the hook
    /// is called on the driver before it is returned.
    pub fn finish(self) -> &'a mut D {
        (self.on_finish)(self.driver);
        self.driver
    }
}
