//! Value-level stage layouts for stages that are not known at Rust compile
//! time.
//!
//! The typed staging surface ([`Stage`](super::Stage),
//! [`MultiStageCircuit`](super::MultiStageCircuit)) pins a circuit's stage
//! hierarchy in the type system: the `Parent` chain and the `values()` /
//! `num_gates()` / `skip_gates()` associated functions determine the partial
//! trace layout statically.
//!
//! Some layouts cannot be known that early. A circuit whose stage count is a
//! property of the *application* being built — not of any Rust type — has its
//! geometry settled at registry time instead. [`InducedStages`] mirrors a
//! [`Stage`](super::Stage) chain for exactly that case: same wire positions,
//! same masks, same rx, but folded over recorded widths rather than over a
//! `Parent` type chain.
//!
//! ## An induced run is still one typed stage
//!
//! A layout does not replace the typed hierarchy; it subdivides one stage of
//! it. The type system keeps describing the whole chain — the run appears in it
//! as a single [`Stage`](super::Stage) whose `values()` spans every slot — and
//! the layout says only where the slot boundaries fall *inside* that span.
//!
//! That works because gate spans add: a stage occupying `w` wires occupies
//! `w.div_ceil(2)` gates, so a run of slots whose widths are all even spans
//! exactly as many gates as the sum of its parts. Declaring the run as one
//! typed stage therefore leaves `skip_gates` correct for everything that
//! follows, and ordinary typed stages — including
//! [`MultiStageCircuit::Last`](super::MultiStageCircuit::Last) — chain after it
//! with no special handling. Nothing downstream of the run has to know the run
//! was subdivided.
//!
//! Layouts are anchored for exactly this reason: [`InducedStages::after`] takes
//! the run's position from the typed stage that spans it, so the layout
//! describes a suffix of the trace rather than restating the prefix. See
//! [`StageBuilder::configure_induced`](super::StageBuilder::configure_induced),
//! which reserves a run and checks the layout against the span it was given.
//!
//! * [`skip_gates`](InducedStages::skip_gates) / [`num_gates`](InducedStages::num_gates)
//!   mirror [`Stage::skip_gates`](super::Stage::skip_gates) and
//!   [`StageExt::num_gates`](super::StageExt::num_gates) — the fold over the
//!   `Parent` type chain becomes a fold over the recorded widths.
//! * [`mask`](InducedStages::mask) / [`final_mask`](InducedStages::final_mask)
//!   mirror [`StageExt::mask`](super::StageExt::mask) and
//!   [`StageExt::final_mask`](super::StageExt::final_mask).
//! * [`rx_configured`](InducedStages::rx_configured) mirrors
//!   [`StageExt::rx_configured`](super::StageExt::rx_configured), running a
//!   stage body for its values but positioning them from the layout;
//!   [`rx`](InducedStages::rx) is the same thing given the values directly.

use alloc::{boxed::Box, vec::Vec};

use ragu_arithmetic::ff::Field;
use ragu_core::Result;

use super::mask::StageMask;
use crate::{
    BondingObject,
    polynomials::{Rank, sparse},
};

/// A discovered, value-level stage layout: the wire width of each induced
/// stage, in stage order, plus the gate the run starts at.
///
/// See [`InducedStages`]'s module for how this mirrors the typed
/// [`Stage`](super::Stage) geometry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InducedStages {
    /// Gates before the first slot, including the SYSTEM gate — the run's
    /// anchor in the surrounding typed chain.
    skip_gates: usize,
    widths: Vec<usize>,
}

impl InducedStages {
    /// Creates a layout from the wire width of each stage, in stage order,
    /// anchored at the start of the trace.
    /// (does not count the final stage, which is left as implicit)
    pub fn new(widths: Vec<usize>) -> Self {
        // What `after::<_, _, ()>` would produce: the base stage skips the
        // SYSTEM gate and occupies nothing. Spelled out because `new` has no
        // field or rank to name `()`'s `Stage` impl with.
        Self {
            skip_gates: 1,
            widths,
        }
    }

    /// Creates a layout for a run that begins immediately after the typed
    /// stage `S` — the run's slots subdivide the span of the stage that
    /// *follows* `S`.
    ///
    /// This is the constructor to reach for whenever the run is not the first
    /// thing in the trace. Anchoring here rather than restating the prefix
    /// widths means the typed chain stays the single source of truth for
    /// everything before the run, so a change to an earlier stage cannot leave
    /// the layout silently describing the wrong gates.
    pub fn after<F: Field, R: Rank, S: super::Stage<F, R>>(widths: Vec<usize>) -> Self {
        use super::StageExt;

        Self {
            skip_gates: S::skip_gates() + S::num_gates(),
            widths,
        }
    }

    /// Creates a layout for a run of `count` slots, each `width` wires wide,
    /// beginning at gate `skip_gates`.
    ///
    /// The type-free counterpart of [`after`](Self::after), for callers that
    /// have the anchor as a number rather than as the stage that produced it.
    ///
    /// That happens where geometry has to travel as *data*. A layout owns a
    /// `Vec`, so it cannot ride along in a `Copy` context; a uniform run is
    /// fully described by these three numbers, so the anchor travels instead
    /// and the layout is rebuilt where it is needed. The alternative — naming
    /// the anchoring stage type — would force the count into the type of
    /// whatever is carrying it, which is exactly what value-level geometry
    /// exists to avoid.
    ///
    /// Prefer [`after`](Self::after) when the anchoring stage is nameable: it
    /// keeps the typed chain as the single source of truth for the anchor.
    pub fn uniform(skip_gates: usize, count: usize, width: usize) -> Self {
        Self {
            skip_gates,
            widths: alloc::vec![width; count],
        }
    }

    /// The gate this layout's run begins at — its anchor in the surrounding
    /// typed chain, as [`uniform`](Self::uniform) would take it.
    pub fn anchor(&self) -> usize {
        self.skip_gates
    }

    /// Returns the number of stages in this layout.
    pub fn len(&self) -> usize {
        self.widths.len()
    }

    /// Returns `true` if the layout contains no stages.
    pub fn is_empty(&self) -> bool {
        self.widths.is_empty()
    }

    /// Returns the wire width of the given stage.
    ///
    /// # Panics
    ///
    /// Panics if `stage >= self.len()`.
    pub fn width(&self, stage: usize) -> usize {
        self.widths[stage]
    }

    /// Returns the number of gates occupied by the given stage; the
    /// value-level mirror of [`StageExt::num_gates`](super::StageExt::num_gates).
    ///
    /// # Panics
    ///
    /// Panics if `stage >= self.len()`.
    pub fn num_gates(&self, stage: usize) -> usize {
        self.widths[stage].div_ceil(2)
    }

    /// Returns the number of gates to skip before the given stage, including
    /// the SYSTEM gate (gate 0); the value-level mirror of
    /// [`Stage::skip_gates`](super::Stage::skip_gates).
    ///
    /// # Panics
    ///
    /// Panics if `stage > self.len()` (equality is permitted: it yields the
    /// first gate after the last stage).
    pub fn skip_gates(&self, stage: usize) -> usize {
        self.skip_gates
            + self.widths[..stage]
                .iter()
                .map(|w| w.div_ceil(2))
                .sum::<usize>()
    }

    /// Returns `skip_gates` for the final trace — the first gate after every
    /// stage in the layout. Mirrors what
    /// [`StageExt::final_mask`](super::StageExt::final_mask) computes from the
    /// last typed stage.
    pub fn final_skip_gates(&self) -> usize {
        self.skip_gates(self.len())
    }

    /// Creates the well-formedness mask for the given stage; the value-level
    /// mirror of [`StageExt::mask`](super::StageExt::mask).
    ///
    /// # Panics
    ///
    /// Panics if `stage >= self.len()`.
    pub fn mask<'a, F: Field, R: Rank>(&self, stage: usize) -> Result<BondingObject<'a, F, R>> {
        Ok(BondingObject::new(Box::new(StageMask::<R>::new(
            self.skip_gates(stage),
            self.num_gates(stage),
        )?)))
    }

    /// Creates the well-formedness mask for the final trace of a circuit with
    /// this stage layout; the value-level mirror of
    /// [`StageExt::final_mask`](super::StageExt::final_mask).
    pub fn final_mask<'a, F: Field, R: Rank>(&self) -> Result<BondingObject<'a, F, R>> {
        Ok(BondingObject::new(Box::new(StageMask::<R>::new_final(
            self.final_skip_gates(),
        )?)))
    }

    /// Computes the (partial) $r(X)$ polynomial for the given stage from its
    /// slot values; the value-level mirror of
    /// [`StageExt::rx_configured`](super::StageExt::rx_configured).
    ///
    /// `values` are the stage's wire values in canonical traversal order and
    /// may be shorter than the stage's gate capacity (the remainder is
    /// zero-padded). See `rx_configured` for the role of `alpha`.
    ///
    /// # Panics
    ///
    /// Panics if `stage >= self.len()`.
    pub fn rx<F: Field, R: Rank>(
        &self,
        stage: usize,
        alpha: F,
        values: &[F],
    ) -> Result<sparse::Polynomial<F, R>> {
        super::build_stage_rx(
            alpha,
            self.skip_gates(stage),
            self.num_gates(stage),
            2 * self.num_gates(stage),
            values,
        )
    }

    /// Computes the (partial) $r(X)$ polynomial for the given stage by running
    /// a [`Stage`](super::Stage) body for its values; the value-level mirror of
    /// [`StageExt::rx_configured`](super::StageExt::rx_configured).
    ///
    /// The stage supplies the witness body only — where the resulting wires
    /// land comes from this layout, not from the type's own chain position.
    /// That is the whole point: one stage type serves every slot of a run.
    ///
    /// # Panics
    ///
    /// Panics if `stage >= self.len()`.
    pub fn rx_configured<F: Field, R: Rank, S: super::Stage<F, R>>(
        &self,
        stage: usize,
        alpha: F,
        body: &S,
        witness: S::Witness<'_>,
    ) -> Result<sparse::Polynomial<F, R>> {
        use ragu_core::{
            drivers::emulator::Emulator,
            maybe::{Always, MaybeKind},
        };

        let values = {
            let mut dr = Emulator::extractor();
            let out = body.witness(&mut dr, Always::maybe_just(|| witness))?;
            dr.wires(&out)?
        };

        self.rx(stage, alpha, &values)
    }
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use ragu_arithmetic::ff::Field;
    use ragu_core::{
        drivers::{Driver, DriverValue},
        gadgets::{Bound, Gadget},
    };
    use ragu_pasta::Fp;
    use ragu_primitives::{Element, io::Write};

    use super::*;
    use crate::{
        WiringObject,
        staging::{Stage, StageExt, mask::global_project},
    };

    type R = crate::polynomials::ProductionRank;

    /// Typed twin of an induced layout with widths `[4, 3]`, used to check
    /// that the value-level geometry matches the typed geometry exactly.
    #[derive(Default)]
    struct TypedFour;

    #[derive(Gadget, Write)]
    struct FourElements<'dr, #[ragu(driver)] D: Driver<'dr>> {
        #[ragu(gadget)]
        a: Element<'dr, D>,
        #[ragu(gadget)]
        b: Element<'dr, D>,
        #[ragu(gadget)]
        c: Element<'dr, D>,
        #[ragu(gadget)]
        d: Element<'dr, D>,
    }

    impl Stage<Fp, R> for TypedFour {
        type Parent = ();
        type Witness<'source> = [Fp; 4];
        type OutputKind =
            <FourElements<'static, PhantomData<Fp>> as Gadget<'static, PhantomData<Fp>>>::Kind;

        fn values() -> usize {
            4
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<Bound<'dr, D, Self::OutputKind>>
        where
            Self: 'dr,
        {
            use ragu_core::maybe::Maybe;
            use ragu_primitives::allocator::Standard;
            let alloc = &mut Standard::new();
            let a = Element::alloc(dr, alloc, witness.as_ref().map(|w| w[0]))?;
            let b = Element::alloc(dr, alloc, witness.as_ref().map(|w| w[1]))?;
            let c = Element::alloc(dr, alloc, witness.as_ref().map(|w| w[2]))?;
            let d = Element::alloc(dr, alloc, witness.as_ref().map(|w| w[3]))?;
            Ok(FourElements { a, b, c, d })
        }
    }

    /// Geometry-only twin of the second induced stage (width 3), chained onto
    /// [`TypedFour`] as its parent. Only its static geometry
    /// (`values` / `Parent`) is exercised, so the witness machinery is stubbed
    /// out like the base `()` stage.
    #[derive(Default)]
    struct TypedThree;

    impl Stage<Fp, R> for TypedThree {
        type Parent = TypedFour;
        type Witness<'source> = ();
        type OutputKind = ();

        fn values() -> usize {
            3
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            _: &mut D,
            _: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<Bound<'dr, D, Self::OutputKind>>
        where
            Self: 'dr,
        {
            Ok(())
        }
    }

    /// A two-wire stage, the shape every slot of a real induced run has: one
    /// value pair, exactly one gate, no padding.
    #[derive(Clone, Default)]
    struct TypedTwo;

    #[derive(Gadget, Write)]
    struct TwoElements<'dr, #[ragu(driver)] D: Driver<'dr>> {
        #[ragu(gadget)]
        a: Element<'dr, D>,
        #[ragu(gadget)]
        b: Element<'dr, D>,
    }

    impl Stage<Fp, R> for TypedTwo {
        type Parent = ();
        type Witness<'source> = [Fp; 2];
        type OutputKind =
            <TwoElements<'static, PhantomData<Fp>> as Gadget<'static, PhantomData<Fp>>>::Kind;

        fn values() -> usize {
            2
        }

        fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'source>>,
        ) -> Result<Bound<'dr, D, Self::OutputKind>>
        where
            Self: 'dr,
        {
            use ragu_core::maybe::Maybe;
            use ragu_primitives::allocator::Standard;
            let alloc = &mut Standard::new();
            let a = Element::alloc(dr, alloc, witness.as_ref().map(|w| w[0]))?;
            let b = Element::alloc(dr, alloc, witness.as_ref().map(|w| w[1]))?;
            Ok(TwoElements { a, b })
        }
    }

    /// An induced run reserves exactly what the equivalent chain of typed
    /// stages reserves, and leaves the trace at the same gate.
    ///
    /// This is the property that lets a run be declared to the type system as
    /// one stage: a run of two 2-wire slots and a single 4-wire stage cover the
    /// same gates, so anything chaining after the run — including
    /// `MultiStageCircuit::Last` — computes `skip_gates` correctly without
    /// knowing the run was subdivided. If the two paths ever diverge, every
    /// stage positioned after a run moves, so this is pinned rather than
    /// argued.
    #[test]
    fn induced_run_matches_typed_chain() -> Result<()> {
        use ragu_core::{
            drivers::emulator::{Emulator, Wireless},
            maybe::Empty,
        };

        use crate::staging::StageBuilder;

        // Two 2-wire slots subdividing the span of one 4-wire typed stage.
        let layout = InducedStages::new(alloc::vec![2, 2]);
        assert_eq!(
            layout.final_skip_gates(),
            <TypedFour as Stage<Fp, R>>::skip_gates() + <TypedFour as StageExt<Fp, R>>::num_gates(),
            "the run does not tile the typed stage that stands for it"
        );

        let mut typed_dr: Emulator<Wireless<Empty, Fp>> = Emulator::counter();
        let typed = StageBuilder::<'_, '_, _, R, (), TypedFour>::new(&mut typed_dr, |_| {})
            .add_stage::<TypedFour>()?
            .0;

        let mut induced_dr: Emulator<Wireless<Empty, Fp>> = Emulator::counter();
        let (induced, _) =
            StageBuilder::<'_, '_, _, R, (), TypedFour>::new(&mut induced_dr, |_| {})
                .configure_induced::<TypedFour, _>(TypedTwo, &layout)?;

        assert_eq!(induced.len(), 2, "one guard per slot");
        assert_eq!(
            induced.iter().map(|g| g.num_reserved()).sum::<usize>(),
            typed.num_reserved(),
            "induced run reserves a different number of wires than the typed chain"
        );

        Ok(())
    }

    /// A layout that does not tile its typed stage is rejected before any wire
    /// is allocated — the check that keeps the value-level and type-level
    /// geometries from drifting apart.
    #[test]
    fn induced_run_must_tile_its_typed_stage() {
        use ragu_core::{
            drivers::emulator::{Emulator, Wireless},
            maybe::Empty,
        };

        use crate::staging::StageBuilder;

        // Three slots where the typed stage spans only two gates.
        let layout = InducedStages::new(alloc::vec![2, 2, 2]);

        let mut dr: Emulator<Wireless<Empty, Fp>> = Emulator::counter();
        let result = StageBuilder::<'_, '_, _, R, (), TypedFour>::new(&mut dr, |_| {})
            .configure_induced::<TypedFour, _>(TypedTwo, &layout);

        assert!(
            result.is_err(),
            "an over-long run was accepted into a shorter typed span"
        );
    }

    /// An anchored layout puts its first slot exactly where the following
    /// typed stage would have started.
    #[test]
    fn anchored_layout_starts_after_its_base() {
        let layout = InducedStages::after::<Fp, R, TypedFour>(alloc::vec![2, 2]);

        assert_eq!(
            layout.skip_gates(0),
            <TypedThree as Stage<Fp, R>>::skip_gates(),
            "an anchored run does not start where the next typed stage would"
        );
    }

    /// Rebuilding a uniform run from its anchor reproduces the layout exactly.
    ///
    /// This is what lets geometry travel as a number through `Copy` contexts
    /// that cannot hold the layout itself: the anchor plus the slot shape is
    /// the whole of the information.
    #[test]
    fn uniform_round_trips_through_its_anchor() {
        let typed = InducedStages::after::<Fp, R, TypedFour>(alloc::vec![2, 2, 2]);
        let rebuilt = InducedStages::uniform(typed.anchor(), 3, 2);

        assert_eq!(typed, rebuilt, "a uniform run did not survive its anchor");
        assert_eq!(rebuilt.skip_gates(2), typed.skip_gates(2));
        assert_eq!(rebuilt.final_skip_gates(), typed.final_skip_gates());
    }

    #[test]
    fn geometry_matches_typed_stages() {
        let layout = InducedStages::new(alloc::vec![4, 3]);

        assert_eq!(layout.len(), 2);
        assert_eq!(
            layout.skip_gates(0),
            <TypedFour as Stage<Fp, R>>::skip_gates()
        );
        assert_eq!(
            layout.num_gates(0),
            <TypedFour as StageExt<Fp, R>>::num_gates()
        );

        // Second stage: width 3, chained onto the first.
        assert_eq!(
            layout.skip_gates(1),
            <TypedThree as Stage<Fp, R>>::skip_gates()
        );
        assert_eq!(
            layout.num_gates(1),
            <TypedThree as StageExt<Fp, R>>::num_gates()
        );
        // The final trace starts right after the last stage.
        assert_eq!(
            layout.final_skip_gates(),
            <TypedThree as Stage<Fp, R>>::skip_gates()
                + <TypedThree as StageExt<Fp, R>>::num_gates()
        );
    }

    #[test]
    fn empty_layout() {
        let layout = InducedStages::new(alloc::vec![]);
        assert!(layout.is_empty());
        // The final trace starts right after the SYSTEM gate, like an
        // ordinary single-stage circuit.
        assert_eq!(layout.final_skip_gates(), 1);
    }

    /// The induced rx for a stage satisfies its own induced mask and fails the
    /// mask of a different stage — the same property the typed system
    /// guarantees (`test_staging_valid` in the mask module).
    #[test]
    fn induced_rx_satisfies_induced_mask() -> Result<()> {
        let layout = InducedStages::new(alloc::vec![4, 3]);

        let values_a = [Fp::from(7), Fp::from(11), Fp::from(13), Fp::from(17)];
        let values_b = [Fp::from(19), Fp::from(23), Fp::from(29)];

        let rx_a = layout.rx::<Fp, R>(0, Fp::ZERO, &values_a)?;
        let rx_b = layout.rx::<Fp, R>(1, Fp::ZERO, &values_b)?;

        let mask_a = layout.mask::<Fp, R>(0)?.into_inner();
        let mask_b = layout.mask::<Fp, R>(1)?.into_inner();

        let y = Fp::from(0x5eed);

        // sy() returns -notch; add global_project to recover the full mask.
        let full_sy = |mask: &dyn WiringObject<Fp, R>, y| {
            let mut poly = global_project::<Fp, R>(y);
            poly += &mask.sy(y, &[]);
            poly
        };

        assert_eq!(rx_a.revdot(&full_sy(&*mask_a, y)), Fp::ZERO);
        assert_eq!(rx_b.revdot(&full_sy(&*mask_b, y)), Fp::ZERO);
        assert_ne!(rx_a.revdot(&full_sy(&*mask_b, y)), Fp::ZERO);
        assert_ne!(rx_b.revdot(&full_sy(&*mask_a, y)), Fp::ZERO);

        Ok(())
    }

    /// The induced rx for a stage matches the typed `StageExt::rx` for an
    /// equivalent typed stage.
    #[test]
    fn induced_rx_matches_typed_rx() -> Result<()> {
        let layout = InducedStages::new(alloc::vec![4]);
        let values = [Fp::from(3), Fp::from(1), Fp::from(4), Fp::from(1)];

        let induced = layout.rx::<Fp, R>(0, Fp::from(42), &values)?;
        let typed = TypedFour::rx(Fp::from(42), values)?;

        let point = Fp::from(0xbeef);
        assert_eq!(induced.eval(point), typed.eval(point));

        Ok(())
    }
}
