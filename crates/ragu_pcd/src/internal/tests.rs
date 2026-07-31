use native::{InternalCircuitIndex, InternalCircuitValues, RxIndex, RxValues};
use ragu_circuits::staging::Stage;
use ragu_pasta::{Pasta, fp, fq};

use super::*;
use crate::*;
pub type R = ragu_circuits::polynomials::ProductionRank;

use ragu_arithmetic::ff::PrimeField;
use ragu_circuits::polynomials::Rank;
use ragu_core::{
    drivers::emulator::{Emulator, Wireless},
    gadgets::{Bound, Gadget},
    maybe::Empty,
};

/// The number of wires `stage` actually allocates.
pub fn stage_wire_count<F, R, S>(stage: &S) -> usize
where
    F: PrimeField,
    R: Rank,
    S: Stage<F, R>,
    for<'dr> Bound<'dr, Emulator<Wireless<Empty, F>>, S::OutputKind>:
        Gadget<'dr, Emulator<Wireless<Empty, F>>>,
{
    let mut emulator = Emulator::counter();
    stage
        .witness(&mut emulator, Empty)
        .expect("allocation should succeed")
        .num_wires()
        .expect("wire counting should succeed")
}

/// A stage whose width its type knows allocates exactly `Stage::values()`
/// wires.
///
/// Only for stages that are genuinely shape-free. A stage sized by the
/// application has no `values()` to check against — assert its wire count
/// against its `num_values(capacity)` directly, as the shaped stages' own
/// tests do.
pub fn assert_stage_values<F, R, S>(stage: &S)
where
    F: PrimeField,
    R: Rank,
    S: Stage<F, R>,
    for<'dr> Bound<'dr, Emulator<Wireless<Empty, F>>, S::OutputKind>:
        Gadget<'dr, Emulator<Wireless<Empty, F>>>,
{
    assert_eq!(
        stage_wire_count(stage),
        S::values(),
        "Stage::values() does not match actual wire count"
    );
}

// When changing HEADER_SIZE, update the constraint counts by running:
//   cargo test -p ragu_pcd --release print_internal_circuit -- --nocapture
// Then copy-paste the output into the check_constraints! calls in the test below.
//
// This is the widest header the framework claims to support, and it trades
// directly against the claim slots: both are terms in the same k(Y) Horner
// loop, charged to `outer_collapse` — the largest internal circuit — at
// roughly 13 gates per header element and 12 per slot against its 2048-gate
// bound. A slot costs about one header element.
pub const HEADER_SIZE: usize = 90;

// Number of dummy application circuits to register before testing internal
// circuits. This ensures the tests work correctly even when application
// steps are present.
const NUM_APP_STEPS: usize = 6000;

/// The header size the slotted shape pins at.
///
/// Small on purpose: the slotted shape exists to cover the *slot* regions,
/// and a 90-element header alongside real slots pushes `hashes_2` against
/// its gate bound for no gain.
const SLOTTED_HEADER_SIZE: usize = 4;

/// Dummy application circuits for the slotted shape. The no-slot shape
/// already registers [`NUM_APP_STEPS`] to show the internal circuits survive
/// a large application; a small count here keeps this file's runtime down.
const NUM_SLOTTED_APP_STEPS: usize = 6;

/// Builds a dummy application at a stated shape.
///
/// The shape is the point: every pinned number below is a function of it, so
/// the same checks run at more than one, and a change that only touches the
/// slot regions cannot slip past them.
fn dummy_app<
    'params,
    const HDR: usize,
    const POLYS: usize,
    const CLAIMS: usize,
    const CHALLENGES: usize,
>(
    pasta: &'params <Pasta as ragu_arithmetic::Cycle>::Params,
    steps: usize,
) -> crate::Application<'params, Pasta, R, HDR, POLYS, CLAIMS, CHALLENGES, 2> {
    ApplicationBuilder::<Pasta, R, HDR, POLYS, CLAIMS, CHALLENGES, 2>::new()
        .register_dummy_circuits(steps)
        .unwrap()
        .finalize(pasta)
        .unwrap()
}

/// Pins one internal circuit's gate and constraint counts in `app`.
///
/// Takes the application because these numbers are a function of its declared
/// shape, and the shape is what has to be covered at more than one value: the
/// gate count is measured against `R::n()`, the 2048-gate bound that sets an
/// application's claim capacity, and only a shape with slots can show a slot
/// region pushing against it.
macro_rules! check_constraints {
    ($app:expr, $variant:ident, mul = $mul:expr, lin = $lin:expr) => {{
        let circuit_index = InternalCircuitIndex::$variant.circuit_index();
        let (actual_gates, actual_constraints) =
            $app.native_registry.constraint_counts(circuit_index);
        assert_eq!(
            actual_gates,
            $mul,
            "{}: gates: expected {}, got {}",
            stringify!($variant),
            $mul,
            actual_gates
        );
        assert_eq!(
            actual_constraints,
            $lin,
            "{}: constraints: expected {}, got {}",
            stringify!($variant),
            $lin,
            actual_constraints
        );
    }};
}

#[rustfmt::skip]
#[test]
fn test_internal_circuit_constraint_counts() {
    let pasta = Pasta::baked();

    let app = dummy_app::<HEADER_SIZE, 0, 0, 0>(pasta, NUM_APP_STEPS);

    check_constraints!(app, Hashes1Circuit,          mul = 1406, lin = 2038);
    check_constraints!(app, Hashes2Circuit,          mul = 1954, lin = 2951);
    check_constraints!(app, InnerCollapseCircuit,    mul = 1831, lin = 1918);
    check_constraints!(app, OuterCollapseCircuit,    mul = 1848, lin = 2742);
    // `ChallengeBinding`'s count includes `OuterError`'s 186 gates: it
    // reaches the challenge slots on the branch below `OuterError`, and a
    // circuit's trace spans every gate up to its last stage, so it pays for
    // the stage it skips on the way.
    check_constraints!(app, ComputeVCircuit,         mul = 1239, lin = 1819);
    check_constraints!(app, ChallengeBindingCircuit, mul =  518, lin =   71);
}

/// The same pins at a shape that *has* slots — two polynomials, three claims,
/// one challenge.
///
/// [`test_internal_circuit_constraint_counts`] declares none of those, so every
/// width the slot regions contribute collapses to zero and a change confined to
/// them passes it untouched. These numbers are the ones that move when a claim
/// gets wider, when `compute_v`'s per-claim resolution gets dearer, or when a
/// slot region starts pushing an internal circuit toward `R::n()`.
///
/// The gate column is the one to watch: `compute_v` is the circuit that sets an
/// application's claim capacity, and it does so by reaching 2048 first.
#[rustfmt::skip]
#[test]
fn test_slotted_internal_circuit_constraint_counts() {
    let pasta = Pasta::baked();

    let app = dummy_app::<SLOTTED_HEADER_SIZE, 2, 3, 1>(pasta, NUM_SLOTTED_APP_STEPS);

    // All six span the preamble stage, so all six include the coordinate
    // region's wires (two per polynomial slot per child); `OuterCollapse`'s
    // `application_ky` Horner additionally folds them.
    check_constraints!(app, Hashes1Circuit,          mul = 1152, lin = 1834);
    check_constraints!(app, Hashes2Circuit,          mul = 1716, lin = 2951);
    check_constraints!(app, InnerCollapseCircuit,    mul = 1593, lin = 1918);
    check_constraints!(app, OuterCollapseCircuit,    mul =  805, lin = 1122);
    // The two that read the slot regions, and the reason this shape is pinned
    // at all. `ComputeV` carries the per-claim one-hot resolution and the
    // per-child q(u) re-derivation from the coordinate instance wires, so it
    // moves whenever those do. `ChallengeBinding` is 861 here against 518
    // with no slots: an application that derives a challenge has one to bind.
    check_constraints!(app, ComputeVCircuit,         mul = 1112, lin = 2077);
    check_constraints!(app, ChallengeBindingCircuit, mul =  861, lin = 1225);
}

/// Prints the counts `test_internal_circuit_constraint_counts` pins, so a
/// deliberate change can be re-pinned in one run instead of one per circuit.
///
/// Ignored by default: it is a helper, not a check.
///
/// Run with: `cargo test -p ragu_pcd print_internal_circuit_constraint -- --ignored --nocapture`
#[test]
#[ignore = "prints the pinned constraint counts; run explicitly"]
fn print_internal_circuit_constraint_counts() {
    use std::println;

    let pasta = Pasta::baked();

    let print = |registry: &ragu_circuits::registry::Registry<_, R>, test: &str| {
        println!("\n// Copy-paste the following into {test}:");
        for variant in [
            InternalCircuitIndex::Hashes1Circuit,
            InternalCircuitIndex::Hashes2Circuit,
            InternalCircuitIndex::InnerCollapseCircuit,
            InternalCircuitIndex::OuterCollapseCircuit,
            InternalCircuitIndex::ComputeVCircuit,
            InternalCircuitIndex::ChallengeBindingCircuit,
        ] {
            let (mul, lin) = registry.constraint_counts(variant.circuit_index());
            println!(
                "    check_constraints!(app, {:<24} mul = {:>4}, lin = {:>4});",
                alloc::format!("{variant:?},"),
                mul,
                lin
            );
        }
    };

    print(
        &dummy_app::<HEADER_SIZE, 0, 0, 0>(pasta, NUM_APP_STEPS).native_registry,
        "test_internal_circuit_constraint_counts",
    );
    print(
        &dummy_app::<SLOTTED_HEADER_SIZE, 2, 3, 1>(pasta, NUM_SLOTTED_APP_STEPS).native_registry,
        "test_slotted_internal_circuit_constraint_counts",
    );
}

/// The stage types `test_internal_stage_parameters` pins, at eight polynomial
/// slots. The geometry is a function of the declared slot counts, so the
/// counts have to be named.
mod pinned_chain {
    use super::{HEADER_SIZE, R};
    use crate::internal::native::chain;

    pub type Preamble = chain::Preamble<ragu_pasta::Pasta, R, HEADER_SIZE, 8, 1>;
    pub type OuterError = chain::OuterError<ragu_pasta::Pasta, R, HEADER_SIZE, 8, 1>;
    pub type InnerError = chain::InnerError<ragu_pasta::Pasta, R, HEADER_SIZE, 8, 1>;
    pub type Query = chain::Query<ragu_pasta::Pasta, R, HEADER_SIZE, 8, 1>;
    pub type Eval = chain::Eval<ragu_pasta::Pasta, R, HEADER_SIZE, 8, 1>;
    pub type Challenges = chain::Challenges<ragu_pasta::Pasta, R, HEADER_SIZE, 8, 1, 1, 2>;
}

/// Pins the native stages' gate geometry at a stated slot count.
///
/// A drift detector for circuit size: a stage that grows pushes everything
/// after it, and these numbers say by how much. Every number here comes off the
/// stage type, through its `Parent` chain — the same source the registry's
/// masks and the fuse's rx placements use.
#[rustfmt::skip]
#[test]
fn test_internal_stage_parameters() {
    use ragu_circuits::staging::{Stage as _, StageExt as _};

    macro_rules! check_stage {
        ($stage:ty, $name:literal, skip = $skip:expr, num = $num:expr) => {{
            assert_eq!(<$stage>::skip_gates(), $skip, "{}: skip", $name);
            assert_eq!(<$stage>::num_gates(), $num, "{}: num", $name);
        }};
    }

    check_stage!(pinned_chain::Preamble,   "Preamble",   skip =   1, num = 336);
    check_stage!(pinned_chain::OuterError, "OuterError", skip = 337, num = 186);
    check_stage!(pinned_chain::InnerError, "InnerError", skip = 523, num = 399);
    check_stage!(pinned_chain::Query,      "Query",      skip = 337, num =  27);
    check_stage!(pinned_chain::Eval,       "Eval",       skip = 364, num =  29);
    // A sibling of InnerError, not a successor: both start where OuterError
    // ends, so a circuit reaching the challenge slots is not charged for
    // InnerError's gates.
    check_stage!(pinned_chain::Challenges, "Challenges", skip = 523, num =   5);
}

/// Helper test to print current stage parameters in copy-pasteable format.
/// Run with: `cargo test -p ragu_pcd --release print_internal_stage -- --nocapture`
#[test]
fn print_internal_stage_parameters() {
    use std::println;

    use ragu_circuits::staging::StageExt as _;

    fn line<S: ragu_circuits::staging::Stage<ragu_pasta::Fp, R>>(name: &str) {
        println!(
            "    check_stage!(pinned_chain::{:<12} {:<13} skip = {:>3}, num = {:>3});",
            alloc::format!("{name},"),
            alloc::format!("\"{name}\","),
            S::skip_gates(),
            S::num_gates()
        );
    }

    println!("\n// Copy-paste the following into test_internal_stage_parameters:");
    line::<pinned_chain::Preamble>("Preamble");
    line::<pinned_chain::OuterError>("OuterError");
    line::<pinned_chain::InnerError>("InnerError");
    line::<pinned_chain::Query>("Query");
    line::<pinned_chain::Eval>("Eval");
    line::<pinned_chain::Challenges>("Challenges");
}

/// Verifies the native registry digest matches the expected value.
///
/// This test ensures the wiring polynomial structure is mathematically
/// equivalent to the reference implementation by comparing cryptographic
/// digests.
#[test]
fn test_native_registry_digest() {
    let pasta = Pasta::baked();

    let app = dummy_app::<HEADER_SIZE, 0, 0, 0>(pasta, NUM_APP_STEPS);

    // The digest is per application: capacity is a set of declared const
    // parameters, and this test application declares
    // `POLYS = 0, CLAIMS = 0, CHALLENGES = 0`, so every slot-dependent width
    // collapses. That is also this pin's blind spot — a change confined to
    // the slot regions cannot move it; [`test_slotted_registry_digests`]
    // covers those.
    let expected = fp!(0x2bb64a4adaa9e869d9187bec77ae9f8c8788703ca013ff9bae02b6fdbc02dec0);

    assert_eq!(
        app.native_registry.digest(),
        expected,
        "Native registry digest changed unexpectedly!"
    );
}

/// Pins both registry digests for an application that *has* slots.
///
/// [`test_native_registry_digest`] and [`test_nested_registry_digest`] both
/// build a `POLYS = 0, CLAIMS = 0, CHALLENGES = 0` application, so every width
/// the slot regions contribute collapses to zero and a change confined to them
/// passes both untouched. That is not hypothetical: an omission in the
/// challenge stage slipped through exactly this way earlier on this branch,
/// caught only by an integration test.
///
/// This application declares two polynomials, three claims and one challenge,
/// so it moves when any slot region's wiring does — which is the case the other
/// two cannot see.
#[test]
fn test_slotted_registry_digests() {
    let pasta = Pasta::baked();

    let app = dummy_app::<SLOTTED_HEADER_SIZE, 2, 3, 1>(pasta, NUM_SLOTTED_APP_STEPS);

    // Covers the limb machinery: the eval stage carries one q(u) per child
    // and `compute_v` re-derives it from the coordinate instance wires. The
    // `POLYS = 0` digests holding alongside is the isolation check:
    // `q_slots(0) = 0`, so the feature vanishes at that shape.
    assert_eq!(
        app.native_registry.digest(),
        fp!(0x06286f4bb9b9f9dd4d2f36c8bd877eefc6bc66d67bed3cc82e84348d604595e8),
        "Native registry digest changed unexpectedly at a slotted shape!"
    );
    // Covers the nested side of the claim machinery: one coordinate-pair
    // slot per claim bridge, the stashed `C_q`, and the endoscaling growth.
    // The limb machinery itself (`q`, the coordinate instance region,
    // `compute_v`'s re-derivation) is all native and must move only the
    // digest above.
    assert_eq!(
        app.nested_registry.digest(),
        fq!(0x3158d084e78957d7df2a0123baddfd948e4e7f3d920327f78c5b851eb3444d67),
        "Nested registry digest changed unexpectedly at a slotted shape!"
    );
}

/// Verifies the nested registry digest matches the expected value.
///
/// This test ensures the wiring polynomial structure is mathematically
/// equivalent to the reference implementation by comparing cryptographic
/// digests.
#[test]
fn test_nested_registry_digest() {
    let pasta = Pasta::baked();

    let app = dummy_app::<HEADER_SIZE, 0, 0, 0>(pasta, NUM_APP_STEPS);

    // Per application, like the native digest above: at
    // `POLYS = 0, CLAIMS = 0, CHALLENGES = 0` the claim-bridge run is empty,
    // the eval and preamble bridges carry no stashed claims, and the
    // endoscaling point list carries no per-slot points — so a change
    // confined to any of those cannot move this number.
    // [`test_slotted_registry_digests`] covers that shape.
    let expected = fq!(0x06bb3145242fd72534249a81cf321e7e4608d2610f745aa4eafa42887528f9d9);

    assert_eq!(
        app.nested_registry.digest(),
        expected,
        "Nested registry digest changed unexpectedly!"
    );
}

/// Helper test to print current registry digests in copy-pasteable format.
/// Run with: `cargo test -p ragu_pcd --release print_registry_digests -- --nocapture`
#[test]
fn print_registry_digests() {
    use alloc::{format, string::String};
    use std::println;

    use ragu_arithmetic::ff::PrimeField;

    let pasta = Pasta::baked();

    // Big-endian hex, the `fp!`/`fq!` literal form.
    fn hex<F: PrimeField>(digest: F) -> String {
        digest
            .to_repr()
            .as_ref()
            .iter()
            .rev()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    let no_slots = dummy_app::<HEADER_SIZE, 0, 0, 0>(pasta, NUM_APP_STEPS);
    let slotted = dummy_app::<SLOTTED_HEADER_SIZE, 2, 3, 1>(pasta, NUM_SLOTTED_APP_STEPS);

    println!("\n// Copy-paste the following into the registry digest tests:");
    println!(
        "    // test_native_registry_digest\n    let expected = fp!(0x{});",
        hex(no_slots.native_registry.digest())
    );
    println!(
        "    // test_nested_registry_digest\n    let expected = fq!(0x{});",
        hex(no_slots.nested_registry.digest())
    );
    println!(
        "    // test_slotted_registry_digests\n    fp!(0x{}),\n    fq!(0x{}),",
        hex(slotted.native_registry.digest()),
        hex(slotted.nested_registry.digest())
    );
}

/// The nested chain layout tiles — every stage starts where its predecessor
/// ended — at every capacity.
///
/// The masks cut from it are functions of precisely these offsets, so a break
/// in tiling silently misplaces every stage after it. Checked across
/// capacities: the bug this guards against is geometry that is right at one
/// blessed shape and wrong at every other.
///
/// Only the nested chain needs this. The native chain is typed, so
/// [`Stage::skip_gates`](ragu_circuits::staging::Stage::skip_gates) *is*
/// `Parent::skip_gates() + Parent::num_gates()` by definition.
#[test]
fn nested_chain_layout_tiles_at_every_capacity() {
    use ragu_pasta::Pasta;

    type Host = <Pasta as ragu_arithmetic::Cycle>::HostCurve;

    for polys in [0, 1, 4, 8] {
        let nested = crate::internal::nested::chain_layout::<Host, R>(polys);

        for stage in 0..nested.len() {
            assert_eq!(
                nested.skip_gates(stage + 1),
                nested.skip_gates(stage) + nested.num_gates(stage),
                "not contiguous after stage {stage} at polys={polys}"
            );
        }
    }
}

/// The endoscaling point count is one formula in two forms, and they agree.
///
/// `num_endoscaling_points` sizes the value-level layouts that *place* the points
/// stage; `EndoPoints` is the [`Len`](ragu_primitives::vec::Len) that gives
/// [`Points`](crate::internal::endoscalar::Points) its width as a gadget. A gadget
/// wider than the span holding it is a wire-position bug that no other test here
/// would attribute, so this pins the two together across the shapes the suite
/// proves at.
///
/// The expected side is spelled out longhand rather than read from
/// `num_endoscaling_points`: `1` for `f.commitment`, two per-child blocks of
/// `RxIndex::NUM + 4 + polys` plus the child's claim-coordinate `C_q` (one whenever
/// there are slots, none otherwise), and the current step's six components.
/// Calling the function under test on both sides would assert `x == x`.
#[test]
fn endoscaling_points_len_matches_the_value_formula() {
    use ragu_primitives::vec::{ConstLen, Len};

    use crate::internal::{
        native::{RxIndex, stages::eval::CURRENT_STEP_COMPONENTS},
        nested::{EndoPoints, num_endoscaling_points},
    };

    fn check<const POLYS: usize>() {
        let q = if POLYS == 0 { 0 } else { 1 };
        let longhand = 1 + 2 * (RxIndex::NUM + 4 + POLYS + q) + CURRENT_STEP_COMPONENTS;

        assert_eq!(
            num_endoscaling_points(POLYS),
            longhand,
            "the value formula drifted at polys={POLYS}"
        );
        assert_eq!(
            EndoPoints::<ConstLen<POLYS>>::len(),
            longhand,
            "the type-level count disagrees with the value formula at polys={POLYS}"
        );
    }

    check::<0>();
    check::<1>();
    check::<4>();
    check::<8>();
}

/// `ChainStage`'s discriminants are the indices `chain_layout` builds.
///
/// The runs and the mask registration address the chain through
/// [`ChainStage`](crate::internal::nested::ChainStage) rather than through bare
/// integers, which is only safe while the two orders agree. Nothing else
/// enforces that: `chain_layout` pushes widths into a `Vec`, so a stage
/// inserted in one place and not the other compiles fine and silently
/// misplaces every stage after it.
#[test]
fn nested_chain_positions_match_layout() {
    use ragu_pasta::Pasta;

    use crate::internal::nested::ChainStage;

    type Host = <Pasta as ragu_arithmetic::Cycle>::HostCurve;

    let chain = crate::internal::nested::chain_layout::<Host, R>(4);

    assert_eq!(
        chain.len(),
        ChainStage::ALL.len(),
        "the chain and `ChainStage::ALL` disagree on how many stages there are"
    );
    for (position, stage) in ChainStage::ALL.iter().enumerate() {
        assert_eq!(
            stage.index(),
            position,
            "{stage:?} is at position {position} of ALL but reports index {}",
            stage.index()
        );
    }
}

#[test]
fn test_internal_circuit_index_all_exhaustive() {
    let mut collected = alloc::vec::Vec::new();
    let _values = InternalCircuitValues::from_fn(|id| {
        collected.push(id);
    });
    assert_eq!(collected.as_slice(), InternalCircuitIndex::ALL);
}

#[test]
fn test_rx_index_all_exhaustive() {
    let mut collected = alloc::vec::Vec::new();
    let _values = RxValues::from_fn(|id| {
        collected.push(id);
    });
    assert_eq!(collected.as_slice(), RxIndex::ALL);
}

/// A light application's recursion is **measurably smaller** than a heavy
/// one's: two applications, identical but for the capacity they declare, and
/// every internal circuit the heavy one registers is strictly larger —
/// capacity is the application's own declaration, not a framework constant.
///
/// Each application's single step is written to match what it declares —
/// `Light` calls no hook, `Heavy` witnesses two polynomials, opens one of
/// them twice and derives a challenge — but the gate counts come from the
/// declared consts alone; the steps are here so the declarations read as
/// something an application would really ask for.
mod capacity_is_per_application {
    use ragu_arithmetic::ff::Field;
    use ragu_core::{
        drivers::{Driver, DriverValue},
        gadgets::{Bound, Kind},
        maybe::Maybe,
    };
    use ragu_pasta::{Fp, Pasta};
    use ragu_primitives::{
        Element,
        allocator::{Allocator, Standard},
    };

    use super::*;
    use crate::{
        framework_hooks::{ChallengeLayout, HookLayout, PolyQueryLayout},
        header::{Header, Suffix},
        step::{Encoded, Index, Step, StepCtx},
    };

    const HS: usize = 4;

    struct H;

    impl Header<Fp> for H {
        const SUFFIX: Suffix = Suffix::new(50);
        type Data = Fp;
        type Output = Kind![Fp; Element<'_, _>];

        fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
            dr: &mut D,
            allocator: &mut A,
            witness: DriverValue<D, Self::Data>,
        ) -> Result<Bound<'dr, D, Self::Output>> {
            Element::alloc(dr, allocator, witness)
        }
    }

    /// A step that uses no framework hooks at all.
    struct Light;

    /// A step that witnesses two polynomials, opens one of them twice, and
    /// derives a challenge.
    struct Heavy;

    macro_rules! step {
        ($ty:ty, |$ctx:ident| $hooks:block) => {
            impl Step<Pasta> for $ty {
                const INDEX: Index = Index::new(0);
                type Witness<'source> = ();
                type Aux<'source> = ();
                type Left = H;
                type Right = H;
                type Output = H;

                fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const N: usize>(
                    &self,
                    $ctx: &mut StepCtx<'_, 'dr, D, Pasta>,
                    _: DriverValue<D, ()>,
                    left: DriverValue<D, Fp>,
                    right: DriverValue<D, Fp>,
                ) -> Result<(
                    (
                        Encoded<'dr, D, Self::Left, N>,
                        Encoded<'dr, D, Self::Right, N>,
                        Encoded<'dr, D, Self::Output, N>,
                    ),
                    DriverValue<D, Fp>,
                    DriverValue<D, ()>,
                )> {
                    let allocator = &mut Standard::new();
                    let l = Element::alloc($ctx.dr, allocator, left)?;
                    let r = Element::alloc($ctx.dr, allocator, right)?;
                    $hooks
                    let out = l.add($ctx.dr, &r);
                    let out_val = Maybe::map(out.value(), |v| *v);
                    Ok((
                        (
                            Encoded::from_gadget(l),
                            Encoded::from_gadget(r),
                            Encoded::from_gadget(out),
                        ),
                        out_val,
                        D::unit(),
                    ))
                }
            }
        };
    }

    step!(Light, |ctx| {
        let _ = &ctx;
    });

    step!(Heavy, |ctx| {
        // This step is only ever registered, never proved, so what matters here
        // is that the hook calls happen — not the values they carry.
        let commitment = D::try_just(|| {
            Err::<crate::poly_commitment::PolyCommitment<Pasta, R>, _>(Error::InvalidWitness(
                "the capacity test never builds a proof".into(),
            ))
        })?;
        // Both polynomials in one call: slot 0 is `handle`, slot 1 is `other`.
        let [handle, other] =
            ctx.witness_polynomial::<R, 2>([Maybe::clone(&commitment), commitment])?;
        let zero = Element::alloc(ctx.dr, &mut Standard::new(), D::just(|| Fp::ZERO))?;
        // One polynomial opened twice, the other once: three claims over two
        // polynomials.
        ctx.enforce_poly_query(&handle, zero.clone(), zero.clone())?;
        ctx.enforce_poly_query(&handle, zero.clone(), zero.clone())?;
        ctx.enforce_poly_query(&other, zero.clone(), zero)?;
        ctx.derive_challenge(&[handle.bridge_commitment().clone()])?;
    });

    fn gates<const POLYS: usize, const CLAIMS: usize, const CHALLENGES: usize>(
        app: &Application<'_, Pasta, R, HS, POLYS, CLAIMS, CHALLENGES, 2>,
        id: InternalCircuitIndex,
    ) -> usize {
        app.native_registry.constraint_counts(id.circuit_index()).0
    }

    #[test]
    fn a_light_application_pays_less_than_a_heavy_one() {
        let pasta = Pasta::baked();
        // The declared polynomial capacity is the difference between these two
        // applications: `Light` witnesses none, `Heavy` witnesses two.
        let light = ApplicationBuilder::<Pasta, R, HS, 0, 0, 0, 2>::new()
            .register(Light)
            .unwrap()
            .finalize(pasta)
            .unwrap();
        let heavy = ApplicationBuilder::<Pasta, R, HS, 2, 3, 1, 2>::new()
            .register(Heavy)
            .unwrap()
            .finalize(pasta)
            .unwrap();

        // Each application's capacity is its own declaration, and each declared
        // const lands on its own axis. Reading the four back together is what
        // makes this more than a restatement: `<2, 3, 1, 2>` is four distinct
        // values, so a `capacity()` that crossed two of them fails here rather
        // than downstream as a slot-count mismatch.
        assert_eq!(
            light.capacity(),
            HookLayout {
                challenge: ChallengeLayout { calls: 0, width: 2 },
                poly_query: PolyQueryLayout {
                    polys: 0,
                    claims: 0
                },
            }
        );
        assert_eq!(
            heavy.capacity(),
            HookLayout {
                challenge: ChallengeLayout { calls: 1, width: 2 },
                poly_query: PolyQueryLayout {
                    polys: 2,
                    claims: 3
                },
            }
        );

        // Every internal circuit that reads a child's slots is strictly
        // smaller in the light application.
        for id in [
            InternalCircuitIndex::Hashes1Circuit,
            InternalCircuitIndex::OuterCollapseCircuit,
            InternalCircuitIndex::ComputeVCircuit,
            InternalCircuitIndex::ChallengeBindingCircuit,
        ] {
            assert!(
                gates(&light, id) < gates(&heavy, id),
                "{id:?}: light {} is not smaller than heavy {}",
                gates(&light, id),
                gates(&heavy, id),
            );
        }

        // And the saving is real, not a rounding difference: a step that
        // derives no challenge pays nothing at all to bind one.
        assert!(
            gates(&light, InternalCircuitIndex::ChallengeBindingCircuit) * 2
                < gates(&heavy, InternalCircuitIndex::ChallengeBindingCircuit),
            "light {} vs heavy {}",
            gates(&light, InternalCircuitIndex::ChallengeBindingCircuit),
            gates(&heavy, InternalCircuitIndex::ChallengeBindingCircuit),
        );
    }
}
