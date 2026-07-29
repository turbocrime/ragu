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

/// A capacity with the given poly count, for shaped-stage tests.
#[cfg(test)]
pub fn capacity_with_polys(polys: usize) -> crate::framework_hooks::HookLayout {
    crate::framework_hooks::HookLayout {
        challenge: crate::framework_hooks::ChallengeLayout { calls: 1, width: 2 },
        poly_query: crate::framework_hooks::PolyQueryLayout { polys, claims: 1 },
    }
}

// When changing HEADER_SIZE, update the constraint counts by running:
//   cargo test -p ragu_pcd --release print_internal_circuit -- --nocapture
// Then copy-paste the output into the check_constraints! calls in the test below.
//
// This is not a free test parameter. It is the widest header the framework
// claims to support, and it trades directly against the claim slots: both are
// charged to `outer_collapse`, the largest internal circuit, at roughly 13
// gates per header element and 12 per slot. Measured against its 2048-gate
// bound, back when the slot count was a framework constant:
//
//     4 slots, header 100 -> 2044   (4 gates spare)
//     8 slots, header  90 -> 1962
//     8 slots, header  84 -> 1884
//     8 slots, header  60 -> 1572
//
// So a slot costs about one header element, and ten elements of header bought
// four more claim slots. That constant is gone — claim slots are now whatever
// header space is left before `GateBoundExceeded` trips, since claim slots and
// header elements are terms in the same k(Y) Horner loop. The measurements
// stand as the exchange rate.
pub const HEADER_SIZE: usize = 90;

// Number of dummy application circuits to register before testing internal
// circuits. This ensures the tests work correctly even when application
// steps are present.
const NUM_APP_STEPS: usize = 6000;

#[rustfmt::skip]
#[test]
fn test_internal_circuit_constraint_counts() {
    let pasta = Pasta::baked();

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE, 0, 0, 0, 2>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    macro_rules! check_constraints {
        ($variant:ident, mul = $mul:expr, lin = $lin:expr) => {{
            let circuit_index = InternalCircuitIndex::$variant.circuit_index();
            let (actual_gates, actual_constraints) =
                app.native_registry.constraint_counts(circuit_index);
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

    check_constraints!(Hashes1Circuit,          mul = 1406, lin = 2038);
    check_constraints!(Hashes2Circuit,          mul = 1954, lin = 2951);
    check_constraints!(InnerCollapseCircuit,    mul = 1831, lin = 1918);
    check_constraints!(OuterCollapseCircuit,    mul = 1848, lin = 2742);
    // `ComputeV` grew by 13: it iterates the internal circuits, and the
    // challenge slots added a stage mask and a final-trace mask.
    //
    // `ChallengeBinding` grew by 186 — exactly `OuterError`'s gates. It reaches
    // the challenge slots on the branch below `OuterError`, and a circuit's
    // trace spans every gate up to its last stage, so it pays for the stage it
    // skips on the way. That is the price of keeping `OuterCollapse` — which
    // needs both `OuterError` and the challenge slots — able to reach both.
    check_constraints!(ComputeVCircuit,         mul = 1239, lin = 1819);
    check_constraints!(ChallengeBindingCircuit, mul =  518, lin =   71);
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
    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE, 0, 0, 0, 2>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    println!("\n// Copy-paste the following into test_internal_circuit_constraint_counts:");
    for variant in [
        InternalCircuitIndex::Hashes1Circuit,
        InternalCircuitIndex::Hashes2Circuit,
        InternalCircuitIndex::InnerCollapseCircuit,
        InternalCircuitIndex::OuterCollapseCircuit,
        InternalCircuitIndex::ComputeVCircuit,
        InternalCircuitIndex::ChallengeBindingCircuit,
    ] {
        let (mul, lin) = app
            .native_registry
            .constraint_counts(variant.circuit_index());
        println!(
            "    check_constraints!({:<24} mul = {:>4}, lin = {:>4});",
            alloc::format!("{variant:?},"),
            mul,
            lin
        );
    }
}

/// The stage types `test_internal_stage_parameters` pins, at eight polynomial
/// slots.
///
/// The geometry is a function of the declared slot counts, so the counts have
/// to be named — there is no single "the" layout, which is the point of the
/// branch these numbers were re-pinned on.
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

    check_stage!(pinned_chain::Preamble,   "Preamble",   skip =   1, num = 319);
    check_stage!(pinned_chain::OuterError, "OuterError", skip = 320, num = 186);
    check_stage!(pinned_chain::InnerError, "InnerError", skip = 506, num = 399);
    check_stage!(pinned_chain::Query,      "Query",      skip = 320, num =  27);
    check_stage!(pinned_chain::Eval,       "Eval",       skip = 347, num =  28);
    // A sibling of InnerError, not a successor: both start where OuterError
    // ends, so a circuit reaching the challenge slots is not charged for
    // InnerError's gates.
    check_stage!(pinned_chain::Challenges, "Challenges", skip = 506, num =   5);
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

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE, 0, 0, 0, 2>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    // Changed when challenge derivation moved into application-circuit stages:
    // every application circuit gained `NUM_CHALLENGE_SLOTS` staged wire
    // regions and `NUM_CHALLENGE_SLOTS * 3` instance elements (the bridged
    // stage commitment and its challenge, per slot). Changed again when the
    // `challenge_binding` circuit landed: the native registry gained that
    // circuit, a `PreambleFinalStaged` mask, and one more `RxIndex` component
    // (which widens the `query` and `eval` stages by one evaluation per child).
    // Changed again when unused challenge slots started being *filled* rather
    // than skipped: a skipped slot left its `CHALLENGE_WIDTH` reserved wires
    // unconstrained inside a region the stage commits, so each padded slot now
    // pins them to zero. Changed again when slot padding stopped being its own
    // routine and started calling `derive_challenge` — which, like every real
    // call, takes a fresh gate allocator, so a padded slot's challenge element
    // no longer shares a gate with the next slot's. Changed again when the
    // challenge stages became `RxIndex` variants: they moved from their own
    // position in the `_10_p` accumulation into the `RxIndex::ALL` block, and
    // `compute_v` gained the poly-query triple every other rx component has
    // (four more per fuse, one per child per slot). Changed again when the
    // query-slot count went from 4 to 8 and `HEADER_SIZE` from 100 to 90
    // — both change the width of every application circuit's instance.
    //
    // Changed again when `derive_challenge` became points-only. The challenge
    // stages are gone, so the native registry lost the per-slot stage masks,
    // the per-count final-trace masks, and the `ChallengeStage` rx components
    // — which shrinks `RxIndex::ALL`, and with it every stage that carries one
    // evaluation per rx component. What grew is the instance: a slot now
    // carries `2 * challenge.width + 1` elements where it carried
    // three, so the preamble stage and its readers widen by two per slot per
    // child.
    //
    // Changed again — and now **per application** — when the slot capacity
    // became the discovered maximum over the registered steps rather than a
    // framework constant. This digest is *this test application's*: its dummy
    // steps witness no polynomials, raise no claims and derive no challenges,
    // so every slot-dependent width collapses. `challenge_binding` in
    // particular falls from 1534 gates to 332, because an application that
    // never derives a challenge has nothing to bind. Another application's
    // digest will differ, which is the point.
    //
    // Changed again when the challenge slots became their own stage. Two
    // circuits gained stages — `outer_collapse` and `challenge_binding` both
    // end at the new stage now — so their entries in `native::claims::build`
    // fold two more rx components. `compute_v` builds that same claim list
    // in-circuit, and the extra components are evaluations folded into linear
    // combinations it already had, so its wiring moves while its gate counts do
    // not. That is why this digest changed and
    // `test_internal_circuit_constraint_counts` did not.
    let expected = fp!(0x2bb64a4adaa9e869d9187bec77ae9f8c8788703ca013ff9bae02b6fdbc02dec0);

    assert_eq!(
        app.native_registry.digest(),
        expected,
        "Native registry digest changed unexpectedly!"
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

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE, 0, 0, 0, 2>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    // Changed when the per-claim bridge stages were added: the nested registry
    // gained one bonding mask per poly-query claim slot
    // (`InternalCircuitIndex::BridgeClaim`), and the `Loading` circuit's final
    // stage moved from `eval` to the last claim-bridge stage. Changed again
    // when challenge stages joined the accumulation: the nested preamble
    // stashes two more commitments per child and the endoscaling point list
    // grew by `2 * NUM_CHALLENGE_SLOTS`. Changed again when the challenge
    // bridge stages landed: one more bonding mask per challenge slot, the eval
    // bridge widened to record them, and `Loading`'s final stage moved from the
    // last claim bridge to the last challenge bridge. Changed again when the
    // `challenge_binding` circuit landed: its rx joins the per-child
    // commitment walk, so `NUM_ENDOSCALING_POINTS` grew by two and the nested
    // preamble stashes one more commitment per child. Changed again when the
    // challenge stages became `RxIndex` variants: the point count is unchanged,
    // but they moved within the per-child block, from after the poly-query
    // claims to inside the `RxIndex::ALL` run. Changed again when the
    // query-slot count went from 4 to 8: four more claim-bridge masks,
    // four more stashed commitments per child, and eight more endoscaling
    // points.
    //
    // Changed again when `derive_challenge` became points-only. A challenge is
    // now hashed from points the step already holds, so nothing about it
    // crosses the curve boundary: the challenge bridge stages and their
    // bonding masks are gone, `Loading`'s final stage moved back from the last
    // challenge bridge to the last claim bridge, the eval and preamble bridges
    // no longer stash challenge-stage commitments, and the endoscaling point
    // list shrank by `2 * NUM_CHALLENGE_SLOTS` per child.
    //
    // Changed again when the slot capacity became per-application: this test
    // application's steps use no slots, so the claim-bridge run is empty, the
    // eval and preamble bridges carry no stashed claims, and the endoscaling
    // point list loses a point per slot per child. See the native digest.
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
    use alloc::{format, string::String, vec::Vec};
    use std::println;

    use ragu_arithmetic::ff::PrimeField;

    let pasta = Pasta::baked();

    let app = ApplicationBuilder::<Pasta, R, HEADER_SIZE, 0, 0, 0, 2>::new()
        .register_dummy_circuits(NUM_APP_STEPS)
        .unwrap()
        .finalize(pasta)
        .unwrap();

    let native_digest = app.native_registry.digest();
    let nested_digest = app.nested_registry.digest();

    // Convert to big-endian hex for repr256! format
    let native_bytes: Vec<u8> = native_digest
        .to_repr()
        .as_ref()
        .iter()
        .rev()
        .cloned()
        .collect();
    let nested_bytes: Vec<u8> = nested_digest
        .to_repr()
        .as_ref()
        .iter()
        .rev()
        .cloned()
        .collect();

    println!("\n// Copy-paste the following into the registry digest tests:");
    println!(
        "    let expected = fp!(0x{});",
        native_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    println!(
        "    let expected = fq!(0x{});",
        nested_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
}

/// The nested chain layout tiles — every stage starts where its predecessor
/// ended — at every capacity.
///
/// The masks cut from it are functions of precisely these offsets, so a chain
/// that stopped tiling would silently misplace every stage after the break.
/// Checked across capacities on purpose: the bug this guards against is
/// geometry that is right at one blessed shape and wrong at every other, which
/// is exactly what asserting against a fixed placeholder could not catch.
///
/// Only the nested chain needs this. The native chain is typed, so
/// [`Stage::skip_gates`](ragu_circuits::staging::Stage::skip_gates) *is*
/// `Parent::skip_gates() + Parent::num_gates()` by definition and tiling is not
/// something it can get wrong.
#[test]
fn nested_chain_layout_tiles_at_every_capacity() {
    use ragu_pasta::Pasta;

    use crate::framework_hooks::{ChallengeLayout, HookLayout, PolyQueryLayout};

    type Host = <Pasta as ragu_arithmetic::Cycle>::HostCurve;

    for polys in [0, 1, 4, 8] {
        let capacity = HookLayout {
            challenge: ChallengeLayout { calls: 1, width: 2 },
            poly_query: PolyQueryLayout { polys, claims: 1 },
        };
        let nested = crate::internal::nested::chain_layout::<Host, R>(capacity);

        for stage in 0..nested.len() {
            assert_eq!(
                nested.skip_gates(stage + 1),
                nested.skip_gates(stage) + nested.num_gates(stage),
                "not contiguous after stage {stage} at polys={polys}"
            );
        }
    }
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

    let chain = crate::internal::nested::chain_layout::<Host, R>(capacity_with_polys(4));

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

/// The branch's acceptance gate: a light application's recursion is
/// **measurably smaller** than a heavy one's.
///
/// Two applications, identical but for what their single step does. The light
/// one witnesses nothing and derives nothing; the heavy one witnesses two
/// polynomials, opens one of them twice, and derives a challenge. Every
/// internal circuit the heavy application registers must be strictly larger,
/// because its capacity is discovered from that step rather than fixed by the
/// framework — which is the whole point of the exercise.
///
/// A framework constant would make these two identical.
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
        // Discovery runs on a structure-only driver, so what matters here is
        // the hook calls, not the values they carry.
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
        // polynomials, which is the split this branch exists for.
        ctx.enforce_poly_query(&handle, zero.clone(), zero.clone())?;
        ctx.enforce_poly_query(&handle, zero.clone(), zero.clone())?;
        ctx.enforce_poly_query(&other, zero.clone(), zero)?;
        ctx.derive_challenge(&[handle.commitment().clone()])?;
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

        // Declared: polynomial slots, claim slots, and the challenge input
        // width. Each application asks for what its own step needs, which is
        // what makes the two shapes differ at all.
        assert_eq!(light.capacity().poly_query.polys, 0);
        assert_eq!(heavy.capacity().poly_query.polys, 2);
        assert_eq!(light.capacity().poly_query.claims, 0);
        assert_eq!(heavy.capacity().poly_query.claims, 3);
        assert_eq!(light.capacity().challenge.width, 2);

        // Discovered: how many challenges a step actually derives. The last
        // axis still folded from the steps rather than declared.
        assert_eq!(light.capacity().challenge.calls, 0);
        assert_eq!(heavy.capacity().challenge.calls, 1);

        // Every internal circuit that reads a child's slots is strictly
        // smaller in the light application. Under a framework constant these
        // would be equal — that equality is exactly what this branch removed.
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
