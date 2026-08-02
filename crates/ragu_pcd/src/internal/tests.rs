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

/// A stage allocates exactly `Stage::values()` wires.
pub fn assert_stage_values<F, R, S>(stage: &S)
where
    F: PrimeField,
    R: Rank,
    S: Stage<F, R>,
    for<'dr> Bound<'dr, Emulator<Wireless<Empty, F>>, S::OutputKind>:
        Gadget<'dr, Emulator<Wireless<Empty, F>>>,
{
    let mut emulator = Emulator::counter();
    let num_wires = stage
        .witness(&mut emulator, Empty)
        .expect("allocation should succeed")
        .num_wires()
        .expect("wire counting should succeed");
    assert_eq!(
        num_wires,
        S::values(),
        "Stage::values() does not match actual wire count"
    );
}

// When changing HEADER_SIZE, update the constraint counts by running:
//   cargo test -p ragu_pcd --release print_internal_circuit -- --nocapture
// Then copy-paste the output into the check_constraints! calls in the test below.
pub const HEADER_SIZE: usize = 90;

// Number of dummy application circuits to register before testing internal
// circuits. This ensures the tests work correctly even when application
// steps are present.
const NUM_APP_STEPS: usize = 6000;

/// Header size for the slotted shape: kept small so the slot regions, not the
/// header, set the gate counts.
const SLOTTED_HEADER_SIZE: usize = 4;

/// Small step count for the slotted shape, to keep this file's runtime down.
const NUM_SLOTTED_APP_STEPS: usize = 6;

fn dummy_app<
    'params,
    const HDR: usize,
    const POLYS: usize,
    const CLAIMS: usize,
    const CHALLENGES: usize,
>(
    pasta: &'params <Pasta as ragu_arithmetic::Cycle>::Params,
    steps: usize,
) -> crate::Application<'params, Pasta, R, HDR, AppHooks<POLYS, CLAIMS, CHALLENGES, 2>> {
    ApplicationBuilder::<Pasta, R, HDR, AppHooks<POLYS, CLAIMS, CHALLENGES, 2>>::new()
        .register_dummy_circuits(steps)
        .unwrap()
        .finalize(pasta)
        .unwrap()
}

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
    check_constraints!(app, ComputeVCircuit,         mul = 1239, lin = 1819);
    // `ChallengeBinding`'s count includes `OuterError`'s 186 gates: it
    // reaches the challenge slots on the branch below `OuterError`, and a
    // circuit's trace spans every gate up to its last stage, so it pays for
    // the stage it skips on the way.
    check_constraints!(app, ChallengeBindingCircuit, mul =  518, lin =   71);
}

/// The same pins at a shape that *has* slots (two polynomials, three claims,
/// one challenge); a change confined to the slot regions cannot move the
/// no-slot pins in [`test_internal_circuit_constraint_counts`].
#[rustfmt::skip]
#[test]
fn test_slotted_internal_circuit_constraint_counts() {
    let pasta = Pasta::baked();

    let app = dummy_app::<SLOTTED_HEADER_SIZE, 2, 3, 1>(pasta, NUM_SLOTTED_APP_STEPS);

    // All six span the preamble stage, so all six include the coordinate
    // region's wires (two per polynomial slot per child); `OuterCollapse`'s
    // `application_ky` Horner additionally folds them.
    check_constraints!(app, Hashes1Circuit,          mul = 1148, lin = 1834);
    check_constraints!(app, Hashes2Circuit,          mul = 1712, lin = 2951);
    check_constraints!(app, InnerCollapseCircuit,    mul = 1589, lin = 1918);
    check_constraints!(app, OuterCollapseCircuit,    mul =  787, lin = 1098);
    // The two that read the slot regions, and the reason this shape is pinned
    // at all. `ComputeV` carries the per-claim one-hot resolution and the
    // per-child q(u) re-derivation from the coordinate instance wires, so it
    // moves whenever those do; an application that derives a challenge gives
    // `ChallengeBinding` one to bind.
    check_constraints!(app, ComputeVCircuit,         mul = 1078, lin = 2007);
    check_constraints!(app, ChallengeBindingCircuit, mul =  855, lin = 1225);
}

/// Prints the constraint counts the pin tests expect, for re-pinning.
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
/// slots.
mod pinned_chain {
    use super::{HEADER_SIZE, R};
    use crate::{AppHooks, internal::native::chain};

    pub type Preamble = chain::Preamble<ragu_pasta::Pasta, R, HEADER_SIZE, AppHooks<8, 1, 1, 2>>;
    pub type OuterError =
        chain::OuterError<ragu_pasta::Pasta, R, HEADER_SIZE, AppHooks<8, 1, 1, 2>>;
    pub type InnerError =
        chain::InnerError<ragu_pasta::Pasta, R, HEADER_SIZE, AppHooks<8, 1, 1, 2>>;
    pub type Query = chain::Query<ragu_pasta::Pasta, R, HEADER_SIZE, AppHooks<8, 1, 1, 2>>;
    pub type Eval = chain::Eval<ragu_pasta::Pasta, R, HEADER_SIZE, AppHooks<8, 1, 1, 2>>;
    pub type Challenges =
        chain::Challenges<ragu_pasta::Pasta, R, HEADER_SIZE, AppHooks<8, 1, 1, 2>>;
}

/// Pins the native stages' gate geometry at a stated slot count.
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

    check_stage!(pinned_chain::Preamble,   "Preamble",   skip =   1, num = 320);
    check_stage!(pinned_chain::OuterError, "OuterError", skip = 321, num = 186);
    check_stage!(pinned_chain::InnerError, "InnerError", skip = 507, num = 399);
    check_stage!(pinned_chain::Query,      "Query",      skip = 321, num =  27);
    check_stage!(pinned_chain::Eval,       "Eval",       skip = 348, num =  29);
    // A sibling of InnerError, not a successor: both start where OuterError
    // ends, so a circuit reaching the challenge slots is not charged for
    // InnerError's gates.
    check_stage!(pinned_chain::Challenges, "Challenges", skip = 507, num =   3);
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

/// The nested stage types `test_nested_stage_parameters` pins, at eight
/// polynomial slots.
mod pinned_nested_chain {
    use ragu_primitives::vec::ConstLen;

    use super::R;
    use crate::internal::{
        endoscalar,
        nested::{EndoPoints, stages},
    };

    type Host = <ragu_pasta::Pasta as ragu_arithmetic::Cycle>::HostCurve;
    type L = ConstLen<8>;

    pub type Endoscalar = endoscalar::EndoscalarStage;
    pub type Points = endoscalar::PointsStage<Host, EndoPoints<L>>;
    pub type Preamble = stages::preamble::Stage<Host, R, L>;
    pub type SPrime = stages::s_prime::Stage<Host, R, L>;
    pub type InnerError = stages::inner_error::Stage<Host, R, L>;
    pub type OuterError = stages::outer_error::Stage<Host, R, L>;
    pub type Ab = stages::ab::Stage<Host, R, L>;
    pub type Query = stages::query::Stage<Host, R, L>;
    pub type F = stages::f::Stage<Host, R, L>;
    pub type Eval = stages::eval::Stage<Host, R, L>;
}

/// Pins the nested chain's gate geometry at a stated slot count.
#[rustfmt::skip]
#[test]
fn test_nested_stage_parameters() {
    use ragu_circuits::staging::StageExt;

    macro_rules! check_stage {
        ($stage:ty, $name:literal, skip = $skip:expr, num = $num:expr) => {{
            assert_eq!(<$stage as Stage<ragu_pasta::Fq, R>>::skip_gates(), $skip, "{}: skip", $name);
            assert_eq!(<$stage as StageExt<ragu_pasta::Fq, R>>::num_gates(), $num, "{}: num", $name);
        }};
    }

    check_stage!(pinned_nested_chain::Endoscalar, "Endoscalar", skip =   1, num =  64);
    check_stage!(pinned_nested_chain::Points,     "Points",     skip =  65, num =  74);
    check_stage!(pinned_nested_chain::Preamble,   "Preamble",   skip = 139, num =  53);
    check_stage!(pinned_nested_chain::SPrime,     "SPrime",     skip = 192, num =   3);
    check_stage!(pinned_nested_chain::InnerError, "InnerError", skip = 195, num =   2);
    check_stage!(pinned_nested_chain::OuterError, "OuterError", skip = 197, num =   1);
    check_stage!(pinned_nested_chain::Ab,         "Ab",         skip = 198, num =   2);
    check_stage!(pinned_nested_chain::Query,      "Query",      skip = 200, num =   2);
    check_stage!(pinned_nested_chain::F,          "F",          skip = 202, num =   1);
    check_stage!(pinned_nested_chain::Eval,       "Eval",       skip = 203, num =   9);
}

/// Run with: `cargo test -p ragu_pcd --release print_nested_stage -- --nocapture`
#[test]
fn print_nested_stage_parameters() {
    use std::println;

    use ragu_circuits::staging::StageExt as _;

    fn line<S: ragu_circuits::staging::Stage<ragu_pasta::Fq, R>>(name: &str) {
        println!(
            "    check_stage!(pinned_nested_chain::{:<12} {:<13} skip = {:>3}, num = {:>3});",
            alloc::format!("{name},"),
            alloc::format!("\"{name}\","),
            S::skip_gates(),
            S::num_gates()
        );
    }

    println!("\n// Copy-paste the following into test_nested_stage_parameters:");
    line::<pinned_nested_chain::Endoscalar>("Endoscalar");
    line::<pinned_nested_chain::Points>("Points");
    line::<pinned_nested_chain::Preamble>("Preamble");
    line::<pinned_nested_chain::SPrime>("SPrime");
    line::<pinned_nested_chain::InnerError>("InnerError");
    line::<pinned_nested_chain::OuterError>("OuterError");
    line::<pinned_nested_chain::Ab>("Ab");
    line::<pinned_nested_chain::Query>("Query");
    line::<pinned_nested_chain::F>("F");
    line::<pinned_nested_chain::Eval>("Eval");
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

    // At `POLYS = 0, CLAIMS = 0, CHALLENGES = 0` every slot-dependent width
    // collapses.
    let expected = fp!(0x2bb64a4adaa9e869d9187bec77ae9f8c8788703ca013ff9bae02b6fdbc02dec0);

    assert_eq!(
        app.native_registry.digest(),
        expected,
        "Native registry digest changed unexpectedly!"
    );
}

/// Pins both registry digests for an application that *has* slots (two
/// polynomials, three claims, one challenge). The no-slot digest pins cannot
/// see a change confined to the slot regions.
#[test]
fn test_slotted_registry_digests() {
    let pasta = Pasta::baked();

    let app = dummy_app::<SLOTTED_HEADER_SIZE, 2, 3, 1>(pasta, NUM_SLOTTED_APP_STEPS);

    // Covers the limb machinery: per-child q(u) in the eval stage and
    // `compute_v`'s re-derivation from the coordinate instance wires.
    assert_eq!(
        app.native_registry.digest(),
        fp!(0x325fdfbe3950edd8fcddb1fcc2f2993378ff5a13f36b2be2d48babc94f48d05f),
        "Native registry digest changed unexpectedly at a slotted shape!"
    );
    // Covers the nested side: stashed claim host commitments, `C_q`, the eval
    // stage's claim slots, and the endoscaling growth.
    assert_eq!(
        app.nested_registry.digest(),
        fq!(0x04dd2f0651e20dd6aed682818e4b40e1f54c80f7fab5149395f3ec45de9b9340),
        "Nested registry digest changed unexpectedly at a slotted shape!"
    );
}

/// Pins the nested registry digest at the no-slot shape.
#[test]
fn test_nested_registry_digest() {
    let pasta = Pasta::baked();

    let app = dummy_app::<HEADER_SIZE, 0, 0, 0>(pasta, NUM_APP_STEPS);

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

/// [`EndoPoints`] matches the accumulation walk. The expected side is spelled
/// out longhand so this is not `x == x`.
#[test]
fn endoscaling_points_len_matches_the_accumulation_walk() {
    use ragu_primitives::vec::{ConstLen, Len};

    use crate::internal::{
        native::{RxIndex, stages::eval::CURRENT_STEP_COMPONENTS},
        nested::EndoPoints,
    };

    fn check<const POLYS: usize>() {
        let q = if POLYS == 0 { 0 } else { 1 };
        let longhand = 1 + 2 * (RxIndex::NUM + 4 + POLYS + q) + CURRENT_STEP_COMPONENTS;

        assert_eq!(
            EndoPoints::<ConstLen<POLYS>>::len(),
            longhand,
            "the point count drifted at polys={POLYS}"
        );
    }

    check::<0>();
    check::<1>();
    check::<4>();
    check::<8>();
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

/// Two applications identical but for the capacity they declare: every
/// internal circuit the heavy one registers is strictly larger. Capacity is
/// the application's own declaration, not a framework constant.
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
        framework_hooks::HookLayout,
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
        // Only ever registered, never proved: the hook calls matter, not the
        // values they carry.
        let commitment = D::try_just(|| {
            Err::<crate::poly_commitment::PolyCommitment<Pasta>, _>(Error::InvalidWitness(
                "the capacity test never builds a proof".into(),
            ))
        })?;
        // Both polynomials in one call: slot 0 is `handle`, slot 1 is `other`.
        let [handle, other] = ctx.witness_polynomial([Maybe::clone(&commitment), commitment])?;
        let zero = Element::alloc(ctx.dr, &mut Standard::new(), D::just(|| Fp::ZERO))?;
        // Three claims over two polynomials.
        ctx.enforce_poly_query(&handle, zero.clone(), zero.clone())?;
        ctx.enforce_poly_query(&handle, zero.clone(), zero.clone())?;
        ctx.enforce_poly_query(&other, zero.clone(), zero)?;
        ctx.derive_challenge(Pasta::baked(), &handle)?;
    });

    fn gates<J: crate::framework_hooks::HookConfig>(
        app: &Application<'_, Pasta, R, HS, J>,
        id: InternalCircuitIndex,
    ) -> usize {
        app.native_registry.constraint_counts(id.circuit_index()).0
    }

    #[test]
    fn a_light_application_pays_less_than_a_heavy_one() {
        let pasta = Pasta::baked();
        let light = ApplicationBuilder::<Pasta, R, HS, NoHooks>::new()
            .register(Light)
            .unwrap()
            .finalize(pasta)
            .unwrap();
        let heavy = ApplicationBuilder::<Pasta, R, HS, AppHooks<2, 3, 1, 2>>::new()
            .register(Heavy)
            .unwrap()
            .finalize(pasta)
            .unwrap();

        // `<2, 3, 1, 2>` is four distinct values, so a `capacity()` that
        // crossed two axes fails here rather than downstream.
        assert_eq!(
            light.hook_layout(),
            HookLayout {
                challenge_calls: 0,
                challenge_width: 0,
                polys: 0,
                claims: 0,
            }
        );
        assert_eq!(
            heavy.hook_layout(),
            HookLayout {
                challenge_calls: 1,
                challenge_width: 2,
                polys: 2,
                claims: 3,
            }
        );

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

        // The *2 margin: a step that derives no challenge pays nothing to bind one.
        assert!(
            gates(&light, InternalCircuitIndex::ChallengeBindingCircuit) * 2
                < gates(&heavy, InternalCircuitIndex::ChallengeBindingCircuit),
            "light {} vs heavy {}",
            gates(&light, InternalCircuitIndex::ChallengeBindingCircuit),
            gates(&heavy, InternalCircuitIndex::ChallengeBindingCircuit),
        );
    }
}
