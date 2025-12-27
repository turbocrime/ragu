use arithmetic::Cycle;
use ragu_circuits::{
    mesh::{CircuitIndex, MeshBuilder},
    polynomials::Rank,
    staging::StageExt,
};
use ragu_core::Result;

pub mod compute_c;
pub mod compute_v;
pub mod dummy;
pub mod fold;
pub mod hashes_1;
pub mod hashes_2;
pub mod stages;
pub mod unified;

pub use crate::components::fold_revdot::NativeParameters;

#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub enum InternalCircuitIndex {
    DummyCircuit = 0,
    Hashes1Staged = 1,
    Hashes1Circuit = 2,
    Hashes2Staged = 3,
    Hashes2Circuit = 4,
    FoldStaged = 5,
    FoldCircuit = 6,
    ComputeCStaged = 7,
    ComputeCCircuit = 8,
    ComputeVStaged = 9,
    ComputeVCircuit = 10,
    PreambleStage = 11,
    ErrorMStage = 12,
    ErrorNStage = 13,
    QueryStage = 14,
    EvalStage = 15,
}

/// The number of internal circuits registered by [`register_all`],
/// and the number of variants in [`InternalCircuitIndex`].
pub const NUM_INTERNAL_CIRCUITS: usize = 16;

/// Compute the total circuit count and log2 domain size from the number of
/// application-defined steps.
pub(crate) fn total_circuit_counts(num_application_steps: usize) -> (usize, u32) {
    let total_circuits =
        num_application_steps + super::step::NUM_INTERNAL_STEPS + NUM_INTERNAL_CIRCUITS;
    let log2_circuits = total_circuits.next_power_of_two().trailing_zeros();
    (total_circuits, log2_circuits)
}

impl InternalCircuitIndex {
    pub fn circuit_index(self, num_application_steps: usize) -> CircuitIndex {
        CircuitIndex::new(num_application_steps + super::step::NUM_INTERNAL_STEPS + self as usize)
    }
}

pub fn register_all<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize>(
    mesh: MeshBuilder<'params, C::CircuitField, R>,
    params: &'params C::Params,
    log2_circuits: u32,
) -> Result<MeshBuilder<'params, C::CircuitField, R>> {
    let initial_num_circuits = mesh.num_circuits();

    let mesh = mesh.register_circuit(dummy::Circuit)?;
    let mesh = {
        let hashes_1 =
            hashes_1::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(params, log2_circuits);
        mesh.register_circuit_object(hashes_1.final_into_object()?)?
            .register_circuit(hashes_1)?
    };
    let mesh = {
        let hashes_2 = hashes_2::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(params);
        mesh.register_circuit_object(hashes_2.final_into_object()?)?
            .register_circuit(hashes_2)?
    };
    let mesh = {
        let fold = fold::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new();
        mesh.register_circuit_object(fold.final_into_object()?)?
            .register_circuit(fold)?
    };
    let mesh = {
        let compute_c = compute_c::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new();
        mesh.register_circuit_object(compute_c.final_into_object()?)?
            .register_circuit(compute_c)?
    };
    let mesh = {
        let compute_v = compute_v::Circuit::<C, R, HEADER_SIZE>::new();
        mesh.register_circuit_object(compute_v.final_into_object()?)?
            .register_circuit(compute_v)?
    };

    let mesh = mesh.register_circuit_object(
        stages::native::preamble::Stage::<C, R, HEADER_SIZE>::into_object()?,
    )?;
    let mesh = mesh.register_circuit_object(stages::native::error_m::Stage::<
        C,
        R,
        HEADER_SIZE,
        NativeParameters,
    >::into_object()?)?;
    let mesh = mesh.register_circuit_object(stages::native::error_n::Stage::<
        C,
        R,
        HEADER_SIZE,
        NativeParameters,
    >::into_object()?)?;
    let mesh = mesh.register_circuit_object(
        stages::native::query::Stage::<C, R, HEADER_SIZE>::into_object()?,
    )?;
    let mesh = mesh.register_circuit_object(
        stages::native::eval::Stage::<C, R, HEADER_SIZE>::into_object()?,
    )?;

    // Verify we registered the expected number of circuits.
    assert_eq!(
        mesh.num_circuits(),
        initial_num_circuits + NUM_INTERNAL_CIRCUITS,
        "internal circuit count mismatch"
    );

    Ok(mesh)
}

#[cfg(test)]
mod test_params {
    use super::*;
    use crate::*;
    use ragu_circuits::polynomials::R;
    use ragu_circuits::staging::{Stage, StageExt};
    use ragu_pasta::Pasta;
    use stages::native::{error_m, error_n, eval, preamble, query};

    // When changing HEADER_SIZE, update the constraint counts by running:
    //   cargo test -p ragu_pcd --release print_internal_circuit -- --nocapture
    // Then copy-paste the output into the check_constraints! calls in the test below.
    const HEADER_SIZE: usize = 38;

    type Preamble = preamble::Stage<Pasta, R<13>, HEADER_SIZE>;
    type ErrorM = error_m::Stage<Pasta, R<13>, HEADER_SIZE, NativeParameters>;
    type ErrorN = error_n::Stage<Pasta, R<13>, HEADER_SIZE, NativeParameters>;
    type Query = query::Stage<Pasta, R<13>, HEADER_SIZE>;
    type Eval = eval::Stage<Pasta, R<13>, HEADER_SIZE>;

    #[rustfmt::skip]
    #[test]
    fn test_internal_circuit_constraint_counts() {
        let pasta = Pasta::baked();

        let app = ApplicationBuilder::<Pasta, R<13>, HEADER_SIZE>::new()
            .finalize(pasta)
            .unwrap();

        let circuits = app.circuit_mesh.circuits();
        const NUM_APP_STEPS: usize = 0;

        macro_rules! check_constraints {
            ($variant:ident, mul = $mul:expr, lin = $lin:expr) => {{
                let idx =
                    NUM_APP_STEPS + step::NUM_INTERNAL_STEPS + InternalCircuitIndex::$variant as usize;
                let circuit = &circuits[idx];
                let (actual_mul, actual_lin) = circuit.constraint_counts();
                assert_eq!(
                    actual_mul,
                    $mul,
                    "{}: multiplication constraints: expected {}, got {}",
                    stringify!($variant),
                    $mul,
                    actual_mul
                );
                assert_eq!(
                    actual_lin,
                    $lin,
                    "{}: linear constraints: expected {}, got {}",
                    stringify!($variant),
                    $lin,
                    actual_lin
                );
            }};
        }

        check_constraints!(DummyCircuit,    mul = 1   , lin = 3);
        check_constraints!(Hashes1Circuit,  mul = 1931, lin = 2800);
        check_constraints!(Hashes2Circuit,  mul = 2048, lin = 2951);
        check_constraints!(FoldCircuit,     mul = 1892, lin = 2649);
        check_constraints!(ComputeCCircuit, mul = 1873, lin = 2610);
        check_constraints!(ComputeVCircuit, mul = 268 , lin = 247);
    }

    #[rustfmt::skip]
    #[test]
    fn test_internal_stage_parameters() {
        macro_rules! check_stage {
            ($Stage:ty, skip = $skip:expr, num = $num:expr) => {{
                assert_eq!(<$Stage>::skip_multiplications(), $skip, "{}: skip", stringify!($Stage));
                assert_eq!(<$Stage as StageExt<_, _>>::num_multiplications(), $num, "{}: num", stringify!($Stage));
            }};
        }

        check_stage!(Preamble, skip =   0, num = 143);
        check_stage!(ErrorM,   skip = 143, num = 270);
        check_stage!(ErrorN,   skip = 413, num = 168);
        check_stage!(Query,    skip = 143, num =   3);
        check_stage!(Eval,     skip = 146, num =   3);
    }

    /// Helper test to print current constraint counts in copy-pasteable format.
    /// Run with: `cargo test -p ragu_pcd --release print_internal_circuit -- --nocapture`
    #[test]
    fn print_internal_circuit_constraint_counts() {
        let pasta = Pasta::baked();

        let app = ApplicationBuilder::<Pasta, R<13>, HEADER_SIZE>::new()
            .finalize(pasta)
            .unwrap();

        let circuits = app.circuit_mesh.circuits();
        const NUM_APP_STEPS: usize = 0;

        let variants = [
            ("DummyCircuit", InternalCircuitIndex::DummyCircuit),
            ("Hashes1Circuit", InternalCircuitIndex::Hashes1Circuit),
            ("Hashes2Circuit", InternalCircuitIndex::Hashes2Circuit),
            ("FoldCircuit", InternalCircuitIndex::FoldCircuit),
            ("ComputeCCircuit", InternalCircuitIndex::ComputeCCircuit),
            ("ComputeVCircuit", InternalCircuitIndex::ComputeVCircuit),
        ];

        println!("\n// Copy-paste the following into test_internal_circuit_constraint_counts:");
        for (name, variant) in variants {
            let idx = NUM_APP_STEPS + step::NUM_INTERNAL_STEPS + variant as usize;
            let circuit = &circuits[idx];
            let (mul, lin) = circuit.constraint_counts();
            println!(
                "        check_constraints!({:<16} mul = {:<4}, lin = {});",
                format!("{},", name),
                mul,
                lin
            );
        }
    }

    /// Helper test to print current stage parameters in copy-pasteable format.
    /// Run with: `cargo test -p ragu_pcd --release print_internal_stage -- --nocapture`
    #[test]
    fn print_internal_stage_parameters() {
        macro_rules! print_stage {
            ($Stage:ty) => {{
                let skip = <$Stage>::skip_multiplications();
                let num = <$Stage as StageExt<_, _>>::num_multiplications();
                println!(
                    "        check_stage!({:<8} skip = {:>3}, num = {:>3});",
                    format!("{},", stringify!($Stage)),
                    skip,
                    num
                );
            }};
        }

        println!("\n// Copy-paste the following into test_internal_stage_parameters:");
        print_stage!(Preamble);
        print_stage!(ErrorM);
        print_stage!(ErrorN);
        print_stage!(Query);
        print_stage!(Eval);
    }
}
