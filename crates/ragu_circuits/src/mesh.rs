//! A [`Mesh`] manages multiple circuits over a field, allowing them to share
//! a common domain for efficient polynomial evaluation.

use crate::{
    Circuit, CircuitExt, CircuitObject,
    polynomials::{Rank, structured, unstructured},
};
use ahash::RandomState;
use alloc::{boxed::Box, vec::Vec};
use arithmetic::Domain;
use arithmetic::bitreverse;
use ff::PrimeField;
use hashbrown::HashMap;
use ragu_core::{Error, Result};

/// A collection of circuits over a particular field, some of which may make
/// reference to the others or be executed in similar contexts.
pub struct Mesh<'params, F: PrimeField, R: Rank> {
    domain: Option<Domain<F>>,
    circuits: Vec<Option<Box<dyn CircuitObject<F, R> + 'params>>>,
    max_log2_circuits: u32,
    finalized: bool,
    omega_lsb_lookup: HashMap<u32, usize, RandomState>,
}

impl<'params, F: PrimeField, R: Rank> Mesh<'params, F, R> {
    /// Initialize a new mesh with the supported number of circuits.
    ///
    /// # Panics
    ///
    /// Panics if the provided `log2_circuits` exceeds [`R::RANK`](Rank::RANK).
    pub fn new(max_log2_circuits: u32) -> Self {
        assert!(max_log2_circuits <= R::RANK);

        Self {
            domain: None,
            circuits: Vec::new(),
            max_log2_circuits,
            finalized: false,
            omega_lsb_lookup: HashMap::with_hasher(RandomState::new()),
        }
    }

    /// Returns a reference to the finalized domain.
    ///
    /// # Panics
    /// Panics if the mesh has not been finalized.
    fn domain(&self) -> &Domain<F> {
        self.domain
            .as_ref()
            .expect("mesh must be finalized before use")
    }

    /// Registers a circuit in the mesh.
    pub fn register_circuit<C>(&mut self, circuit: C) -> Result<()>
    where
        C: Circuit<F> + Send + 'params,
    {
        if self.finalized {
            return Err(Error::MeshAlreadyFinalized);
        }

        let id = self.circuits.len();
        if id >= (1 << self.max_log2_circuits) {
            return Err(Error::CircuitBoundExceeded(id));
        }

        self.circuits.push(Some(circuit.into_object()?));

        Ok(())
    }

    /// Determines minimal power-of-2 domain k and maps circuits from maximal domain 2^S to 2^k.
    ///
    /// The domain is "rolling" in the sense that this construction supports incremental
    /// circuit registration into the mesh, without knowing the final domain size k. When `k`
    /// is later determined during finalization, bit-reversal automatically maps each
    /// circuit to its correct position in the finalized domain.
    pub fn finalize(&mut self) -> Result<()> {
        if self.circuits.is_empty() {
            return Err(Error::EmptyCircuitRegisteration);
        }

        if self.finalized {
            return Err(Error::MeshAlreadyFinalized);
        }

        // Compute the smallest power-of-2 domain k that fits all circuits.
        let log2_circuits = self
            .circuits
            .len()
            .next_power_of_two()
            .trailing_zeros()
            .min(self.max_log2_circuits);

        self.domain = Some(Domain::new(log2_circuits));

        let domain_size = 1 << log2_circuits;
        let mut reordered = Vec::with_capacity(domain_size);
        reordered.extend((0..domain_size).map(|_| None));

        let domain_omega = self.domain().omega();

        for (tag, circuit_opt) in self.circuits.iter_mut().enumerate() {
            if let Some(circuit) = circuit_opt.take() {
                // Omega values are precomputed in maximal domain 2^S, independent of final domain 2^k.
                //
                // The key property is circuit synthesis can compute the omega^{i} is for the jth circuit at
                // compile-time as: "omega^i where i = bit_reverse(j, S)". This is a pure function that doesn't
                // rely on a mesh construction.
                //
                // During finalization, when k is determined, the circuit's position becomes:
                // "position = bit_reverse(j, S) >> (S - k)"
                //
                // We perform a mapping to the actual position in the smaller domain, effectively compressing
                // the 2^{max_log2_circuits}-slot domain to 2^{log2_circuits}-slot domain. This means that
                // circuit placement is independent of the initial max_log2_circuits choice.
                let bit_reversal_id = bitreverse(tag.try_into().unwrap(), self.max_log2_circuits);
                let position =
                    (bit_reversal_id >> (self.max_log2_circuits - log2_circuits)) as usize;

                // Builds O(1) omega lookup table.
                let omega_at_position = domain_omega.pow([position as u64]);
                let omega_lsb = Self::field_to_lsb(&omega_at_position);
                self.omega_lsb_lookup.insert(omega_lsb, position);

                // TODO: By virtue of the reindexed vector being typed "Option<Box<_>>", it contains
                // gaps (that can be collapsed) when # circuits < domain size. These are inherently
                // sparse indices right now.

                // Shuffle the circuit by moving each circuit to it's bit-reversed position.
                reordered[position] = Some(circuit);
            }
        }

        self.circuits = reordered;
        self.finalized = true;

        Ok(())
    }

    /// Extracts least signifigant 32 bits of a field element.
    ///
    /// For field elements of order 2^k (omega values), the LSB
    /// uniquely identifies each element.
    fn field_to_lsb(f: &F) -> u32 {
        let bytes = f.to_repr();
        let byte_slice = bytes.as_ref();

        u32::from_le_bytes([byte_slice[0], byte_slice[1], byte_slice[2], byte_slice[3]])
    }

    /// Returns the index of the circuit for the provided omega^{i} value using constant lookup.
    fn get_circuit_from_omega(&self, w: F) -> Option<usize> {
        let w_lsb = Self::field_to_lsb(&w);
        self.omega_lsb_lookup.get(&w_lsb).copied()
    }

    /// Evaluate the mesh polynomial unrestricted at $W$.
    pub fn xy(&self, x: F, y: F) -> unstructured::Polynomial<F, R> {
        let mut coeffs = unstructured::Polynomial::default();
        for (circuit_opt, lc) in self.circuits.iter().zip(coeffs.iter_mut()) {
            if let Some(circuit) = circuit_opt {
                *lc = circuit.sxy(x, y);
            }
        }
        // Convert from the Lagrange basis.
        let domain = self.domain();
        domain.ifft(&mut coeffs[..domain.n()]);

        coeffs
    }

    /// Evaluate the mesh polynomial unrestricted at $X$.
    pub fn wy(&self, w: F, y: F) -> structured::Polynomial<F, R> {
        self.w(
            w,
            structured::Polynomial::default,
            |circuit, circuit_coeff, poly| {
                let mut tmp = circuit.sy(y);
                tmp.scale(circuit_coeff);
                poly.add_assign(&tmp);
            },
        )
    }

    /// Evaluate the mesh polynomial unrestricted at $Y$.
    pub fn wx(&self, w: F, x: F) -> unstructured::Polynomial<F, R> {
        self.w(
            w,
            unstructured::Polynomial::default,
            |circuit, circuit_coeff, poly| {
                let mut tmp = circuit.sx(x);
                tmp.scale(circuit_coeff);
                poly.add_assign(&tmp);
            },
        )
    }

    /// Evaluate the mesh polynomial at the provided point.
    pub fn wxy(&self, w: F, x: F, y: F) -> F {
        self.w(
            w,
            || F::ZERO,
            |circuit, circuit_coeff, poly| {
                *poly += circuit.sxy(x, y) * circuit_coeff;
            },
        )
    }

    /// Computes the polynomial restricted at $W$ based on the provided
    /// closures.
    fn w<T>(
        &self,
        w: F,
        init: impl FnOnce() -> T,
        add_poly: impl Fn(&dyn CircuitObject<F, R>, F, &mut T),
    ) -> T {
        // Compute the Lagrange coefficients for the provided `w`.
        let domain = self.domain.as_ref().unwrap();
        let ell = domain.ell(w, self.circuits.len());

        let mut result = init();

        if let Some(ell) = ell {
            // The provided `w` was not in the domain, and `ell` are the
            // coefficients we need to use to separate each (partial) circuit
            // evaluation.
            for (circuit_opt, circuit_coeff) in self.circuits.iter().zip(ell) {
                if let Some(circuit) = circuit_opt {
                    add_poly(&**circuit, circuit_coeff, &mut result);
                }
            }
        } else if let Some(i) = self.get_circuit_from_omega(w) {
            if let Some(circuit) = &self.circuits[i] {
                add_poly(&**circuit, F::ONE, &mut result);
            }
        } else {
            // In this case, the circuit is not defined and defaults to the zero polynomial.
        }

        result
    }
}

/// Returns the omega value for a given circuit ID on the fly.
pub fn compute_circuit_omega<F: PrimeField>(id: u32, max_log2_circuits: u32) -> F {
    let domain = Domain::<F>::new(max_log2_circuits);

    let bit_reversal_id = bitreverse(id, max_log2_circuits);

    // Compute omega^{bit_reversal_id}.
    domain.omega().pow([bit_reversal_id as u64])
}

#[test]
fn test_mesh_circuit_consistency() {
    use ff::Field;
    use ragu_core::{
        Result,
        drivers::{Driver, DriverValue},
        gadgets::{GadgetKind, Kind},
    };
    use ragu_pasta::Fp;
    use ragu_primitives::Element;
    use rand::thread_rng;

    use crate::polynomials::R;

    struct SquareCircuit {
        times: usize,
    }

    impl Circuit<Fp> for SquareCircuit {
        type Instance<'instance> = Fp;
        type Output = Kind![Fp; Element<'_, _>];
        type Witness<'witness> = Fp;
        type Aux<'witness> = ();

        fn instance<'dr, 'instance: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            instance: DriverValue<D, Self::Instance<'instance>>,
        ) -> Result<<Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>> {
            Element::alloc(dr, instance)
        }

        fn witness<'dr, 'witness: 'dr, D: Driver<'dr, F = Fp>>(
            &self,
            dr: &mut D,
            witness: DriverValue<D, Self::Witness<'witness>>,
        ) -> Result<(
            <Self::Output as GadgetKind<Fp>>::Rebind<'dr, D>,
            DriverValue<D, Self::Aux<'witness>>,
        )> {
            let mut a = Element::alloc(dr, witness)?;

            for _ in 0..self.times {
                a = a.square(dr)?;
            }

            Ok((a, D::just(|| ())))
        }
    }

    type TestRank = R<8>;

    let mut mesh = Mesh::<Fp, TestRank>::new(8);

    mesh.register_circuit(SquareCircuit { times: 2 }).unwrap();
    mesh.register_circuit(SquareCircuit { times: 5 }).unwrap();
    mesh.register_circuit(SquareCircuit { times: 10 }).unwrap();
    mesh.register_circuit(SquareCircuit { times: 11 }).unwrap();
    mesh.register_circuit(SquareCircuit { times: 19 }).unwrap();
    mesh.register_circuit(SquareCircuit { times: 19 }).unwrap();
    mesh.register_circuit(SquareCircuit { times: 19 }).unwrap();
    mesh.register_circuit(SquareCircuit { times: 19 }).unwrap();

    mesh.finalize().unwrap();

    let w = Fp::random(thread_rng());
    let x = Fp::random(thread_rng());
    let y = Fp::random(thread_rng());

    let xy_poly = mesh.xy(x, y);
    let wy_poly = mesh.wy(w, y);
    let wx_poly = mesh.wx(w, x);

    let wxy_value = mesh.wxy(w, x, y);

    assert_eq!(wxy_value, xy_poly.eval(w));
    assert_eq!(wxy_value, wy_poly.eval(x));
    assert_eq!(wxy_value, wx_poly.eval(y));

    let domain = mesh.domain();

    let mut w = Fp::ONE;
    for _ in 0..domain.n() {
        let xy_poly = mesh.xy(x, y);
        let wy_poly = mesh.wy(w, y);
        let wx_poly = mesh.wx(w, x);

        let wxy_value = mesh.wxy(w, x, y);

        assert_eq!(wxy_value, xy_poly.eval(w));
        assert_eq!(wxy_value, wy_poly.eval(x));
        assert_eq!(wxy_value, wx_poly.eval(y));

        w *= domain.omega();
    }
}
