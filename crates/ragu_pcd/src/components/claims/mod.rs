//! Common abstraction for orchestrating revdot claims.

use alloc::{borrow::Cow, vec::Vec};
use ff::PrimeField;
use ragu_circuits::{
    mesh::{CircuitIndex, Mesh},
    polynomials::{Rank, structured},
};

pub mod native;
pub mod nested;

/// Trait for providing claim component values from sources.
///
/// This trait abstracts over what a "source" provides. For polynomial contexts
/// (verify, fuse), it provides polynomial references. For evaluation contexts
/// (compute_v), it provides element evaluation tuples.
///
/// Implementors provide access to rx values for all proofs they manage.
/// The `RxComponent` associated type defines which components can be requested.
pub trait Source {
    /// The type identifying which rx component to retrieve.
    /// For native claims, this is [`native::RxComponent`].
    type RxComponent: Copy;

    /// Opaque type for rx values.
    type Rx;

    /// Type for application circuit identifiers.
    type AppCircuitId;

    /// Get an iterator over rx values for all proofs for the given component.
    fn rx(&self, component: Self::RxComponent) -> impl Iterator<Item = Self::Rx>;

    /// Get an iterator over application circuit info for all proofs.
    fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId>;
}

/// Processor that builds polynomial vectors for revdot claims.
///
/// Accumulates (a, b) polynomial pairs for each claim type, using
/// the mesh polynomial to transform rx polynomials appropriately.
pub struct Builder<'m, 'rx, F: PrimeField, R: Rank> {
    pub(crate) mesh: &'m Mesh<'m, F, R>,
    pub(crate) num_application_steps: usize,
    pub(crate) y: F,
    pub(crate) z: F,
    pub(crate) tz: structured::Polynomial<F, R>,
    /// The accumulated `a` polynomials for revdot claims.
    pub a: Vec<Cow<'rx, structured::Polynomial<F, R>>>,
    /// The accumulated `b` polynomials for revdot claims.
    pub b: Vec<Cow<'rx, structured::Polynomial<F, R>>>,
}

impl<'m, 'rx, F: PrimeField, R: Rank> Builder<'m, 'rx, F, R> {
    /// Create a new claim builder.
    pub fn new(mesh: &'m Mesh<'m, F, R>, num_application_steps: usize, y: F, z: F) -> Self {
        Self {
            mesh,
            num_application_steps,
            y,
            z,
            tz: R::tz(z),
            a: Vec::new(),
            b: Vec::new(),
        }
    }

    fn circuit_impl(
        &mut self,
        circuit_id: CircuitIndex,
        rx: Cow<'rx, structured::Polynomial<F, R>>,
    ) {
        let sy = self.mesh.circuit_y(circuit_id, self.y);
        let mut b = rx.as_ref().clone();
        b.dilate(self.z);
        b.add_assign(&sy);
        b.add_assign(&self.tz);

        self.a.push(rx);
        self.b.push(Cow::Owned(b));
    }
}
