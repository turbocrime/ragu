//! API-level mock of `ragu_pcd`.
//!
//! Enabled by the `mock` feature. Mirrors the shape of the real `ragu_pcd` API
//! so downstream consumers (e.g. Zebra) can integrate against it ahead of the
//! real implementation. The contents are re-exported at the crate root.
//!
//! The mock builds against whichever crypto stack the `modern-deps` (default)
//! or `legacy-deps` feature selects.

pub use application::{Application, ApplicationBuilder};
pub use ctx::StepCtx;
pub use domain::Domain;
pub use header::{Header, Suffix};
pub use hooks::FrameworkHooks;
pub use polynomial::{Polynomial, poly_with_roots};
pub use proof::{Pcd, Proof};
pub use ragu_arithmetic::{Cycle, FixedGenerators};
pub use ragu_core::{Error, Result};
pub use ragu_pasta::{Pasta, VestaGenerators};
pub use sponge::{Sponge, SpongeState};
pub use step::{Index, Step};

pub mod application;
pub mod constraint;
pub mod ctx;
pub mod domain;
pub mod header;
pub mod hooks;
pub mod polynomial;
pub mod proof;
pub mod sponge;
pub mod step;

#[cfg(test)]
mod tests;
