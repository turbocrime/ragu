//! # `ragu`

#![no_std]
#![allow(clippy::type_complexity)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![doc(html_favicon_url = "https://seanbowe.com/ragu_assets/icons/v1_favicon32.png")]
#![doc(html_logo_url = "https://seanbowe.com/ragu_assets/icons/v1_rustdoc128.png")]

pub extern crate ragu_arithmetic as arithmetic;

pub use ragu_core::*;

/// Traits and utilities for synthesizing arithmetic circuits into polynomials.
pub mod circuits {
    pub use ragu_circuits::*;
}

/// Common low-level gadgets and algorithms.
pub mod primitives {
    pub use ragu_primitives::*;
}
