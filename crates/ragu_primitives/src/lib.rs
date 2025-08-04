//! # `ragu_primitives`
//!
//! This crate contains low level gadgets and algorithms for the Ragu project.
//! This API is re-exported (as necessary) in other crates and so this crate is
//! only intended to be used internally by Ragu.

#![no_std]
#![allow(clippy::type_complexity)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![doc(html_favicon_url = "https://seanbowe.com/ragu_assets/icons/v1_favicon32.png")]
#![doc(html_logo_url = "https://seanbowe.com/ragu_assets/icons/v1_rustdoc128.png")]

extern crate alloc;
extern crate ragu_core as ragu;

mod boolean;
pub mod demoted;
mod element;
mod endoscalar;
pub mod fixedvec;
mod foreign;
mod lazy;
mod point;
mod poseidon;
pub mod serialize;
mod util;

pub use boolean::{Boolean, multipack};
pub use element::{Element, multiadd};
pub use endoscalar::Endoscalar;
pub use lazy::Lazy;
pub use point::Point;
pub use poseidon::Sponge;
