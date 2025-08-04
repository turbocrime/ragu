//! # `ragu_macros`
//!
//! This crate contains some procedural macros for the Ragu project. These
//! macros are re-exported in other crates and so this crate is only intended to
//! be used internally by Ragu.

#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![doc(html_favicon_url = "https://seanbowe.com/ragu_assets/icons/v1_favicon32.png")]
#![doc(html_logo_url = "https://seanbowe.com/ragu_assets/icons/v1_rustdoc128.png")]

use proc_macro::TokenStream;
use syn::{DeriveInput, Error, LitInt, parse_macro_input};

mod gadget;
mod helpers;
mod repr;

// Documentation for the `repr256` macro is in `macro@ragu_arithmetic::repr256`.
#[allow(missing_docs)]
#[proc_macro]
pub fn repr256(input: TokenStream) -> TokenStream {
    repr::evaluate(parse_macro_input!(input as LitInt))
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

// Documentation for the `Gadget` derive macro is in `derive@ragu_core::Gadget`.
#[allow(missing_docs)]
#[proc_macro_derive(Gadget, attributes(ragu))]
pub fn derive_gadget(input: TokenStream) -> TokenStream {
    gadget::derive(parse_macro_input!(input as DeriveInput))
        .unwrap_or_else(Error::into_compile_error)
        .into()
}
