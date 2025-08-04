use proc_macro2::TokenTree;
use syn::{
    Attribute, GenericArgument, GenericParam, Ident, Meta, PathArguments, Type, TypeParam,
    TypeParamBound, TypePath, parse_quote,
};

pub fn attr_is(attr: &Attribute, needle: &str) -> bool {
    if !attr.path().is_ident("ragu") {
        return false;
    }
    match &attr.meta {
        Meta::List(list) => list.tokens.clone().into_iter().any(|tt| match tt {
            TokenTree::Ident(ref ident) => ident == needle,
            _ => false,
        }),
        _ => false,
    }
}

#[test]
fn test_attr_is() {
    let attr: Attribute = parse_quote!(#[ragu(driver)]);
    assert!(attr_is(&attr, "driver"));
    assert!(!attr_is(&attr, "not_driver"));

    let attr: Attribute = parse_quote!(#[ragu(not_driver)]);
    assert!(!attr_is(&attr, "driver"));
    assert!(attr_is(&attr, "not_driver"));

    let attr: Attribute = parse_quote!(#[ragu]);
    assert!(!attr_is(&attr, "driver"));

    let attr: Attribute = parse_quote!(#[not_ragu(driver)]);
    assert!(!attr_is(&attr, "driver"));
}

pub trait Substitution {
    fn substitute(&mut self, driver_id: &Ident, driverfield_ident: &Ident);
}

impl Substitution for TypePath {
    fn substitute(&mut self, driver_id: &Ident, driverfield_ident: &Ident) {
        if self.qself.is_none() && self.path.segments.len() == 2 {
            let segs = &self.path.segments;
            if segs[0].ident == *driver_id && segs[1].ident == "F" {
                *self = parse_quote!(#driverfield_ident);
                return;
            }
        }

        for seg in &mut self.path.segments {
            if let PathArguments::AngleBracketed(ab) = &mut seg.arguments {
                for arg in ab.args.iter_mut() {
                    match arg {
                        GenericArgument::Type(t) => {
                            t.substitute(driver_id, driverfield_ident);
                        }
                        GenericArgument::Constraint(constraint) => {
                            constraint.bounds.iter_mut().for_each(|bound| {
                                bound.substitute(driver_id, driverfield_ident);
                            });
                        }
                        GenericArgument::AssocType(assoc_type) => {
                            assoc_type.ty.substitute(driver_id, driverfield_ident);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

impl Substitution for Type {
    fn substitute(&mut self, driver_id: &Ident, driverfield_ident: &Ident) {
        match self {
            Type::Path(type_path) => {
                type_path.substitute(driver_id, driverfield_ident);
            }
            Type::Tuple(tuple) => {
                for elem in &mut tuple.elems {
                    elem.substitute(driver_id, driverfield_ident);
                }
            }
            _ => {}
        }
    }
}

impl Substitution for TypeParamBound {
    fn substitute(&mut self, driver_id: &Ident, driverfield_ident: &Ident) {
        if let TypeParamBound::Trait(trait_bound) = self {
            for seg in &mut trait_bound.path.segments {
                if let syn::PathArguments::AngleBracketed(ab) = &mut seg.arguments {
                    for arg in ab.args.iter_mut() {
                        match arg {
                            GenericArgument::Type(t) => {
                                t.substitute(driver_id, driverfield_ident);
                            }
                            GenericArgument::Constraint(constraint) => {
                                constraint.bounds.iter_mut().for_each(|b| {
                                    b.substitute(driver_id, driverfield_ident);
                                });
                            }
                            GenericArgument::AssocType(assoc_type) => {
                                assoc_type.ty.substitute(driver_id, driverfield_ident);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }
}

pub fn replace_driver_field_in_generic_param(
    param: &mut syn::GenericParam,
    driver_id: &syn::Ident,
    driverfield_ident: &syn::Ident,
) {
    if let GenericParam::Type(TypeParam {
        bounds, default, ..
    }) = param
    {
        for bound in bounds.iter_mut() {
            bound.substitute(driver_id, driverfield_ident);
        }
        if let Some(default_ty) = default {
            default_ty.substitute(driver_id, driverfield_ident);
        }
    }
}
