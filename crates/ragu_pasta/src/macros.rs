/// Creates a raw [`Fp`](pasta_curves::Fp) element from a hex string literal
macro_rules! fp {
    ( $x:expr ) => {
        pasta_curves::Fp::from_raw(arithmetic::repr256!($x))
    };
}

/// Creates a raw [`Fq`](pasta_curves::Fq) element from a hex string literal
macro_rules! fq {
    ( $x:expr ) => {
        pasta_curves::Fq::from_raw(arithmetic::repr256!($x))
    };
}
