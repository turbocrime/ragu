use blake2b_simd::Params;
use ragu_core::{
    Result,
    pasta::{EqAffine, Fp},
};
use udon::{curve::Affine, field::Field};

use super::hooks::FrameworkHooks;

const CHALLENGE_LEN: usize = 64;

/// Framework-side state threaded through
/// [`Step::witness`](crate::Step::witness).
pub struct StepCtx<'a> {
    hooks: &'a mut FrameworkHooks,
}

impl<'a> StepCtx<'a> {
    pub(crate) fn new(hooks: &'a mut FrameworkHooks) -> Self {
        Self { hooks }
    }

    /// Records a polynomial-query opening claim. Errors if `com` is the
    /// identity, which real ragu cannot witness as a commitment `Point`.
    pub fn enforce_poly_query(&mut self, com: EqAffine, x: Fp, y: Fp) -> Result<()> {
        self.hooks.enforce_polynomial_query(com, x, y)
    }

    /// Derives a Fiat-Shamir challenge from `elements` and `points`, each
    /// absorbed separately.
    pub fn derive_challenge(&mut self, elements: &[Fp], points: &[EqAffine]) -> Result<Fp> {
        let mut state = Params::new()
            .hash_length(CHALLENGE_LEN)
            .personal(b"MkRagu_Challng_\0")
            .to_state();

        {
            state.update(b"Fp");
            for fp in elements {
                state.update(fp.to_bytes().as_ref());
            }
        }

        {
            state.update(b"EqAffine");
            for eq in points {
                state.update(eq.to_bytes().as_ref());
            }
        }

        let mut wide = [0u8; CHALLENGE_LEN];
        wide.copy_from_slice(state.finalize().as_bytes());
        Ok(Fp::from_uniform_bytes(&wide))
    }
}
