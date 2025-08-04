use ff::Field;

use ragu_core::drivers::{Coeff, LinearExpression};

pub mod sx;
pub mod sxy;
pub mod sy;

#[derive(Clone)]
enum Wire<F> {
    Value(F),
    One,
}

struct WireSum<F: Field> {
    value: F,
    one: F,
    gain: Coeff<F>,
}

impl<F: Field> WireSum<F> {
    fn new(one: F) -> Self {
        Self {
            value: F::ZERO,
            one,
            gain: Coeff::One,
        }
    }
}

impl<F: Field> LinearExpression<Wire<F>, F> for WireSum<F> {
    fn add_term(mut self, wire: &Wire<F>, coeff: Coeff<F>) -> Self {
        self.value += match wire {
            Wire::Value(v) => *v,
            Wire::One => self.one,
        } * (coeff * self.gain).value();
        self
    }

    fn gain(mut self, coeff: Coeff<F>) -> Self {
        self.gain = self.gain * coeff;
        self
    }
}
