#![allow(non_snake_case)]

use ff::Field;
use ragu_pasta::Fp;
use rand::thread_rng;

use crate::{
    CircuitExt, CircuitObject,
    polynomials::{R, Rank},
    test_fixtures::MySimpleCircuit,
};

fn consistency_checks<R: Rank>(circuit: &dyn CircuitObject<Fp, R>) {
    let x = Fp::random(thread_rng());
    let y = Fp::random(thread_rng());
    let k = Fp::random(thread_rng());

    let sxy_eval = circuit.sxy(x, y, k);
    let s0y_eval = circuit.sxy(Fp::ZERO, y, k);
    let sx0_eval = circuit.sxy(x, Fp::ZERO, k);
    let s00_eval = circuit.sxy(Fp::ZERO, Fp::ZERO, k);

    let sxY_poly = circuit.sx(x, k);
    let sXy_poly = circuit.sy(y, k).unstructured();
    let s0Y_poly = circuit.sx(Fp::ZERO, k);
    let sX0_poly = circuit.sy(Fp::ZERO, k).unstructured();

    assert_eq!(sxy_eval, arithmetic::eval(&sXy_poly[..], x));
    assert_eq!(sxy_eval, arithmetic::eval(&sxY_poly[..], y));
    assert_eq!(s0y_eval, arithmetic::eval(&sXy_poly[..], Fp::ZERO));
    assert_eq!(sx0_eval, arithmetic::eval(&sxY_poly[..], Fp::ZERO));
    assert_eq!(s0y_eval, arithmetic::eval(&s0Y_poly[..], y));
    assert_eq!(sx0_eval, arithmetic::eval(&sX0_poly[..], x));
    assert_eq!(s00_eval, arithmetic::eval(&s0Y_poly[..], Fp::ZERO));
    assert_eq!(s00_eval, arithmetic::eval(&sX0_poly[..], Fp::ZERO));
}

#[test]
fn test_simple_circuit() {
    // Simple circuit: prove knowledge of a and b such that a^5 = b^2 and a + b = c
    // and a - b = d where c and d are public inputs.

    let assignment = MySimpleCircuit
        .rx::<MyRank>(
            (
                Fp::from_raw([
                    1833481853729904510,
                    5119040798866070668,
                    13106006979685074791,
                    104139735293675522,
                ]),
                Fp::from_raw([
                    1114250137190507128,
                    15522336584428696251,
                    4689053926428793931,
                    2277752110332726989,
                ]),
            ),
            Fp::ONE,
        )
        .unwrap()
        .0;

    type MyRank = R<5>;
    let circuit = MySimpleCircuit.into_object::<MyRank>().unwrap();

    consistency_checks(&*circuit);

    let y = Fp::random(thread_rng());
    let z = Fp::random(thread_rng());
    let k = Fp::one();

    let a = assignment.clone();
    let mut b = assignment.clone();
    b.dilate(z);
    b.add_assign(&circuit.sy(y, k));
    b.add_assign(&MyRank::tz(z));

    let expected = arithmetic::eval(
        &MySimpleCircuit
            .ky((
                Fp::from_raw([
                    2947731990920411638,
                    2194633309585215303,
                    17795060906113868723,
                    2381891845626402511,
                ]),
                Fp::from_raw([
                    11756763772759733511,
                    10513277942061441772,
                    8416953053256280859,
                    2438073643388336437,
                ]),
            ))
            .unwrap(),
        y,
    );

    let a = a.unstructured();
    let b = b.unstructured();

    assert_eq!(expected, arithmetic::dot(a.iter(), b.iter().rev()),);
}
