# Split-accumulation for Batched Evaluation

## PCS Aggregation

In the [last step](../nark.md#nark) of our NARK, the verifier needs to verify
many polynomial evaluations on different polynomials. Naively running an instance
of [PCS evaluation](../../prelim/bulletproofs.md) protocol for each claim is
expensive. Instead, we use batching techniques to aggregate all evaluation claims
into a single claim that can be verified once. This is sometimes called
_multi-opening_ or _batched opening_ in the literature. Here is how Ragu
aggregates evaluation claims of multiple points on multiple polynomials:

**Input claims**: For each $i$, we have the claim that $p_i(x_i) = y_i$ where

- public instance: $\inst:=(\bar{C}_i\in\G, x_i, y_i\in\F)_i$, the "(commitment,
  evaluation point, evaluation)" tuple held by both the prover and the verifier
- secret witness: $\wit:=(p_i(X)\in\F[X], \gamma_i\in\F)$, the underlying
  polynomial and the blinding factor used for commitment, held by the prover

**Output claim**: A single aggregated claim $p(u)=v$ where

- public instance: $\inst:=(\bar{P}, u, v)\in\G\times\F^2$, held by both
- secret witness: $\wit:=(p(X), \gamma)$, aggregated polynomial and blinding
  factors held by the prover

**Summary**: The key idea is to batch using quotient polynomials. For each
claim $p_i(x_i) = y_i$, the quotient $q_i(X) = \frac{p_i(X) - y_i}{X - x_i}$
exists (with no remainder) if and only if the claim is valid. The protocol
proceeds in three phases:
- _alpha batching_: linearly combines these quotients as 
  $f(X) = \sum_i \alpha^i \cdot q_i(X)$
- _evaluation at u_: the prover evaluates each $p_i$ at a fresh challenge point $u$
- _beta batching_: combines the quotient with the original polynomials as
  $p(X) = f(X) + \sum_i \beta^i \cdot p_i(X)$. The verifier derives the expected
  evaluation from the quotient relation and the $p_i(u)$ values.

The full protocol proceeds as follows:

1. Verifier sends challenge $\alpha \sample \F$
2. Prover computes quotient polynomials $q_i(X) = \frac{p_i(X) - y_i}{X - x_i}$
for each claim. The prover linearly combines them as
$f(X)=\sum_i \alpha^i \cdot q_i(X)$, samples a blinding factor
$\gamma_f\sample\F$, computes the commitment $\bar{F}\leftarrow\com(f(X);\gamma_f)$,
and sends $\bar{F}$ to the verifier
3. Verifier sends challenge $u\sample\F$, which will be the evaluation point for
the aggregated polynomial
4. Prover computes $p_i(u)$ for each $i$ and sends these to the verifier. When
multiple claims share the same underlying polynomial, only one evaluation per
polynomial is needed since $p_i(u)$ depends only on the polynomial, not the
original evaluation point $x_i$.
5. Verifier sends challenge $\beta\sample\F$
6. Prover computes the aggregated polynomial (named `final_poly` by Ragu)
$p(X) = f(X) + \sum_i \beta^i \cdot p_i(X)$ and the aggregated blinding factor
$\gamma = \gamma_f + \sum_i \beta^i \cdot \gamma_i$
7. Verifier derives the aggregated commitment
$\bar{P} = \bar{F} + \sum_i \beta^i \cdot \bar{C}_i$ and the aggregated evaluation
$v=\sum_i \alpha^i\cdot\frac{p_i(u)-y_i}{u-x_i} + \sum_i\beta^i\cdot p_i(u)$,
then outputs $(\bar{P}, u, v)$

The soundness of our aggregation relies on the simple fact that: the quotients
polynomial $q_i(X)=\frac{p_i(X)-y_i}{X-x_i}$ exist (with no remainder) if and
only if the claims $p_i(x_i) = y_i$ are valid. The random linear combination
would preserve this with overwhelming probability, causing the final verification
to fail if any one of the claims is false. The quotient relation is enforced
at step 7 when the verifier derives the $q_i(u)$ from the prover-provided
$p_i(u)$ values through the quotient equation.
