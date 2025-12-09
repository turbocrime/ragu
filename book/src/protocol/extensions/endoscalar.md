# Endoscalars

Introduced in the Halo protocol, an _endoscalar_ $\endo{s}\in\{0,1\}^\lambda$
is a small binary string used to perform scalar multiplication on curves with
an efficient endomorphism (such as both Pasta curves).
The endoscalar space is smaller than both $\F_p$ and $\F_q$, allowing it to serve
as a _cross-circuit scalar_ that can be efficiently mapped to both target fields.
In `ragu`, we support both `u128` (default) and 136-bit `Uendo` as the
endoscalar type, unified under the `Endoscalar` type.
Endoscalars must support the following operations:

- $\mathsf{extract}(s\in\F)\rightarrow \endo{s}$: deterministically extract a
$\lambda$-bit value from a field element $s\in\F$ where $\log |\F|>\lambda$
- $\mathsf{lift}(\endo{s})\rightarrow s\in\F$: deterministically lift an
endoscalar back to a target field; note that this target field can differ
from the source field from which $\endo{s}$ is extracted, as long as the target
field size is $>2^\lambda$
- $\endo{s}\cdot G\in\G \rightarrow H\in\G$: perform scalar multiplication
on group elements, we call this operation _endoscaling_

The expected properties include:

- pseudorandom extraction: informally, if the original field element is sampled
from a uniform distribution over $\F$ where $|\F|\gg 2^\lambda$, then
the extracted $\endo{s}$ is pseudorandom over $\{0,1\}^\lambda$
- endoscaling consistency: $\endo{s}\cdot G = \mathsf{lift}(\endo{s})\cdot G$
for any $\endo{s}$
- circuit efficiency: all three operations above should be efficient to constrain

Consider a random verifier challenge $\alpha\in\F_p$ produced in a circuit over
$\F_p$ where we want to compute $\alpha\cdot G\in\G_1$.
Any group operations inside an $\F_p$-circuit require expensive non-native arithmetic,
so we prefer deferring this to an $\F_q$-circuit where group elements are natively
represented and arithmetic over coordinates $\in\F_q$ is also native.
We can move $\alpha$ across circuits via an endoscalar:
first, run $\mathsf{extract}$ in the $\F_p$-circuit to obtain the endoscalar as a
public output; then use the same endoscalar as the public input of the
$\F_q$-circuit and constrain $\endo{s}\cdot G$ completely natively.
