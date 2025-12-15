# Split-Accumulation Schemes

## IVC Syntax

Imagine proving a blockchain's entire history is valid without replaying every
transaction. Incremental verifiable computation (IVC) and its generalization
proof-carrying data (PCD) enable this: each new proof $\pi_{i+1}$ attests to
the entire computational history, not just the latest step.

The challenge is recursion. Building these proofs requires proving that the
previous proof was valid. If verification is expensive, then proving you
verified becomes prohibitively expensive—a bootstrapping problem that makes
efficient recursion nearly impossible with traditional proof systems.

Accumulation schemes solve this by deferring expensive checks. Instead of fully
verifying each proof during recursion, we partially verify it and accumulate
the remaining work for later batch verification. The per-step overhead becomes
sublinear while the final decider amortizes the accumulated checks across all
steps.

Consider the IVC syntax formalized in
[[BCMS20]](https://eprint.iacr.org/2020/499):

<p align="center">
  <img src="../../../assets/ivc_syntax.svg" alt="ivc_syntax" />
</p>

Picture a step function being a blockchain VM. At each step $i$, given current
state $z_i$ (public instance), new transactions $w_i$ (auxiliary witness/advice),
and proof $\pi_i$ attesting that $z_i$ was honestly derived from genesis, the
IVC prover computes $z_{i+1}$ and produces $\pi_{i+1}$.
This construction has two key properties:

1. **Single proof for entire history**: $\pi_{i+1}$ attests to the entire
   computational history, so the IVC verifier only needs to verify this single
   proof to be convinced of $z_{i+1}$'s validity without enumerating through
   all preceding steps and proofs.

2. **Incremental computation**: Verifying each step as we go avoids constructing
   a giant monolithic proof for the entire computation at once, enabling
   long-running computations.

The simplest IVC construction uses recursive SNARKs. After applying step
function $F$, the SNARK prover proves the relation $\Rel(\inst := (z_{i+1}),
\wit := (z_i, \pi_i))$ such that (1) $F(z_i) = z_{i+1}$; (2)
$\mathsf{SNARK.V}(vk, z_i, \pi_i) = 1$. The prover encodes the SNARK verifier
as part of the circuit, proving both correct state transition and validity of
the previous proof.

One bottleneck of full recursion is that SNARK verifier logic can be expensive.
For example, our Bulletproof verifier is linear, leading to an IVC prover
circuit that's prohibitively expensive to recurse. [Halo](https://eprint.iacr.org/2019/1021)
introduced a technique, later formalized by
[[BCMS20]](https://eprint.iacr.org/2020/499) as _accumulation schemes_, that
replaces full-blown SNARK verification with a sublinear accumulator verifier
who only _partially verifies_ $\pi_i$ and accumulates statements about the
remaining expensive operations into an _accumulator_ $\acc_i$ which will be
batch-checked by a _decider_ down the IVC/PCD tree. Now, the IVC verifier, on
top of verifying the IVC proof $\pi_{i+1}$, will further invoke
$\mathsf{Acc.Decide}(\acc_{i+1})$ subroutine which could contain linear-time
operations—but this is fine since the cost is amortized across all prior steps
and the per-step recursion overhead is massively reduced to sublinear.

Ragu supports **split accumulation**, a variant formalized in
[[BCLMS20]](https://eprint.iacr.org/2020/1618), in which the verifier
$\mathsf{Acc.V}$ checks correct accumulation of _only public instances_, allowing
a potentially non-succinct witness size (usually linear), thus its relaxed
dependency on NARK rather than SNARK. Intuitively, the accumulation prover
partially verifies a new NARK proof $\pi_i$, then folds the remaining unverified
statements with the previously accumulated statement $\acc_i$ into a new
$\acc_{i+1}$ through random linear combination. To enable verification of
correct accumulation by $\mathsf{Acc.V}$, the accumulation prover also includes
all necessary cross terms in $\pf_{i+1}$. Note that accumulation proof
$\pf_{i+1}$ is an internal value consumed by the NARK prover as a subroutine of
the outer IVC prover, not an output of the IVC prover.

The IVC proof becomes $(\acc_i, \pi_i)$, and the relation becomes
$\Rel(\inst := (z_{i+1}, \acc_{i+1}), \wit := (z_i, \pi_i, \acc_i, \pf_{i+1}))$
such that (1) $F(z_i) = z_{i+1}$; (2) $\mathsf{Acc.V}(\acc_i.\inst,
\pi_i.\inst, \pf_{i+1}, \acc_{i+1}.\inst) = 1$. The first ensures the step
function is computed correctly, the second ensures accumulators are updated
correctly.

```admonish tip title="Split-accumulation = Folding"
Later, in [Nova [KS21]](https://eprint.iacr.org/2021/370), a conceptually cleaner
_folding scheme_ is introduced to describe the technique of maximally delaying
NARK verification work and only "fold" the committed public instances of a
running-instance (i.e. accumulator) and the NARK for the last step (i.e.
$\pi_i$). For all practical purposes, these two formalizations are equivalent.
In fact, Ragu also does "pure instance folding" and we subsequently use
"accumulation" and "folding" interchangably.
```

## IVC on Cycles of Curves

> todo: [[NBS]](https://eprint.iacr.org/2023/969) and [[CycleFold]](https://eprint.iacr.org/2023/1192)

## 2-arity PCD
