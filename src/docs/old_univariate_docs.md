 The KZG (or Kate) polynomial commitment, space- and time-efficient.
# Background
[[KZG](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf)]
commitments are pretty simple:
- A [`CommitterKey`](self::kzg::CommitterKey) is consists of a sequence $\vec G \defeq (G, \tau G, \dots, \tau^DG)$.
- A [`Commitment`](self::kzg::EvaluationProof) is a polynomial $f(x)$ is $C \defeq \langle \vec f, \vec G \rangle $.
- An [`EvaluationProof`](self::kzg::EvaluationProof)
for the polynomial $f$
in the evaluation point $\alpha$
is a commitment to the quotient of $f(x)$ by $(\tau - \alpha)$.
The remainder is the evaluation $f(\alpha)$.
When evaluation over points $(\alpha_0, \dots, \alpha_m)$,
we can consider at once the quotient of $f(x)$ by $Z$ (the polynomial whose roots are $\alpha_i$).
The remainder is a polynomial $r$ such that $r(\alpha_i) = f(\alpha_i)$.
We refer to the proof as $\pi$.
To verify a proof $\pi$ proving that $f(\alpha) = \mu$, one considers the pairing equation:
\\[
e(C, \tau H - \mu H) = e(f - \mu G, H)
\\]
To verify a proof $\pi$ over a set of points $f(\alpha_i) = \mu_i$,
consider the polynomial $\nu$ such that $\nu(\alpha_i) = \mu_i $, and check:
\\[
e(C, Z) = e(f - \nu, H).
\\]
It is also possible to open multiple polynomials $f_0, \dots, f_n$
 _on the same set of evaluation points_
by asking the verifier a random challenge $\eta$, and opening instead
$\sum_i \eta^i f_i $.
_Nota bene:_ despite it is also possible to open multiple polynomials
over different points [[BDFG20](https://eprint.iacr.org/2020/081.pdf)],
however this is not currently supported by our implementation.


# Examples
When creating a new SRS, one must specify a degree bound `max_degree`
for the commitment polynomials, and a degree bound `max_evals` for
the maximum number of opening points.
From the SRS, it is possible to derive the verification key
[`VerifierKey`](self::kzg::VerifierKey).
```
use ark_gemini::kzg::CommitterKey;
use ark_bls12_381::{Fr, Bls12_381};
let rng = &mut ark_std::test_rng();
let max_degree = 100;
let max_evals = 10;
let ck = CommitterKey::<Bls12_381>::new(max_degree, max_evals, rng);
# // XXX. if you change the following lines,
# // please note that documentation below might break.
# let f = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(4u64), Fr::from(8u64)];
# let commitment  = ck.commit(&f);
# let alpha = Fr::from(42u64);
# let (evaluation, proof) = ck.open(&f, &alpha);
# use ark_gemini::kzg::VerifierKey;
# let vk = VerifierKey::from(&ck);
# assert!(vk.verify(&commitment, &alpha, &evaluation, &proof).is_ok())
````
Then to commit to a polynomial `f`:
```ignore
let f = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(4u64), Fr::from(8u64)];
let commitment  = ck.commit(&f);
```
To prove the evaluation of `f` in a point `alpha`:
```ignore
let alpha = Fr::from(42u64);
let (evaluation, proof) = ck.open(&f, &alpha);
```
To veify that an opening is correct:
```ignore
use gemini::kzg::VerifierKey;
let vk = VerifierKey::from(&ck);
assert!(vk.verify(&commitment, &alpha, &evaluation, &proof).is_ok())
```