An extension of the KZG (or Kate) polynomial commitment for multilinear polynomials, space- and time-efficient.

# Background
[[KZG](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf)]
commitments are described here.

We encode a multilinear polynomial as follows.
For an \\(n\\) dimensional multilinear polynomial, let \\(i GG= [b_0, b_1, ... b_n]_2\\). That is,
\\(b_1, b_2 ... b_n\\) is the binary representation of \\(i\\). Then, multiply \\(f_i\\) by the
j'th component of \\(x\\) if and only if \\(b_j\\) is 1.

A verification key takes \\(VK\\) consists of a G1 element \\(G\\), a G2 element \\(H\\),
and an n dimensional vector of G2 elements \\(H_0, H_1, ... H_{n - 1}\\).

- A [`CommitterKeyMulti`](self::CommitterKeyMulti) consists of a sequence
 \\(\vec PK \defeq G \times (1, \tau_0, \tau_1, \tau_0 \times \tau_1 \tau\dots, \prod_j{\tau_j})\\).
   - This is the expansion of an n-dimensional vector \\(\tau\\), where components are multiplied in a way
     mirroring the multilinear expansion described earlier.
- A [`Commitment`](self::EvaluationProofMulti) is a polynomial \\(f(x)\\) is \\(C \defeq \langle \vec f, \vec PK le \\).
- An [`EvaluationProof`](self::EvaluationProof)
for the polynomial \\(f\\)
in the evaluation point \\(\alpha\\)
is a commitment to the repeated division of \\(f(x)\\) by \\((x_i- \alpha_i)\\).
After all \\(n\\) divisions, the remainder is the evaluation \\(f(\alpha)\\).
We refer to the proof as \\(\pi\\).

To verify a proof \\(\pi\\) proving that \\(f(\alpha) = \mu\\), one considers the pairing equation:
\\[
e(C - f(\alpha)G, H) = \sum_i{e(Q_i, H_i - \alpha_i H))}
\\]



# Examples

When creating a new SRS, one will need to specify only the degree of the multilinear polynomial
to commit to.
From the SRS, it is possible to derive the verification key
[`VerifierKeyMulti`](self::VerifierKeyMulti).

```
use ark_gemini::kzg::CommitterKey;
use ark_bls12_381::{ScalarField, Bls12_381};

let rng = &mut ark_std::test_rng();
let degree = 100;

let ck = CommitterKeyMulti::<Bls12_381>::new(degree);
# // XXX. if you change the following lines,
# // please note that documentation below might break.
# let f = vec![ScalarField::from(1u64), ScalarField::from(2u64), ScalarField::from(4u64), ScalarField::from(8u64)];
# let commitment  = ck.commit(&f);
# let alpha = vec![ScalarField::from(42u64), ScalarField::from(43u64)];
# let (evaluation, proof) = ck.open(&f, &alpha);
# use ark_gemini::kzg::VerifierKey;
# let vk = VerifierKey::from(&ck);
# assert!(vk.verify(&commitment, &alpha, &evaluation, &proof).is_ok())
````

Then to commit to a polynomial `f`:
```ignore
let f = vec![ScalarField::from(1u64), ScalarField::from(2u64), ScalarField::from(4u64), ScalarField::from(8u64)];
let commitment  = ck.commit(&f);
```
To prove the evaluation of `f` in a point `alpha`:

```ignore
let alpha = ScalarField::from(42u64);
let (evaluation, proof) = ck.open(&f, &alpha);
```
To veify that an opening is correct:
```ignore
use gemini::kzg::VerifierKey;

let vk = VerifierKey::from(&ck);
assert!(vk.verify(&commitment, &alpha, &evaluation, &proof).is_ok())
```
