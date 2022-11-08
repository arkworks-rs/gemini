##### Setup
 
$\tau \in \Z_p$, a prime field element, and $G \in \GG_1$ is a generator for affine group $\GG_1$. \
$H$ is a generator for the affine group $\GG_2$. $\GG_1$ and $\GG_2$ are pairing-friendly. \
The commitment key is defined as $ck = \(G, \tau G, \tau^2 G, ..., \tau^{n-1} G \)$. \
The verification key is defined as $vk = \(G, H, \tau H \)$. \
The polynomial $f$ is a vector of coefficients $f(x) = \Sigma_{i=0}^{n-1} f_i \cdot x_i$. \

##### Commitment
The commitment step hides the choice of polynomial using the commitment key $ck$. \
The commitment step returns $C = \Sigma_i f_i \cdot ck_i$.

##### Evaluation

The evaluation step is given the committer key, polynomial, and an evaluation point $\alpha \in \Z_p$. \
It returns the evaluation (output of the polynomial evaluated at $\alpha$) and the proof, a set of quotients. \
Proof quotients $q_i$ are found by dividing $\(x - \alpha\)$ into $f(x)$, such that $f(x) = \Sigma_i q(x) \cdot \(x_i - \alpha\) + r$. \
Thus, the evaluation $f( \alpha ) = r \in \FF_p$. \
The proof is $\Sigma_i q_i \cdot ck_i$.

##### Verification

Verification verifies that the group pairing equation $\epsilon(C - f(\alpha)G, H) = \epsilon(Q, \tau H - \alpha H)$ is true. \
The pairing $\epsilon$ is defined by the user's choice of groups $\GG_1, \GG_2$ and their implied pairing scheme. 

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