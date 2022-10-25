This module implements multivariate polynomial commitments, while module `kzg` implements the univariate version. \
Like in the univariate version, the notation $\tau \in \Z_p$ is a prime field element and $G \in \GG_1$ is a generator for affine group $\GG_1$. \
$H$ is a generator for the affine group $\GG_2$. $\GG_1$ and $\GG_2$ are pairing-friendly. \
The univariate protocol is edited for commitments to multilinear polynomials $f(x_1, x_2, x_3, ... x_n)$. \
For example, $f(x_1, ... x_n) = f_0 + f_1 \cdot x_1 + f_2 \cdot x_2 + f_3 \cdot x_1 \cdot x_2 + f_4 \cdot x_3 + f_5 \cdot x_3 \cdot x_1 + f_6 \cdot x_3 \cdot x_2 + f_7 \cdot x_3 \cdot x_2 \cdot x_1 + ...$ \
 
##### Setup

$\tau_i \in \Z_p$ are still prime field elements. \
The commitment key is now defined as $ck = \(G, \tau_1 G, \tau_2 G, \tau_1 \tau_2 G, \tau_3 G, \tau_3 \tau_1 G ... \)$. \
The verification key is defined as $vk = \(G, H_0, \tau_1 H_1, \tau_2 H_2, ... \tau_n H_n\)$. \
The polynomial $f$ is a vector of coefficients $f(x) = \Sigma_{i=0}^{n-1} f_i \cdot x_i$. \
Commitment key is represented by struct `CommitterKeyMulti` from which `VerifierKeyMulti` can be produced.

##### Commitment

The commitment step, implemented by `commit`, hides the choice of polynomial using the commitment key $ck$. \
The commitment step again returns $C = \Sigma_i f_i \cdot ck_i$.

##### Evaluation

The evaluation step is given the committer key, polynomial, and an evaluation vector $\hat{\alpha} \in \Z_p$. \
`open` returns the evaluation (output of the polynomial evaluated at $\hat{\alpha}$) and the proof, a set of quotients. \
Proof quotients $Q_i$ are found by dividing $\(x - \alpha\)$ into $f(x)$, such that $f(x) = \Sigma_i q(x) \cdot \(x_i - \alpha\) + r(x)$. \
Thus, the evaluation $f( \alpha ) = r \in \FF_p$. \
The proof is ${ \Sigma_j q_{1,j} \cdot ck_j, ..., \Sigma_j q_{n,j} \cdot ck_j } $.

##### Verification

`verify` verifies that the group pairing equation $\epsilon(C - f(\hat{\alpha})G, H_0) = \Sigma_i \epsilon(Q_i, H_i - \alpha_i H_i)$ is true. 

### Multivariate Batching

If multiple polynomials are to be opened at one evaluation point, `batched_poly` takes a linear combination of the polynomials scaled by powers of a field element challenge, and then `batch_open_multi_polys` actually opens the combined polynomial to one point. \
Say we have a set of $m$ multilinear polynomials of equal degree to evaluate at $\alpha$, $f_i$. The Verifier sends across a challenge field element $c \in \FF_p$. \
Then the scaling vector is computed as $(1, c, c^{2}, c^{3}...)$ and proofs are batched. \
The statement to verify becomes $\Sigma_i (\mu^i \cdot f_i) (\alpha) = \Sigma_i \mu_i \cdot (f_i (\alpha))$. 


# Example Multivariate Protocol Usage
```
use ark_bls12_381::Bls12_381;
use ark_bls12_381::Fr;
use ark_std::UniformRand;
use ark_gemini_polyzygotic::errors::{VerificationError, VerificationResult};
use ark_gemini_polyzygotic::multikzg::{Commitment, VerifierKeyMulti, CommitterKeyMulti};
use ark_gemini_polyzygotic::misc::{evaluate_multi_poly};

let dim = 3;
let rng = &mut ark_std::test_rng();
let ck = CommitterKeyMulti::<Bls12_381>::new(dim, rng);
let vk = VerifierKeyMulti::from(&ck);

let polynomial_flat = (0..1<<dim).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

let alpha = (0..dim).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
let commitment = ck.commit(&polynomial_flat);
let (evaluation, proof) = ck.open(&polynomial_flat, &alpha);
assert!(vk.verify(&commitment, &alpha, &evaluation, &proof).is_ok());
```
See also: Package tests.

