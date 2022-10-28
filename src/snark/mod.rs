//! Elastic *non-preprocessing* SNARK for R1CS.
//!
//!
//! # Protocol overview
//! Consider a prover $\prover$ as input a R1CS instance $(A, B, C, \vec x, \vec w)$ of size $N$ and
//! a verifier taking as input a R1CS instance $(A, B, C, \vec x)$.
//! We want to prove that $\vec z \defeq (\vec x, \vec w)$ is such that the R1CS relation is satisfied, i.e.:
//!
//! $$
//! A \vec z \circ B \vec z = C \vec z
//! $$
//!
//! The prover starts the protocol sending $\vec w$, and receiving
//!  $\alpha \in \FF^\times$ from the verifier $\verifier$.
//! $\prover$ constructs the vector $\vec r_C \defeq (1, \alpha, \dots, \alpha^N)$ and sends
//!  $u_2 \defeq Cz \cdot \vec r_C$ to $\verifier$.
//! The prover engages an inner product protocol to prove that;
//!
//! $$
//! \langle Az \circ \vec r_C, Bz \rangle = u_2,
//! $$
//!
//! This is done through the sumcheck protocol.
//! Denote the randomnes with $\rho_0, \dots, \rho_{n-1} \in \FF^\times$, and with
//! $\vec r_B \defeq \otimes_0^{n-1} (1, \rho_j)$.
//! Denote $\vec r_A \defeq \vec r_B \circ \vec r_C$.
//! This produces the following subclaims:
//!
//! $$
//! \begin{aligned}
//! \langle \vec r_A A, \vec z \rangle &= u_0 \\\\
//! \langle \vec r_B B, \vec z \rangle &= u_1 \\\\
//! \langle \vec r_C C, \vec z \rangle &= u_2
//! \end{aligned}
//! $$
//!
//! Which are proven with a second sumcheck: $\verifier$ sends $\eta \in \FF^\times$ and $\prover$
//! engages a second sumcheck for:
//!
//! $$
//! \langle \vec r_A A + \eta  \vec r_B B + \eta^2  \vec r_C C, \vec z \rangle =
//! u_0 + \eta u_1 + \eta^2 u_2.
//! $$
//!
//! producing two subclaims (let $\rho_0', \dots, \rho_{n-1}'$ denote the randomness of this new sumcheck):
//!
//! $$
//! \begin{align}
//! \langle \vec r_A A + \eta  \vec r_B B + \eta^2  \vec r_C C, \otimes_i (1, \rho'_i ) \rangle = s_0 \\\\
//! \langle z, \otimes_i (1, \rho'_i ) \rangle = s_1
//! \end{align}
//! $$
//!
//! Both claims can be checked via the tensorcheck protocol.
//! The evaluations of the base polynomials are generated internally by the verifier, using the R1CS matrices
//! and the statement provided as input.

mod elastic_prover;
mod time_prover;
mod verifier;

/// Utilities for producing streams in SNARK protocol.
mod streams;
#[cfg(test)]
mod tests;

use ark_ec::pairing::Pairing;
use ark_serialize::*;

use crate::kzg::Commitment;
use crate::subprotocols::sumcheck::prover::ProverMsgs;
use crate::subprotocols::tensorcheck::TensorcheckProof;

/// The SNARK proof, composed of all prover's messages sent throughout the protocol.
#[derive(CanonicalSerialize, PartialEq, Eq)]
pub struct Proof<E: Pairing> {
    witness_commitment: Commitment<E>,
    zc_alpha: E::ScalarField,
    first_sumcheck_msgs: ProverMsgs<E::ScalarField>,
    second_sumcheck_msgs: ProverMsgs<E::ScalarField>,
    tensorcheck_proof: TensorcheckProof<E>,
}

impl<E: Pairing> ark_std::fmt::Debug for Proof<E> {
    fn fmt(&self, f: &mut ark_std::fmt::Formatter<'_>) -> ark_std::fmt::Result {
        f.debug_struct("Proof").finish()
    }
}
