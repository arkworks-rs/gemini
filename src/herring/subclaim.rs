use ark_serialize::*;
use ark_std::vec::Vec;

use super::module::BilinearModule;
use super::prover::SumcheckMsg;

/// The subclaim of the sumcheck.
pub struct Subclaim<M: BilinearModule> {
    /// The verifier's challenges \\(\rho_0, \dots, \rho_{n-1}\\)
    pub challenges: Vec<M::ScalarField>,
    /// The subclaim \\(t_0, t_1\\).
    pub final_foldings: Vec<(M::Lhs, M::Rhs)>,
}

/// Messages sent by the prover throughout the protocol.
#[derive(CanonicalSerialize, Clone, Debug, PartialEq, Eq)]
pub struct SumcheckMsgs<M: BilinearModule>(
    pub(crate) Vec<SumcheckMsg<M::Target>>,
    pub(crate) Vec<(M::Lhs, M::Rhs)>,
);
