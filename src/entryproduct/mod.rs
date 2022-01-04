//! Implementation of entry product.
//!
//! The entry product argument, also called _grand product argument_ in
//! [plookup](https://eprint.iacr.org/2020/315.pdf),
//! [spartan](https://github.com/microsoft/Spartan),
//! reduces a claim of the form
//! \\[
//! \prod \vec f = t
//! \\]
//! to sumcheck claim of the form:
//!  \langle \vec f + x^N, \rangle
//!
use ark_ec::PairingEngine;

use crate::kzg::Commitment;
use crate::sumcheck::Prover;

mod elastic_prover;
mod time_prover;

pub mod streams;

#[derive(Debug, PartialEq, Eq)]
pub struct ProverMsgs<E: PairingEngine> {
    acc_v_commitments: Vec<Commitment<E>>,
    claimed_sumchecks: Vec<E::Fr>,
}

pub struct EntryProduct<E: PairingEngine, P: Prover<E::Fr>> {
    pub msgs: ProverMsgs<E>,
    pub chal: E::Fr,
    pub provers: Vec<P>,
}
