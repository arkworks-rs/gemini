//! The verifier for the algebraic holographicc proofs.
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_std::vec::Vec;
use ark_std::{One, Zero};

use crate::circuit::R1cs;
use crate::errors::{VerificationError, VerificationResult};
use crate::kzg::VerifierKey;
use crate::misc::{evaluate_geometric_poly, evaluate_le, evaluate_tensor_poly};
use crate::misc::{evaluate_index_poly, hadamard, powers, powers2};
use crate::psnark::Proof;
use crate::subprotocols::sumcheck::Subclaim;
use crate::transcript::GeminiTranscript;
use crate::PROTOCOL_NAME;

use super::Index;

/// Given oracle access to a polynomial $f \in \FF[x]$ and a field element $\psi \in \FF$, returns $(f - \psi)(x)$.
/// XXX. use for real
#[allow(unused)]
#[inline]
fn eval_entryprod<F: Field>(oracle: impl FnOnce(F) -> F, psi: F, n: usize) -> impl FnOnce(F) -> F {
    move |x| oracle(x) - psi * evaluate_geometric_poly(x, n)
}

/// Given oracle access to a polynomial $f$, return $xf(x) + 1$.
///
/// This corresponds to the right rotation of the polynomial
/// extended with a leading $1$ on the top.
#[inline]
fn eval_shift<F: Field>(oracle: impl FnOnce(F) -> F) -> impl FnOnce(F) -> F {
    move |x| x * oracle(x) + F::one()
}

/// Given a polynomial oracle, compute the plookup subset evalution using the randomness of the verifier `y, `z`.
///
/// Given oracle access to a polynomial $f$ of degree $n$, return $f(x) + \zeta * [n](x) + y * (1 + x + x^2 + .. + x^{n-1})$.
#[inline]
const fn eval_plookup_subset<F: Field>(
    oracle: impl FnOnce(F) -> F,
    index_oracle: impl Fn(F) -> F,
    y: F,
    zeta: F,
    n: usize,
) -> impl FnOnce(F) -> F {
    move |x| oracle(x) + zeta * index_oracle(x) + y * evaluate_geometric_poly(x, n)
}

fn compute_plookup_subset_eval<F: Field>(
    subset_eval: F,
    index_eval: F,
    eval_point: F,
    y: F,
    _z: F,
    zeta: F,
    n: usize,
) -> F {
    let oracle = |_x| subset_eval;
    let index_oracle = |_x| index_eval;
    eval_shift(eval_plookup_subset(oracle, index_oracle, y, zeta, n))(eval_point)
}

/// Given a polynomial oracle, compute the plookup set evalution using the randomness of the verifier `y, `z`.
/// It would have been nice to have this be a higher level function returning `impl Fn(F) -> impl Fn(F) -> F`
/// and use currying to introduct the randomness, but this is unfortunately not yet supported in the Rust type system.
#[inline]
fn eval_plookup_set<F: Field>(oracle: impl Fn(F) -> F, y: F, z: F, n: usize) -> impl Fn(F) -> F {
    move |x| (F::one() + z) * y * evaluate_geometric_poly(x, n + 1) + (x + z) * oracle(x)
}

fn compute_plookup_set_eval<F: Field>(
    set_eval: F,
    eval_point: F,
    y: F,
    z: F,
    _zeta: F,
    n: usize,
) -> F {
    let oracle = |_x| set_eval;
    eval_shift(eval_plookup_set(oracle, y, z, n))(eval_point)
}

impl<E: Pairing> Proof<E> {
    /// Verification function for Preprocsessing SNARK proof.
    /// The input contains the R1CS instance and the verification key
    /// of polynomial commitment.
    pub fn verify(
        &self,
        r1cs: &R1cs<E::ScalarField>,
        vk: &VerifierKey<E>,
        index: &Index<E>,
        num_non_zero: usize,
    ) -> VerificationResult {
        let mut transcript = merlin::Transcript::new(PROTOCOL_NAME);
        let witness_commitment = self.witness_commitment;

        transcript.append_serializable(b"witness", &witness_commitment);
        transcript.append_serializable(b"ck", &vk.powers_of_g2);
        transcript.append_serializable(b"instance", &index.as_slice());
        let alpha = transcript.get_challenge::<E::ScalarField>(b"alpha");
        transcript.append_serializable(b"zc(alpha)", &self.zc_alpha);

        // Verify the first sumcheck
        let first_sumcheck_msgs = &self.first_sumcheck_msgs;
        let subclaim_1 = Subclaim::new(&mut transcript, first_sumcheck_msgs, self.zc_alpha)?;

        /*
        TODO: num_constraints should be the input.
        */
        // let num_constraints = r1cs.a.len();
        let num_variables = r1cs.z.len();
        self.r_star_commitments
            .iter()
            .zip(vec![b"ra*", b"rb*", b"rc*"].iter())
            .for_each(|(c, s)| transcript.append_serializable(s.as_slice(), c));
        transcript.append_serializable(b"z*", &self.z_star_commitment);

        let eta = transcript.get_challenge::<E::ScalarField>(b"chal");
        let challenges = powers(eta, 3);

        // Verify the second sumcheck
        let asserted_sum_2 = subclaim_1.final_foldings[0][0]
            + subclaim_1.final_foldings[0][1] * challenges[1]
            + self.zc_alpha * challenges[2];

        let subclaim_2 =
            Subclaim::new(&mut transcript, &self.second_sumcheck_msgs, asserted_sum_2)?;

        let zeta = transcript.get_challenge::<E::ScalarField>(b"zeta");

        vec![
            self.sorted_alpha_commitment,
            self.sorted_r_commitment,
            self.sorted_z_commitment,
        ]
        .iter()
        .zip(
            vec![
                "sorted_alpha_commitment",
                "sorted_r_commitment",
                "sorted_z_commitment",
            ]
            .iter(),
        )
        .for_each(|(c, s)| transcript.append_serializable(s.as_bytes(), c));

        let y = transcript.get_challenge::<E::ScalarField>(b"gamma");
        let z = transcript.get_challenge::<E::ScalarField>(b"chi");

        vec![
            self.set_alpha_ep,
            self.subset_alpha_ep,
            self.set_r_ep,
            self.subset_r_ep,
            self.set_z_ep,
            self.subset_z_ep,
        ]
        .iter()
        .zip(
            vec![
                "set_r_ep",
                "subset_r_ep",
                "set_r_ep",
                "subset_r_ep",
                "set_z_ep",
                "subset_z_ep",
            ]
            .iter(),
        )
        .for_each(|(c, s)| transcript.append_serializable(s.as_bytes(), c));

        self.ep_msgs
            .acc_v_commitments
            .iter()
            .for_each(|acc_v_commitment| {
                transcript.append_serializable(b"acc_v", acc_v_commitment)
            });

        let mu = transcript.get_challenge::<E::ScalarField>(b"ep-chal");
        let open_chal = transcript.get_challenge::<E::ScalarField>(b"open-chal");

        let mut commitments = vec![self.r_star_commitments[0]];
        commitments.extend(&self.ep_msgs.acc_v_commitments);

        let evaluations = self
            .ralpha_star_acc_mu_evals
            .iter()
            .map(|e| vec![*e])
            .collect::<Vec<_>>();
        vk.verify_multi_points(
            &commitments,
            &[mu],
            &evaluations[..],
            &self.ralpha_star_acc_mu_proof,
            &open_chal,
        )
        .map_err(|_e| VerificationError)?;

        // transcript.append_serializable(b"r_val_chal_a", &self.rstars_vals[0]);
        // transcript.append_serializable(b"r_val_chal_b", &self.rstars_vals[1]);
        self.ralpha_star_acc_mu_evals
            .iter()
            .for_each(|e| transcript.append_serializable(b"ralpha_star_acc_mu", e));
        transcript.append_serializable(b"ralpha_star_mu_proof", &self.ralpha_star_acc_mu_proof);

        // Verify the third sumcheck
        // TODO: The following should be derived from the evaluations
        let mut asserted_sum_3 = self.ep_msgs.claimed_sumchecks.clone();
        asserted_sum_3.extend(&self.rstars_vals);
        asserted_sum_3.push(
            (subclaim_2.final_foldings[0][1] - self.rstars_vals[0] - self.rstars_vals[1] * eta)
                * eta.square().inverse().unwrap(),
        );
        asserted_sum_3.push(self.ralpha_star_acc_mu_evals[0]);

        let subclaim_3 =
            Subclaim::new_batch(&mut transcript, &self.third_sumcheck_msgs, &asserted_sum_3)?;

        // Consistency check
        let batch_consistency = transcript.get_challenge::<E::ScalarField>(b"batch_challenge");
        self.tensorcheck_proof
            .folded_polynomials_commitments
            .iter()
            .for_each(|c| transcript.append_serializable(b"commitment", c));
        let beta = transcript.get_challenge(b"evaluation-chal");

        // asserted_res_vec
        let mut asserted_res_vec_1 = Vec::new();
        let mut asserted_res_vec_2 = Vec::new();
        for i in 0..9 {
            asserted_res_vec_1.push(subclaim_3.final_foldings[i][0]);
            asserted_res_vec_2.push(subclaim_3.final_foldings[i][1]);
        }
        asserted_res_vec_1.push(subclaim_3.final_foldings[12][0]);

        for i in 9..13 {
            asserted_res_vec_2.push(subclaim_3.final_foldings[i][1]);
        }

        let asserted_res_vec_3 = vec![subclaim_2.final_foldings[0][0]];
        let asserted_res_vec_4 = vec![
            subclaim_3.final_foldings[9][0],
            subclaim_3.final_foldings[10][0],
            subclaim_3.final_foldings[11][0],
        ];

        // base_polynomials_commitments
        let mut base_polynomials_commitments = vec![self.witness_commitment];
        base_polynomials_commitments.extend(self.r_star_commitments);
        base_polynomials_commitments.extend(vec![self.z_star_commitment]);
        base_polynomials_commitments.extend(index);
        base_polynomials_commitments.extend(vec![
            self.sorted_r_commitment,
            self.sorted_alpha_commitment,
            self.sorted_z_commitment,
        ]);

        let mut direct_base_polynomials_evaluations_1 = [E::ScalarField::zero(); 2];
        let mut tmp = E::ScalarField::one();
        for i in 13..22 {
            direct_base_polynomials_evaluations_1[0] +=
                tmp * self.tensorcheck_proof.base_polynomials_evaluations[i][1];
            direct_base_polynomials_evaluations_1[1] +=
                tmp * self.tensorcheck_proof.base_polynomials_evaluations[i][2];
            tmp *= batch_consistency;
        }
        direct_base_polynomials_evaluations_1[0] +=
            tmp * self.tensorcheck_proof.base_polynomials_evaluations[2][1];
        direct_base_polynomials_evaluations_1[1] +=
            tmp * self.tensorcheck_proof.base_polynomials_evaluations[2][2];
        tmp *= batch_consistency;

        // Second
        let mut direct_base_polynomials_evaluations_2 = [E::ScalarField::zero(); 2];
        let mut tmp = E::ScalarField::one();
        let set_len = 1 << subclaim_1.challenges.len();
        // lookup r*
        direct_base_polynomials_evaluations_2[0] += tmp
            * compute_plookup_set_eval(
                evaluate_tensor_poly(&subclaim_1.challenges, beta)
                    + zeta * evaluate_index_poly(beta, set_len),
                beta,
                y,
                z,
                zeta,
                set_len,
            );
        direct_base_polynomials_evaluations_2[1] += tmp
            * compute_plookup_set_eval(
                evaluate_tensor_poly(&subclaim_1.challenges, -beta)
                    + zeta * evaluate_index_poly(-beta, set_len),
                -beta,
                y,
                z,
                zeta,
                set_len,
            );
        tmp *= batch_consistency;

        direct_base_polynomials_evaluations_2[0] += tmp
            * compute_plookup_subset_eval(
                self.tensorcheck_proof.base_polynomials_evaluations[2][1],
                self.tensorcheck_proof.base_polynomials_evaluations[5][1],
                beta,
                y,
                z,
                zeta,
                num_non_zero,
            );
        direct_base_polynomials_evaluations_2[1] += tmp
            * compute_plookup_subset_eval(
                self.tensorcheck_proof.base_polynomials_evaluations[2][2],
                self.tensorcheck_proof.base_polynomials_evaluations[5][2],
                -beta,
                y,
                z,
                zeta,
                num_non_zero,
            );
        tmp *= batch_consistency;

        direct_base_polynomials_evaluations_2[0] += tmp
            * compute_plookup_set_eval(
                self.tensorcheck_proof.base_polynomials_evaluations[10][1],
                beta,
                y,
                z,
                zeta,
                set_len + num_non_zero,
            );
        direct_base_polynomials_evaluations_2[1] += tmp
            * compute_plookup_set_eval(
                self.tensorcheck_proof.base_polynomials_evaluations[10][2],
                -beta,
                y,
                z,
                zeta,
                set_len + num_non_zero,
            );
        tmp *= batch_consistency;

        // lookup alpha*
        direct_base_polynomials_evaluations_2[0] += tmp
            * compute_plookup_set_eval(
                evaluate_geometric_poly(alpha * beta, set_len)
                    + zeta * evaluate_index_poly(beta, set_len),
                beta,
                y,
                z,
                zeta,
                set_len,
            );
        direct_base_polynomials_evaluations_2[1] += tmp
            * compute_plookup_set_eval(
                evaluate_geometric_poly(alpha * -beta, set_len)
                    + zeta * evaluate_index_poly(-beta, set_len),
                -beta,
                y,
                z,
                zeta,
                set_len,
            );
        tmp *= batch_consistency;
        //
        direct_base_polynomials_evaluations_2[0] += tmp
            * compute_plookup_subset_eval(
                self.tensorcheck_proof.base_polynomials_evaluations[3][1],
                self.tensorcheck_proof.base_polynomials_evaluations[5][1],
                beta,
                y,
                z,
                zeta,
                num_non_zero,
            );
        direct_base_polynomials_evaluations_2[1] += tmp
            * compute_plookup_subset_eval(
                self.tensorcheck_proof.base_polynomials_evaluations[3][2],
                self.tensorcheck_proof.base_polynomials_evaluations[5][2],
                -beta,
                y,
                z,
                zeta,
                num_non_zero,
            );
        tmp *= batch_consistency;
        //
        direct_base_polynomials_evaluations_2[0] += tmp
            * compute_plookup_set_eval(
                self.tensorcheck_proof.base_polynomials_evaluations[11][1],
                beta,
                y,
                z,
                zeta,
                set_len + num_non_zero,
            );
        direct_base_polynomials_evaluations_2[1] += tmp
            * compute_plookup_set_eval(
                self.tensorcheck_proof.base_polynomials_evaluations[11][2],
                -beta,
                y,
                z,
                zeta,
                set_len + num_non_zero,
            );
        tmp *= batch_consistency;
        //
        // lookup z*
        let beta_power = E::ScalarField::pow(&beta, &[r1cs.x.len() as u64]);
        let z_pos = evaluate_le(&r1cs.x, &beta)
            + beta_power * self.tensorcheck_proof.base_polynomials_evaluations[0][1];
        let z_neg = if (r1cs.x.len() & 1) == 0 {
            evaluate_le(&r1cs.x, &-beta)
                + beta_power * self.tensorcheck_proof.base_polynomials_evaluations[0][2]
        } else {
            evaluate_le(&r1cs.x, &-beta)
                - beta_power * self.tensorcheck_proof.base_polynomials_evaluations[0][2]
        };
        direct_base_polynomials_evaluations_2[0] += tmp
            * compute_plookup_set_eval(
                z_pos + zeta * evaluate_index_poly(beta, num_variables),
                beta,
                y,
                z,
                zeta,
                num_variables,
            );
        direct_base_polynomials_evaluations_2[1] += tmp
            * compute_plookup_set_eval(
                z_neg + zeta * evaluate_index_poly(-beta, num_variables),
                -beta,
                y,
                z,
                zeta,
                num_variables,
            );
        tmp *= batch_consistency;
        //
        direct_base_polynomials_evaluations_2[0] += tmp
            * compute_plookup_subset_eval(
                self.tensorcheck_proof.base_polynomials_evaluations[4][1],
                self.tensorcheck_proof.base_polynomials_evaluations[6][1],
                beta,
                y,
                z,
                zeta,
                num_non_zero,
            );
        direct_base_polynomials_evaluations_2[1] += tmp
            * compute_plookup_subset_eval(
                self.tensorcheck_proof.base_polynomials_evaluations[4][2],
                self.tensorcheck_proof.base_polynomials_evaluations[6][2],
                -beta,
                y,
                z,
                zeta,
                num_non_zero,
            );
        tmp *= batch_consistency;
        //
        direct_base_polynomials_evaluations_2[0] += tmp
            * compute_plookup_set_eval(
                self.tensorcheck_proof.base_polynomials_evaluations[12][1],
                beta,
                y,
                z,
                zeta,
                num_variables + num_non_zero,
            );
        direct_base_polynomials_evaluations_2[1] += tmp
            * compute_plookup_set_eval(
                self.tensorcheck_proof.base_polynomials_evaluations[12][2],
                -beta,
                y,
                z,
                zeta,
                num_variables + num_non_zero,
            );
        tmp *= batch_consistency;
        //
        // val_a, val_b, val_c, alpha*
        for i in 7..10 {
            direct_base_polynomials_evaluations_2[0] +=
                tmp * self.tensorcheck_proof.base_polynomials_evaluations[i][1];
            direct_base_polynomials_evaluations_2[1] +=
                tmp * self.tensorcheck_proof.base_polynomials_evaluations[i][2];
            tmp *= batch_consistency;
        }
        direct_base_polynomials_evaluations_2[0] +=
            tmp * self.tensorcheck_proof.base_polynomials_evaluations[3][1];
        direct_base_polynomials_evaluations_2[1] +=
            tmp * self.tensorcheck_proof.base_polynomials_evaluations[3][2];
        tmp *= batch_consistency;
        // Third
        let direct_base_polynomials_evaluations_3 = [
            self.tensorcheck_proof.base_polynomials_evaluations[4][1],
            self.tensorcheck_proof.base_polynomials_evaluations[4][2],
        ];
        // // Fourth
        let mut direct_base_polynomials_evaluations_4 = [E::ScalarField::zero(); 2];
        let mut tmp = E::ScalarField::one();
        direct_base_polynomials_evaluations_4[0] +=
            tmp * self.tensorcheck_proof.base_polynomials_evaluations[1][1];
        direct_base_polynomials_evaluations_4[1] +=
            tmp * self.tensorcheck_proof.base_polynomials_evaluations[1][2];
        tmp *= batch_consistency;
        direct_base_polynomials_evaluations_4[0] +=
            tmp * self.tensorcheck_proof.base_polynomials_evaluations[2][1];
        direct_base_polynomials_evaluations_4[1] +=
            tmp * self.tensorcheck_proof.base_polynomials_evaluations[2][2];
        tmp *= batch_consistency;
        direct_base_polynomials_evaluations_4[0] +=
            tmp * self.tensorcheck_proof.base_polynomials_evaluations[3][1];
        direct_base_polynomials_evaluations_4[1] +=
            tmp * self.tensorcheck_proof.base_polynomials_evaluations[3][2];
        tmp *= batch_consistency;

        // base_polynomials_commitments
        let mut base_polynomials_commitments = vec![
            self.witness_commitment,
            self.r_star_commitments[0],
            self.r_star_commitments[1],
            self.r_star_commitments[2],
            self.z_star_commitment,
            index[0],
            index[1],
            index[2],
            index[3],
            index[4],
            self.sorted_r_commitment,
            self.sorted_alpha_commitment,
            self.sorted_z_commitment,
        ];
        base_polynomials_commitments.extend(&self.ep_msgs.acc_v_commitments);

        let mu_powers2 = powers2(mu, subclaim_3.challenges.len());
        let subclaim_3_chal_leading = &subclaim_3.challenges[0..subclaim_2.challenges.len()];
        self.tensorcheck_proof
            .verify(
                &mut transcript,
                vk,
                &[
                    asserted_res_vec_1,
                    asserted_res_vec_2,
                    asserted_res_vec_3,
                    asserted_res_vec_4,
                ],
                &base_polynomials_commitments,
                &[
                    direct_base_polynomials_evaluations_1,
                    direct_base_polynomials_evaluations_2,
                    direct_base_polynomials_evaluations_3,
                    direct_base_polynomials_evaluations_4,
                ],
                &[
                    hadamard(&subclaim_3.challenges, &mu_powers2),
                    subclaim_3.challenges.clone(),
                    subclaim_2.challenges.clone(),
                    hadamard(&subclaim_2.challenges, subclaim_3_chal_leading),
                ],
                beta,
                batch_consistency,
            )
            .map_err(|_| VerificationError)
    }
}
