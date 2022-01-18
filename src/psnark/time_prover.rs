/// Time-efficient preprocessing SNARK for R1CS.
use ark_ec::PairingEngine;
use ark_ff::Field;
use ark_std::{One, Zero};

use crate::circuit::R1cs;
use crate::entryproduct::EntryProduct;
use crate::kzg::CommitterKey;
use crate::misc::{
    evaluate_le, hadamard, joint_matrices, linear_combination, powers, powers2,
    product_matrix_vector, scalar_prod, sum_matrices, tensor,
};
use crate::sumcheck::{proof::Sumcheck, time_prover::TimeProver, time_prover::Witness};
use crate::tensorcheck::TensorcheckProof;
use crate::transcript::GeminiTranscript;

use crate::PROTOCOL_NAME;

use super::Proof;

#[inline]
fn lookup<T: Copy>(v: &[T], index: &Vec<usize>) -> Vec<T> {
    index.iter().map(|&i| v[i]).collect()
}

#[inline]
fn compute_lookup_vector_with_shift<F: Field>(v: &Vec<F>, gamma: F, chi: F, zeta: F) -> Vec<F> {
    let mut res = Vec::new();
    let tmp = (F::one() + chi) * gamma;
    let mut prev = *v.last().unwrap() + zeta * F::from(v.len() as u64);
    v.iter().enumerate().for_each(|(i, e)| {
        let curr = *e + zeta * F::from(i as u64);
        res.push(tmp + curr + chi * prev);
        prev = curr
    });
    res
}

#[inline]
fn plookup<F: Field>(
    subset: &Vec<F>,
    set: &Vec<F>,
    index_f: &Vec<F>,
    index: &Vec<usize>,
    gamma: F,
    chi: F,
    zeta: F,
) -> (Vec<Vec<F>>, Vec<Vec<F>>, F, F, F, Vec<F>) {
    let mut lookup_vec = Vec::new();
    let mut accumulated_vec = Vec::new();

    // Compute the lookup vector for the subset
    let mut lookup_subset = Vec::new();
    let mut accumulated_subset = Vec::new();
    let mut tmp = F::one();
    subset.iter().zip(index_f.iter()).for_each(|(e, f)| {
        let x = *e + zeta * f + gamma;
        lookup_subset.push(x);
        tmp *= x;
        accumulated_subset.push(tmp)
    });
    let lookup_subset_prod = *accumulated_subset.last().unwrap();
    lookup_vec.push(lookup_subset);
    accumulated_vec.push(accumulated_subset);

    // Compute the lookup vector for the set
    let lookup_set = compute_lookup_vector_with_shift(&set, gamma, chi, zeta);
    let mut accumulated_set = Vec::new();
    let mut tmp = F::one();
    lookup_set.iter().for_each(|x| {
        tmp *= x;
        accumulated_set.push(tmp)
    });
    let lookup_set_prod = *accumulated_set.last().unwrap();
    lookup_vec.push(lookup_set);
    accumulated_vec.push(accumulated_set);

    // Compute the sorted vector
    let mut frequency = vec![1; set.len()];
    index.iter().for_each(|i| frequency[*i] += 1);
    let mut sorted = Vec::new();
    frequency
        .iter()
        .zip(set.iter())
        .for_each(|(f, e)| sorted.append(&mut vec![*e; *f]));

    // Compute the lookup vector for the sorted vector
    let lookup_sorted = compute_lookup_vector_with_shift(&sorted, gamma, chi, zeta);
    let mut accumulated_sorted = Vec::new();
    let mut tmp = F::one();
    lookup_sorted.iter().for_each(|x| {
        tmp *= x;
        accumulated_sorted.push(tmp)
    });
    let lookup_sorted_prod = *lookup_sorted.last().unwrap();
    lookup_vec.push(lookup_sorted);
    accumulated_vec.push(accumulated_sorted);

    (
        lookup_vec,
        accumulated_vec,
        lookup_subset_prod,
        lookup_set_prod,
        lookup_sorted_prod,
        sorted,
    )
}

impl<E: PairingEngine> Proof<E> {
    /// Given as input the R1CS instance `r1cs`
    /// and the committer key `ck`,
    /// return a new _preprocessing_ SNARK using the elastic prover.
    pub fn new_time(r1cs: &R1cs<E::Fr>, ck: &CommitterKey<E>) -> Proof<E> {
        let z_a = product_matrix_vector(&r1cs.a, &r1cs.z);
        let z_b = product_matrix_vector(&r1cs.b, &r1cs.z);
        let z_c = product_matrix_vector(&r1cs.c, &r1cs.z);

        let mut transcript = merlin::Transcript::new(PROTOCOL_NAME);
        let witness_commitment_time = start_timer!(|| "Commitment to w");
        let witness_commitment = ck.commit(&r1cs.w);
        end_timer!(witness_commitment_time);

        transcript.append_commitment(b"witness", &witness_commitment);
        let alpha = transcript.get_challenge(b"alpha");

        let zc_alpha = evaluate_le(&z_c, &alpha);
        transcript.append_scalar(b"zc(alpha)", &zc_alpha);

        let first_sumcheck_time = start_timer!(|| "First sumcheck");
        let first_proof = Sumcheck::new_time(&mut transcript, &z_a, &z_b, &alpha);
        end_timer!(first_sumcheck_time);

        let b_challenges = tensor(&first_proof.challenges);
        let c_challenges = powers(alpha, b_challenges.len());
        let a_challenges = hadamard(&b_challenges, &c_challenges);

        let joint_matrix = sum_matrices(&r1cs.a, &r1cs.b, &r1cs.c);
        let (row, col, row_index, col_index, val_a, val_b, val_c) =
            joint_matrices(&joint_matrix, &r1cs.a, &r1cs.b, &r1cs.c);

        let r_a_star = lookup(&a_challenges, &row_index);
        let r_b_star = lookup(&b_challenges, &row_index);
        let r_c_star = lookup(&c_challenges, &row_index);
        let z_star = lookup(&r1cs.z, &col_index);

        let z_r_commitments_time = start_timer!(|| "Commitments to z* and r*");
        let z_r_commitments = ck.batch_commit(vec![&r_a_star, &r_b_star, &r_c_star, &z_star]);
        end_timer!(z_r_commitments_time);

        z_r_commitments
            .iter()
            .for_each(|c| transcript.append_commitment(b"commitment", c));

        let eta = transcript.get_challenge::<E::Fr>(b"eta");
        let eta2 = eta.square();

        let r_star_val = linear_combination(
            &[
                hadamard(&r_a_star, &val_a),
                hadamard(&r_b_star, &val_b),
                hadamard(&r_c_star, &val_c),
            ],
            &[E::Fr::one(), eta, eta2],
        )
        .unwrap();

        let second_sumcheck_time = start_timer!(|| "Second sumcheck");
        let second_proof = Sumcheck::new_time(&mut transcript, &z_star, &r_star_val, &E::Fr::one());
        let second_challenges = tensor(&second_proof.challenges);
        end_timer!(second_sumcheck_time);

        let gamma = transcript.get_challenge(b"gamma");
        let chi = transcript.get_challenge(b"chi");
        let zeta = transcript.get_challenge(b"zeta");

        let mut lookup_vec = Vec::new();
        let mut accumulated_vec = Vec::new();

        let (
            mut r_b_lookup_vec,
            mut r_b_accumulated_vec,
            r_b_subset_prod,
            r_b_set_prod,
            r_b_sorted_prod,
            r_b_sorted,
        ) = plookup(
            &r_b_star,
            &b_challenges,
            &row,
            &row_index,
            gamma,
            chi,
            E::Fr::zero(),
        );
        lookup_vec.append(&mut r_b_lookup_vec);
        accumulated_vec.append(&mut r_b_accumulated_vec);

        let (
            mut r_c_lookup_vec,
            mut r_c_accumulated_vec,
            r_c_subset_prod,
            r_c_set_prod,
            r_c_sorted_prod,
            r_c_sorted,
        ) = plookup(
            &r_c_star,
            &c_challenges,
            &row,
            &row_index,
            gamma,
            chi,
            E::Fr::zero(),
        );
        lookup_vec.append(&mut r_c_lookup_vec);
        accumulated_vec.append(&mut r_c_accumulated_vec);

        let (
            mut z_lookup_vec,
            mut z_accumulated_vec,
            z_subset_prod,
            z_set_prod,
            z_sorted_prod,
            z_sorted,
        ) = plookup(&z_star, &r1cs.z, &col, &col_index, gamma, chi, zeta);
        lookup_vec.append(&mut z_lookup_vec);
        accumulated_vec.append(&mut z_accumulated_vec);

        vec![
            r_b_subset_prod,
            r_b_set_prod,
            r_c_subset_prod,
            r_c_set_prod,
            z_subset_prod,
            z_set_prod,
        ]
        .iter()
        .for_each(|c| transcript.append_scalar(b"entryprod", c));

        let sorted_commitments_time = start_timer!(|| "Commitments to sorted vectors");
        let sorted_commitments = ck.batch_commit(vec![&r_b_sorted, &r_c_sorted, &z_sorted]);
        end_timer!(sorted_commitments_time);

        sorted_commitments
            .iter()
            .for_each(|c| transcript.append_commitment(b"commitment", c));

        let mut entry_products = EntryProduct::new_time_batch(
            &mut transcript,
            &ck,
            &lookup_vec,
            &[
                r_b_subset_prod,
                r_b_set_prod,
                r_b_sorted_prod,
                r_c_subset_prod,
                r_c_set_prod,
                r_c_sorted_prod,
                z_subset_prod,
                z_set_prod,
                z_sorted_prod,
            ],
        );

        let mu = transcript.get_challenge(b"mu");

        let r_a_star_mu_proof = ck.open(&r_a_star, &mu);
        let s_0_prime = scalar_prod(&hadamard(&r_a_star, &val_a), &second_challenges);
        let s_1_prime = scalar_prod(&hadamard(&r_b_star, &val_b), &second_challenges);
        // let s_2_prime = scalar_prod(&hadamard(&r_c_star, &val_c), &second_challenges);
        transcript.append_scalar(b"r_val_chal_a", &s_0_prime);
        transcript.append_scalar(b"r_val_chal_b", &s_1_prime);
        transcript.append_scalar(b"r_a_star_mu", &r_a_star_mu_proof.0);
        transcript.append_evaluation_proof(b"r_a_star_mu_proof", &r_a_star_mu_proof.1);

        let mut provers = Vec::new();
        provers.append(&mut entry_products.provers);

        provers.push(Box::new(TimeProver::new(Witness::new(
            &hadamard(&r_a_star, &second_challenges),
            &val_a,
            &E::Fr::one(),
        ))));

        provers.push(Box::new(TimeProver::new(Witness::new(
            &hadamard(&r_b_star, &second_challenges),
            &val_b,
            &E::Fr::one(),
        ))));

        provers.push(Box::new(TimeProver::new(Witness::new(
            &hadamard(&r_c_star, &second_challenges),
            &val_c,
            &E::Fr::one(),
        ))));

        provers.push(Box::new(TimeProver::new(Witness::new(
            &r_b_star, &r_c_star, &mu,
        ))));

        let third_sumcheck_time = start_timer!(|| "Third sumcheck");
        let third_proof = Sumcheck::prove_batch(&mut transcript, provers);
        end_timer!(third_sumcheck_time);

        let tc_base_polynomials = [
            &r1cs.w,
            &r_a_star,
            &r_b_star,
            &r_c_star,
            &z_star,
            &row,
            &col,
            &val_a,
            &val_b,
            &val_c,
            &r_b_sorted,
            &r_c_sorted,
            &z_sorted,
        ];

        let accumulated_product_vec = [&accumulated_vec.into_iter().flatten().collect()];
        let twist_powers2 = powers2(entry_products.chal, third_proof.challenges.len());
        let accumulated_vec_randomness = hadamard(&third_proof.challenges, &twist_powers2);

        let third_proof_vec = [
            &lookup_vec.into_iter().flatten().collect(),
            &val_a,
            &val_b,
            &val_c,
            &r_c_star,
        ];

        let mu_powers2 = powers2(mu, third_proof.challenges.len());

        let tc_body_polynomials = [
            (
                &accumulated_product_vec[..],
                &accumulated_vec_randomness[..],
            ),
            (&third_proof_vec[..], &third_proof.challenges[..]),
            (&[&z_star], &second_proof.challenges[..]),
            (
                &[&r_a_star, &r_b_star, &r_c_star],
                &hadamard(&second_proof.challenges, &third_proof.challenges)[..],
            ),
            (
                &[&r_b_star],
                &hadamard(&mu_powers2, &third_proof.challenges)[..],
            ),
        ];

        let tensorcheck_time = start_timer!(|| "Tensorcheck");
        let tensor_check_proof = TensorcheckProof::new_time(
            &mut transcript,
            &ck,
            tc_base_polynomials,
            tc_body_polynomials,
        );
        end_timer!(tensorcheck_time);
        Proof {
            witness_commitment,
            zc_alpha,
            first_sumcheck_msgs: first_proof.prover_messages(),
            r_star_commitments: [z_r_commitments[0], z_r_commitments[1], z_r_commitments[2]],
            z_star_commitment: z_r_commitments[3],
            second_sumcheck_msgs: second_proof.prover_messages(),
            set_r_b_ep: r_b_set_prod,
            subset_r_b_ep: r_b_subset_prod,
            sorted_r_b_ep: r_b_sorted_prod,
            sorted_r_b_commitment: sorted_commitments[0],
            set_r_c_ep: r_c_set_prod,
            subset_r_c_ep: r_c_subset_prod,
            sorted_r_c_ep: r_c_sorted_prod,
            sorted_r_c_commitment: sorted_commitments[1],
            set_z_ep: z_set_prod,
            subset_z_ep: z_subset_prod,
            sorted_z_ep: z_sorted_prod,
            sorted_z_commitment: sorted_commitments[2],
            ep_msgs: entry_products.msgs,
            ra_star_mu: r_a_star_mu_proof,
            rstars_vals: [s_0_prime, s_1_prime],
            third_sumcheck_msgs: third_proof.prover_messages(),
            tensor_check_proof,
        }
    }
}
