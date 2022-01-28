/// Time-efficient preprocessing SNARK for R1CS.
use ark_ec::PairingEngine;
use ark_ff::Field;
use ark_std::{One, Zero};

use crate::circuit::R1cs;
use crate::entryproduct::time_prover::accumulated_product;
use crate::entryproduct::EntryProduct;
use crate::kzg::CommitterKey;
use crate::misc::{
    evaluate_le, hadamard, ip, joint_matrices, linear_combination, powers, powers2,
    product_matrix_vector, sum_matrices, tensor,
};
use crate::plookup::time_prover::{lookup, plookup};
use crate::sumcheck::{proof::Sumcheck, time_prover::TimeProver, time_prover::Witness};
use crate::tensorcheck::TensorcheckProof;
use crate::transcript::GeminiTranscript;

use crate::PROTOCOL_NAME;

use super::Proof;

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

        let num_constraints = r1cs.a.len();
        let num_variables = r1cs.z.len();

        let joint_matrix = sum_matrices(&r1cs.a, &r1cs.b, &r1cs.c, num_variables);
        let (row, col, row_index, col_index, val_a, val_b, val_c) = joint_matrices(
            &joint_matrix,
            num_constraints,
            num_variables,
            &r1cs.a,
            &r1cs.b,
            &r1cs.c,
        );

        let num_non_zero = row.len();

        let r_a_star = lookup(&a_challenges, &row_index);
        let r_b_star = lookup(&b_challenges, &row_index);
        let r_c_star = lookup(&c_challenges, &row_index);
        // MXXX: changed `col_index` into `row_index`. I'm now confused about which ordering is which,
        // but it's important to keep in mind that:
        // - row is monotone column major
        // - col is monotone row major
        let z_star = lookup(&r1cs.z, &row_index);

        let z_r_commitments_time = start_timer!(|| "Commitments to z* and r*");
        let z_r_commitments = ck.batch_commit(vec![&r_a_star, &r_b_star, &r_c_star, &z_star]);
        end_timer!(z_r_commitments_time);

        // MXXX: changed this to a more descriptive transcript, and to be consistent with the elastic prover.
        transcript.append_commitment(b"ra*", &z_r_commitments[0]);
        transcript.append_commitment(b"rb*", &z_r_commitments[1]);
        transcript.append_commitment(b"rc*", &z_r_commitments[2]);
        transcript.append_commitment(b"z*", &z_r_commitments[3]);

        // MXXX: changed "eta" to "chal"
        let eta = transcript.get_challenge::<E::Fr>(b"chal");
        let challenges = powers(eta, 3);

        let r_star_val = linear_combination(
            &[
                hadamard(&r_a_star, &val_a),
                hadamard(&r_b_star, &val_b),
                hadamard(&r_c_star, &val_c),
            ],
            &challenges,
        )
        .unwrap();

        let second_sumcheck_time = start_timer!(|| "Second sumcheck");
        let second_proof = Sumcheck::new_time(&mut transcript, &z_star, &r_star_val, &E::Fr::one());
        let second_challenges = tensor(&second_proof.challenges);
        let second_challenges_head = &second_challenges[..num_non_zero];
        end_timer!(second_sumcheck_time);

        let gamma = transcript.get_challenge::<E::Fr>(b"gamma");
        let chi = transcript.get_challenge::<E::Fr>(b"chi");
        let zeta = transcript.get_challenge::<E::Fr>(b"zeta");

        let mut lookup_vec = Vec::new();
        let mut accumulated_vec = Vec::new();

        let (r_b_lookup_vec, r_b_sorted) = plookup(
            &r_b_star,
            &b_challenges,
            &row_index,
            &gamma,
            &chi,
            &E::Fr::zero(),
        );

        fn product3<F: Field>(v: &[Vec<F>; 3]) -> Vec<F> {
            vec![
                // can't use product() bc borrow confuses the multiplication.
                v[0].iter().fold(F::one(), |x, y| x * y),
                v[1].iter().fold(F::one(), |x, y| x * y),
                v[2].iter().fold(F::one(), |x, y| x * y),
            ]
        }

        fn accproduct3<F: Field>(v: &[Vec<F>; 3]) -> Vec<Vec<F>> {
            vec![
                accumulated_product(&v[0]),
                accumulated_product(&v[1]),
                accumulated_product(&v[2]),
            ]
        }

        let r_b_prod_vec = product3(&r_b_lookup_vec);
        let mut r_b_accumulated_vec = accproduct3(&r_b_lookup_vec);
        lookup_vec.append(&mut r_b_lookup_vec.to_vec());
        accumulated_vec.append(&mut r_b_accumulated_vec);

        let (r_c_lookup_vec, r_c_sorted) = plookup(
            &r_c_star,
            &c_challenges,
            &row_index,
            &gamma,
            &chi,
            &E::Fr::zero(),
        );
        let r_c_prod_vec = product3(&r_c_lookup_vec);
        let mut r_c_accumulated_vec = accproduct3(&r_c_lookup_vec);
        lookup_vec.append(&mut r_c_lookup_vec.to_vec());
        accumulated_vec.append(&mut r_c_accumulated_vec);

        let (z_lookup_vec, z_sorted) = plookup(&z_star, &r1cs.z, &col_index, &gamma, &chi, &zeta);
        let z_prod_vec = product3(&z_lookup_vec);
        let mut z_accumulated_vec = accproduct3(&z_lookup_vec);
        lookup_vec.append(&mut z_lookup_vec.to_vec());
        accumulated_vec.append(&mut z_accumulated_vec);
        vec![
            r_b_prod_vec[0],
            r_b_prod_vec[1],
            r_c_prod_vec[0],
            r_c_prod_vec[1],
            z_prod_vec[0],
            z_prod_vec[1],
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
            ck,
            &lookup_vec,
            &[
                r_b_prod_vec[0],
                r_b_prod_vec[1],
                r_b_prod_vec[2],
                r_c_prod_vec[0],
                r_c_prod_vec[1],
                r_c_prod_vec[2],
                z_prod_vec[0],
                z_prod_vec[1],
                z_prod_vec[2],
            ],
        );

        let mu = entry_products.chal;
        let open_chal = transcript.get_challenge::<E::Fr>(b"open-chal");

        let ralpha_star_acc_mu_proof = ck.batch_open_multi_points(
            &[
                &r_a_star,
                &accumulated_vec.iter().flatten().cloned().collect(),
            ],
            &[mu],
            &open_chal,
        );
        let mut ralpha_star_acc_mu_evals = vec![evaluate_le(&r_a_star, &mu)];
        accumulated_vec
            .iter()
            .for_each(|v| ralpha_star_acc_mu_evals.push(evaluate_le(&v, &mu)));

        let s_0_prime = ip(&hadamard(&r_a_star, &val_a), &second_challenges_head);
        let s_1_prime = ip(&hadamard(&r_b_star, &val_b), &second_challenges_head);
        // let s_2_prime = scalar_prod(&hadamard(&r_c_star, &val_c), &second_challenges);
        transcript.append_scalar(b"r_val_chal_a", &s_0_prime);
        transcript.append_scalar(b"r_val_chal_b", &s_1_prime);
        ralpha_star_acc_mu_evals
            .iter()
            .for_each(|e| transcript.append_scalar(b"r_a_star_acc_mu", e));
        transcript.append_evaluation_proof(b"r_a_star_mu_proof", &ralpha_star_acc_mu_proof);

        let mut provers = Vec::new();
        provers.append(&mut entry_products.provers);

        provers.push(Box::new(TimeProver::new(Witness::new(
            &hadamard(&r_a_star, &second_challenges_head),
            &val_a,
            &E::Fr::one(),
        ))));

        provers.push(Box::new(TimeProver::new(Witness::new(
            &hadamard(&r_b_star, &second_challenges_head),
            &val_b,
            &E::Fr::one(),
        ))));

        provers.push(Box::new(TimeProver::new(Witness::new(
            &hadamard(&r_c_star, &second_challenges_head),
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

        // third_proof.challenges might be longer than second_proof.challenges because of
        // the batched sumcheck involves entry products polynomials.
        let third_proof_challlenges_head = &third_proof.challenges[..second_proof.challenges.len()];
        let tc_body_polynomials = [
            (
                &accumulated_product_vec[..],
                &accumulated_vec_randomness[..],
            ),
            (&third_proof_vec[..], &third_proof.challenges[..]),
            (&[&z_star], &second_proof.challenges[..]),
            (
                &[&r_a_star, &r_b_star, &r_c_star],
                &hadamard(&second_proof.challenges, &third_proof_challlenges_head)[..],
            ),
            (
                &[&r_b_star],
                &hadamard(&mu_powers2, &third_proof.challenges)[..],
            ),
        ];

        let tensorcheck_time = start_timer!(|| "Tensorcheck");
        let tensor_check_proof = TensorcheckProof::new_time(
            &mut transcript,
            ck,
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
            set_r_ep: r_b_prod_vec[0],
            subset_r_ep: r_b_prod_vec[1],
            sorted_r_ep: r_b_prod_vec[2],
            sorted_r_commitment: sorted_commitments[0],
            set_alpha_ep: r_c_prod_vec[0],
            subset_alpha_ep: r_c_prod_vec[1],
            sorted_alpha_ep: r_c_prod_vec[2],
            sorted_alpha_commitment: sorted_commitments[1],
            set_z_ep: z_prod_vec[0],
            subset_z_ep: z_prod_vec[1],
            sorted_z_ep: z_prod_vec[2],
            sorted_z_commitment: sorted_commitments[2],
            ep_msgs: entry_products.msgs,
            ralpha_star_acc_mu_proof,
            ralpha_star_acc_mu_evals,
            rstars_vals: [s_0_prime, s_1_prime],
            third_sumcheck_msgs: third_proof.prover_messages(),
            tensor_check_proof,
        }
    }
}
