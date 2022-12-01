//! Time-efficient preprocessing SNARK for R1CS.

use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_std::boxed::Box;
use ark_std::vec::Vec;
use ark_std::One;

use crate::circuit::R1cs;
use crate::kzg::CommitterKey;
use crate::misc::{
    evaluate_le, hadamard, ip, joint_matrices, linear_combination, powers, powers2,
    product_matrix_vector, sum_matrices, tensor,
};

use crate::subprotocols::entryproduct::time_prover::{accumulated_product, monic, right_rotation};
use crate::subprotocols::entryproduct::EntryProduct;
use crate::subprotocols::plookup::time_prover::{
    alg_hash, compute_frequency, extend_frequency, lookup, plookup, sorted,
};
use crate::subprotocols::sumcheck::{
    proof::Sumcheck, time_prover::TimeProver, time_prover::Witness,
};
use crate::subprotocols::tensorcheck::TensorcheckProof;
use crate::transcript::GeminiTranscript;

use crate::PROTOCOL_NAME;

use super::{Index, Proof};

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
        accumulated_product(&monic(&v[0])),
        accumulated_product(&monic(&v[1])),
        accumulated_product(&monic(&v[2])),
    ]
}

impl<E: Pairing> Proof<E> {

    pub fn index(ck: &CommitterKey<E>, r1cs: &R1cs<E::ScalarField>) -> Index<E> {
        let num_constraints = r1cs.a.len();
        let num_variables = r1cs.z.len();

        let joint_matrix = sum_matrices(&r1cs.a, &r1cs.b, &r1cs.c, num_variables);
        let (row, col, _row_index, _col_index, val_a, val_b, val_c) = joint_matrices(
            &joint_matrix,
            num_constraints,
            num_variables,
            &r1cs.a,
            &r1cs.b,
            &r1cs.c,
        );

        ck.batch_commit(&vec![row, col, val_a, val_b, val_c])
    }

    /// Given as input the R1CS instance `r1cs`
    /// and the committer key `ck`,
    /// return a new _preprocessing_ SNARK using the elastic prover.
    pub fn new_time(ck: &CommitterKey<E>, r1cs: &R1cs<E::ScalarField>, index: &Index<E>) -> Proof<E> {
        let z_a = product_matrix_vector(&r1cs.a, &r1cs.z);
        let z_b = product_matrix_vector(&r1cs.b, &r1cs.z);
        let z_c = product_matrix_vector(&r1cs.c, &r1cs.z);
        let mut transcript = merlin::Transcript::new(PROTOCOL_NAME);
        let witness_commitment_time = start_timer!(|| "Commitment to w");
        let witness_commitment = ck.commit(&r1cs.w);
        end_timer!(witness_commitment_time);

        transcript.append_serializable(b"witness", &witness_commitment);
        transcript.append_serializable(b"ck", &ck.powers_of_g2);
        transcript.append_serializable(b"instance", &index.as_slice());
        let alpha = transcript.get_challenge(b"alpha");

        let zc_alpha = evaluate_le(&z_c, &alpha);
        transcript.append_serializable(b"zc(alpha)", &zc_alpha);

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

        let ralpha_star = lookup(&a_challenges, &row_index);
        let r_star = lookup(&b_challenges, &row_index);
        let alpha_star = lookup(&c_challenges, &row_index);
        let z_star = lookup(&r1cs.z, &col_index);

        let ck_row = ck.index_by(&row_index[..]);
        let ck_col = ck.index_by(&col_index[..]);

        let z_r_commitments_time = start_timer!(|| "Commitments to z* and r*");
        let mut z_r_commitments =
            ck_row.batch_commit(vec![&a_challenges, &b_challenges, &c_challenges]);
        z_r_commitments.push(ck_col.commit(&r1cs.z));
        // let z_r_commitments = ck.batch_commit(vec![&ralpha_star, &r_star, &alpha_star, &z_star]);
        end_timer!(z_r_commitments_time);

        transcript.append_serializable(b"ra*", &z_r_commitments[0]);
        transcript.append_serializable(b"rb*", &z_r_commitments[1]);
        transcript.append_serializable(b"rc*", &z_r_commitments[2]);
        transcript.append_serializable(b"z*", &z_r_commitments[3]);

        let eta = transcript.get_challenge::<E::ScalarField>(b"chal");
        let challenges = powers(eta, 3);

        let r_star_val = linear_combination(
            &[
                hadamard(&ralpha_star, &val_a),
                hadamard(&r_star, &val_b),
                hadamard(&alpha_star, &val_c),
            ],
            &challenges,
        );

        let second_sumcheck_time = start_timer!(|| "Second sumcheck");
        let second_proof = Sumcheck::new_time(
            &mut transcript,
            &z_star,
            &r_star_val,
            &E::ScalarField::one(),
        );
        let second_challenges = tensor(&second_proof.challenges);
        let second_challenges_head = &second_challenges[..num_non_zero];
        end_timer!(second_sumcheck_time);

        let zeta = transcript.get_challenge(b"zeta");

        let sorted_commitments_time = start_timer!(|| "Commitments to sorted vectors");
        let alg_hash_poly = [
            alg_hash(&b_challenges, 0..b_challenges.len(), &zeta),
            alg_hash(&c_challenges, 0..c_challenges.len(), &zeta),
            alg_hash(&r1cs.z, 0..r1cs.z.len(), &zeta),
        ];
        let frequency = [
            compute_frequency(alg_hash_poly[0].len(), &row_index),
            compute_frequency(alg_hash_poly[2].len(), &col_index),
        ];
        let sorted_polynomials = [
            &sorted(&alg_hash_poly[0], &frequency[0]),
            &sorted(&alg_hash_poly[1], &frequency[0]),
            &sorted(&alg_hash_poly[2], &frequency[1]),
        ];

        let ext_fre = [
            extend_frequency(&frequency[0]),
            extend_frequency(&frequency[1]),
        ];
        let ck_fre = [ck.index_by(&ext_fre[0]), ck.index_by(&ext_fre[1])];
        let mut sorted_commitments =
            ck_fre[0].batch_commit(vec![&alg_hash_poly[0], &alg_hash_poly[1]]);
        sorted_commitments.push(ck_fre[1].commit(&alg_hash_poly[2]));
        // let sorted_commitments = ck.batch_commit(sorted_polynomials);
        end_timer!(sorted_commitments_time);

        transcript.append_serializable(b"sorted_alpha_commitment", &sorted_commitments[1]);
        transcript.append_serializable(b"sorted_r_commitment", &sorted_commitments[0]);
        transcript.append_serializable(b"sorted_z_commitment", &sorted_commitments[2]);

        let gamma = transcript.get_challenge(b"gamma");
        let chi = transcript.get_challenge(b"chi");

        // TODO: Make sorted vectors as input to the plookup function.
        let r_lookup_vec = plookup(&r_star, &b_challenges, &row_index, &gamma, &chi, &zeta);
        let r_prod_vec = product3(&r_lookup_vec);
        let r_accumulated_vec = accproduct3(&r_lookup_vec);

        let alpha_lookup_vec = plookup(&alpha_star, &c_challenges, &row_index, &gamma, &chi, &zeta);
        let alpha_prod_vec = product3(&alpha_lookup_vec);
        let alpha_accumulated_vec = accproduct3(&alpha_lookup_vec);

        let z_lookup_vec = plookup(&z_star, &r1cs.z, &col_index, &gamma, &chi, &zeta);
        let z_prod_vec = product3(&z_lookup_vec);
        let z_accumulated_vec = accproduct3(&z_lookup_vec);

        let mut lookup_vec = Vec::new();
        lookup_vec.extend_from_slice(&r_lookup_vec);
        lookup_vec.extend_from_slice(&alpha_lookup_vec);
        lookup_vec.extend_from_slice(&z_lookup_vec);

        let mut accumulated_vec = Vec::new();
        accumulated_vec.extend_from_slice(&r_accumulated_vec);
        accumulated_vec.extend_from_slice(&alpha_accumulated_vec);
        accumulated_vec.extend_from_slice(&z_accumulated_vec);

        transcript.append_serializable(b"set_r_ep", &alpha_prod_vec[0]);
        transcript.append_serializable(b"subset_r_ep", &alpha_prod_vec[1]);
        transcript.append_serializable(b"set_r_ep", &r_prod_vec[0]);
        transcript.append_serializable(b"subset_r_ep", &r_prod_vec[1]);
        transcript.append_serializable(b"set_z_ep", &z_prod_vec[0]);
        transcript.append_serializable(b"subset_z_ep", &z_prod_vec[1]);

        let entry_products = EntryProduct::new_time_batch(
            &mut transcript,
            ck,
            &lookup_vec,
            &[
                r_prod_vec[0],
                r_prod_vec[1],
                r_prod_vec[2],
                alpha_prod_vec[0],
                alpha_prod_vec[1],
                alpha_prod_vec[2],
                z_prod_vec[0],
                z_prod_vec[1],
                z_prod_vec[2],
            ],
        );

        let psi = entry_products.chal;
        let open_chal = transcript.get_challenge::<E::ScalarField>(b"open-chal");

        let mut polynomials = vec![&ralpha_star];
        polynomials.extend(&accumulated_vec);
        let ralpha_star_acc_mu_proof = ck.batch_open_multi_points(&polynomials, &[psi], &open_chal);

        let mut ralpha_star_acc_mu_evals = vec![evaluate_le(&ralpha_star, &psi)];
        accumulated_vec.iter().for_each(|v| {
            ralpha_star_acc_mu_evals.push(evaluate_le(v, &psi));
        });

        let s_0_prime = ip(&hadamard(&ralpha_star, &val_a), second_challenges_head);
        let s_1_prime = ip(&hadamard(&r_star, &val_b), second_challenges_head);
        // let s_2_prime = ip(&hadamard(&alpha_star, &val_c), &second_challenges_head);
        // transcript.append_serializable(b"r_val_chal_a", &s_0_prime);
        // transcript.append_serializable(b"r_val_chal_b", &s_1_prime);
        ralpha_star_acc_mu_evals
            .iter()
            .for_each(|e| transcript.append_serializable(b"ralpha_star_acc_mu", e));
        transcript.append_serializable(b"ralpha_star_mu_proof", &ralpha_star_acc_mu_proof);

        let mut provers = Vec::new();
        provers.extend(entry_products.provers);

        provers.push(Box::new(TimeProver::new(Witness::new(
            &hadamard(&ralpha_star, second_challenges_head),
            &val_a,
            &E::ScalarField::one(),
        ))));
        provers.push(Box::new(TimeProver::new(Witness::new(
            &hadamard(&r_star, second_challenges_head),
            &val_b,
            &E::ScalarField::one(),
        ))));
        provers.push(Box::new(TimeProver::new(Witness::new(
            &hadamard(&alpha_star, second_challenges_head),
            &val_c,
            &E::ScalarField::one(),
        ))));
        provers.push(Box::new(TimeProver::new(Witness::new(
            &r_star,
            &alpha_star,
            &psi,
        ))));

        let third_sumcheck_time = start_timer!(|| "Third sumcheck");
        let third_proof = Sumcheck::prove_batch(&mut transcript, provers);
        end_timer!(third_sumcheck_time);

        let tc_base_polynomials = [
            &r1cs.w,
            &ralpha_star,
            &r_star,
            &alpha_star,
            &z_star,
            &row,
            &col,
            &val_a,
            &val_b,
            &val_c,
            sorted_polynomials[0],
            sorted_polynomials[1],
            sorted_polynomials[2],
            &accumulated_vec[0],
            &accumulated_vec[1],
            &accumulated_vec[2],
            &accumulated_vec[3],
            &accumulated_vec[4],
            &accumulated_vec[5],
            &accumulated_vec[6],
            &accumulated_vec[7],
            &accumulated_vec[8],
        ];

        let twist_powers2 = powers2(entry_products.chal, third_proof.challenges.len());

        let shift_monic_lookup_vec = lookup_vec
            .iter()
            .map(|v| right_rotation(&(monic(v))))
            .collect::<Vec<_>>();
        let mut third_proof_vec = Vec::new();

        third_proof_vec.extend(&shift_monic_lookup_vec);
        third_proof_vec.extend(&[&val_a, &val_b, &val_c, &alpha_star]);

        // third_proof.challenges might be longer than second_proof.challenges because of
        // the batched sumcheck involves entry products polynomials.
        let body_polynomials_0 = [
            &accumulated_vec[0],
            &accumulated_vec[1],
            &accumulated_vec[2],
            &accumulated_vec[3],
            &accumulated_vec[4],
            &accumulated_vec[5],
            &accumulated_vec[6],
            &accumulated_vec[7],
            &accumulated_vec[8],
            &r_star,
        ];
        let third_proof_challlenges_head = &third_proof.challenges[..second_proof.challenges.len()];
        let tc_body_polynomials = [
            (
                &body_polynomials_0[..],
                &hadamard(&third_proof.challenges, &twist_powers2)[..],
            ),
            (&third_proof_vec[..], &third_proof.challenges[..]),
            (&[&z_star], &second_proof.challenges[..]),
            (
                &[&ralpha_star, &r_star, &alpha_star],
                &hadamard(&second_proof.challenges, third_proof_challlenges_head)[..],
            ),
        ];

        let tensorcheck_time = start_timer!(|| "Tensorcheck");
        let tensorcheck_proof = TensorcheckProof::new_time(
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
            set_r_ep: r_prod_vec[0],
            subset_r_ep: r_prod_vec[1],
            sorted_r_commitment: sorted_commitments[0],
            set_alpha_ep: alpha_prod_vec[0],
            subset_alpha_ep: alpha_prod_vec[1],
            sorted_alpha_commitment: sorted_commitments[1],
            set_z_ep: z_prod_vec[0],
            subset_z_ep: z_prod_vec[1],
            sorted_z_commitment: sorted_commitments[2],
            ep_msgs: entry_products.msgs,
            ralpha_star_acc_mu_proof,
            ralpha_star_acc_mu_evals,
            rstars_vals: [s_0_prime, s_1_prime],
            third_sumcheck_msgs: third_proof.prover_messages(),
            tensorcheck_proof,
        }
    }
}
