//! Space-efficient preprocessing SNARK for R1CS.
use ark_ec::PairingEngine;
use ark_ff::Field;
use ark_std::borrow::Borrow;
use ark_std::One;
use merlin::Transcript;

use crate::entryproduct::streams::entry_product_streams;
use crate::entryproduct::EntryProduct;
use crate::kzg::CommitterKeyStream;
// use crate::psnark::streams::memcheck::memcheck_streams;
// use crate::psnark::streams::plookup::plookup_streams;
use crate::psnark::Proof;

use crate::circuit::R1csStream;
use crate::iterable::Iterable;
use crate::misc::{
    evaluate_be, expand_tensor, hadamard, powers, powers2, strip_last, MatrixElement,
};
use crate::psnark::streams::plookup::plookup_streams;
use crate::psnark::streams::{
    HadamardStreamer, IndexStream, LineStream, LookupStreamer, TensorIStreamer, TensorStreamer,
    ValStream,
};
use crate::sumcheck::proof::Sumcheck;
use crate::sumcheck::ElasticProver;

use crate::sumcheck::streams::FoldedPolynomialTree;
use crate::tensorcheck::evaluate_folding;
use crate::transcript::GeminiTranscript;
use crate::{lincomb, PROTOCOL_NAME};

impl<E: PairingEngine> Proof<E> {
    /// Given as input the _streaming_ R1CS instance `r1cs`
    /// and the _streaming_ committer key `ck`,
    /// return a new _preprocessing_ SNARK using the elastic prover.
    #[allow(unused_assignments)]
    pub fn new_elastic<SM, SG, SZ, SW>(
        r1cs: R1csStream<SM, SZ, SW>,
        ck: CommitterKeyStream<E, SG>,
    ) -> Proof<E>
    where
        SM: Iterable + Copy,
        SZ: Iterable<Item = E::Fr> + Copy,
        SW: Iterable + Copy,
        SG: Iterable,
        SM::Item: Borrow<MatrixElement<E::Fr>>,
        SZ::Item: Borrow<E::Fr> + Copy,
        SW::Item: Borrow<E::Fr> + Copy,
        SZ::Item: Borrow<E::Fr> + Copy,
        SG::Item: Borrow<E::G1Affine>,
    {
        let _ahp_proof_time = start_timer!(|| "AP::Prove");
        let mut transcript = Transcript::new(PROTOCOL_NAME);
        // send the vector w
        let witness_commitment_time = start_timer!(|| "Commitment to w");
        let _witness_commitment = ck.commit(&r1cs.witness);
        end_timer!(witness_commitment_time);

        // obtain the challenge from the verifier.
        let alpha = transcript.get_challenge(b"alpha");

        // run the sumcheck for z_a and z_b with twist alpha
        let first_sumcheck_time = start_timer!(|| "First sumcheck");
        let first_sumcheck = Sumcheck::new_space(&mut transcript, r1cs.z_a, r1cs.z_b, alpha);
        end_timer!(first_sumcheck_time);
        let first_sumcheck_messages = first_sumcheck.prover_messages();

        let len = first_sumcheck.challenges.len();
        let r_b_short = &first_sumcheck.challenges;
        let r_c_short = &powers2(alpha, len);
        let r_a_short = &hadamard(r_b_short, r_c_short);

        let r_a_expanded = expand_tensor(r_a_short);
        let r_b_expanded = expand_tensor(r_b_short);
        let r_c_expanded = expand_tensor(r_c_short);

        let r_a = TensorStreamer::new(&r_a_expanded, 1 << len);
        let r_b = TensorStreamer::new(&r_b_expanded, 1 << len);
        let r_c = TensorStreamer::new(&r_c_expanded, 1 << len);

        let row_a = LineStream::new(r1cs.a_colm);
        let row_b = LineStream::new(r1cs.b_colm);
        let row_c = LineStream::new(r1cs.c_colm);
        let row = row_a; //

        let col_a = IndexStream::new(r1cs.a_colm);
        let col_b = IndexStream::new(r1cs.b_colm);
        let col_c = IndexStream::new(r1cs.c_colm);
        let col = col_a; // Changeme

        let z_star = LookupStreamer {
            items: r1cs.z,
            indices: col,
        };

        let r_a_star = TensorIStreamer::new(&r_a_expanded, row, 1 << len);
        let r_b_star = TensorIStreamer::new(&r_b_expanded, row, 1 << len);
        let r_c_star = TensorIStreamer::new(&r_c_expanded, row, 1 << len);

        let val_a = ValStream::new(r1cs.a_colm, r1cs.nonzero);
        let val_b = ValStream::new(r1cs.b_colm, r1cs.nonzero);
        let val_c = ValStream::new(r1cs.c_colm, r1cs.nonzero);
        // XXX derive val GENERIC

        let r_a_star_val_a = HadamardStreamer::new(r_a_star, val_a);
        let r_b_star_val_b = HadamardStreamer::new(r_b_star, val_b);
        let r_c_star_val_c = HadamardStreamer::new(r_c_star, val_c);

        let r_b_star_commitment = ck.commit(&r_b_star);
        let r_c_star_commitment = ck.commit(&r_c_star);
        let z_star_commitment = ck.commit(&z_star);
        // send s0 s1 s2
        let s0 = z_star
            .iter()
            .zip(r_a_star.iter())
            .map(|(x, y)| y * x.borrow())
            .sum::<E::Fr>();
        let s1 = z_star
            .iter()
            .zip(r_b_star.iter())
            .map(|(x, y)| y * x.borrow())
            .sum::<E::Fr>();
        let s2 = z_star
            .iter()
            .zip(r_c_star.iter())
            .map(|(x, y)| y * x.borrow())
            .sum::<E::Fr>();

        transcript.append_commitment(b"rb*", &r_b_star_commitment);
        transcript.append_commitment(b"rb*", &r_c_star_commitment);
        transcript.append_commitment(b"rb*", &z_star_commitment);
        transcript.append_scalar(b"s0", &s0);
        transcript.append_scalar(b"s1", &s1);
        transcript.append_scalar(b"s2", &s2);

        let challenge = transcript.get_challenge::<E::Fr>(b"chal");
        let challenges = powers(challenge, 3);
        let rhs = lincomb!(
            (r_a_star_val_a, r_b_star_val_b, r_c_star_val_c),
            &challenges
        );

        let sumcheck2 = Sumcheck::new_elastic(&mut transcript, z_star, rhs, E::Fr::one());

        let mu = transcript.get_challenge(b"chal");
        let r_c_star_mu = evaluate_be(r_c_star.iter(), &mu);

        // // PLOOKUP PROTOCOL
        let y = transcript.get_challenge(b"y");
        let z = transcript.get_challenge(b"zeta");
        // // ENTRY PRODUCT FOR rA rB rC
        let (pl_set_r, pl_subset_r, pl_sorted_r) = plookup_streams(&r_c, &r_c_star, &row, y, z);
        let (pl_set_z, pl_subset_z, pl_sorted_z) = plookup_streams(&r1cs.z, &z_star, &col, y, z);

        // compute the products to send to the verifier.
        // XXXX. There is no need to compute the sorted ones as they can be derived.
        let gp_set_r = pl_set_r.iter().product();
        let gp_subset_r = pl_subset_r.iter().product();
        let gp_sorted_r = pl_sorted_r.iter().product();
        let gp_set_z = pl_set_z.iter().product();
        let gp_subset_z = pl_subset_z.iter().product();
        let gp_sorted_z = pl_sorted_r.iter().product();

        // compute the commitments to the sorted polynomials
        let comm_sorted_r = ck.commit(&pl_sorted_r);
        let comm_sorted_z = ck.commit(&pl_sorted_z);

        transcript.append_scalar(b"r_c_star_mu", &r_c_star_mu);
        transcript.append_scalar(b"gp_set_r", &gp_set_r);
        transcript.append_scalar(b"gp_subset_r", &gp_subset_r);
        transcript.append_scalar(b"gp_set_z", &gp_set_z);
        transcript.append_scalar(b"gp_subset_z", &gp_subset_z);
        transcript.append_commitment(b"pl_sorted_r", &comm_sorted_r);
        transcript.append_commitment(b"pl_sorted_z", &comm_sorted_z);

        let EntryProduct { msgs, mut provers } = EntryProduct::new_elastic_batch(
            &mut transcript,
            &ck,
            (
                &pl_set_r,
                &pl_subset_r,
                &pl_sorted_r,
                &pl_set_z,
                &pl_subset_z,
                &pl_sorted_z,
            ),
            &vec![
                gp_set_r,
                gp_subset_r,
                gp_sorted_r,
                gp_set_z,
                gp_subset_z,
                gp_sorted_z,
            ],
        );
        // XXX missing the twists?
        provers.push(Box::new(ElasticProver::new(r_a_star, val_a, E::Fr::one())));
        provers.push(Box::new(ElasticProver::new(r_b_star, val_b, E::Fr::one())));
        provers.push(Box::new(ElasticProver::new(r_c_star, val_c, E::Fr::one())));

        let sumcheck3 = Sumcheck::prove_batch(&mut transcript, provers);

        ////
        // TENSORCHECK
        ////
        let (pl_set_sh_r, pl_set_acc_r) = entry_product_streams(&pl_set_r);
        let (pl_subset_sh_r, pl_subset_acc_r) = entry_product_streams(&pl_subset_r);
        let (pl_sorted_sh_r, pl_sorted_acc_r) = entry_product_streams(&pl_sorted_r);
        let (pl_set_sh_z, pl_set_acc_z) = entry_product_streams(&pl_set_z);
        let (pl_subset_sh_z, pl_subset_acc_z) = entry_product_streams(&pl_subset_z);
        let (pl_sorted_sh_z, pl_sorted_acc_z) = entry_product_streams(&pl_sorted_z);
        let tc_chal = transcript.get_challenge::<E::Fr>(b"tc");
        let tc_challenges = powers(tc_chal, 2 * 3 * 2);

        let body_polynomials = lincomb!(
            (
                pl_set_sh_r,
                pl_subset_sh_r,
                pl_sorted_sh_r,
                pl_set_acc_r,
                pl_subset_acc_r,
                pl_sorted_acc_r,
                pl_set_sh_z,
                pl_subset_sh_z,
                pl_sorted_sh_z,
                pl_set_acc_z,
                pl_subset_acc_z,
                pl_sorted_acc_z
            ),
            &tc_challenges
        );
        let tensorcheck_challenges = strip_last(&sumcheck3.challenges);
        let tensorcheck_foldings =
            FoldedPolynomialTree::new(&body_polynomials, tensorcheck_challenges);
        let folded_polynomials_commitments = ck.commit_folding(&tensorcheck_foldings);

        // add commitments to transcript
        folded_polynomials_commitments
            .iter()
            .for_each(|c| transcript.append_commitment(b"commitment", c));
        let eval_chal = transcript.get_challenge::<E::Fr>(b"evaluation-chal");
        let eval_points = [eval_chal.square(), eval_chal, -eval_chal];

        fn evaluate_base_polynomial<I, F>(transcript: &mut Transcript, base_polynomial: I, eval_points: &[F; 3]) -> [F; 3] where  F: Field, I: Iterable, I::Item: Borrow<F> {
            let evaluations_w = [
                    evaluate_be(base_polynomial.iter(), &eval_points[0]),
                    evaluate_be(base_polynomial.iter(), &eval_points[1]),
                    evaluate_be(base_polynomial.iter(), &eval_points[2]),
                ];
            evaluations_w
                    .iter()
                    .for_each(|e| transcript.append_scalar(b"eval", &e));
            evaluations_w
        }

        let folded_polynomials_evaluations =
            evaluate_folding(&tensorcheck_foldings, eval_points[1])
                .into_iter()
                .zip(evaluate_folding(&tensorcheck_foldings, eval_points[2]))
                .map(|(x, y)| [x, y])
                .collect::<Vec<_>>();


        let evaluations_w = vec![
            // evaluate_base_polynomial(&mut transcript, row.iter().map(|x| E::Fr::from(*x.borrow() as u64)), &eval_points),
            // evaluate_base_polynomial(&mut transcript, col.iter().map(|x| E::Fr::from(*x.borrow() as u64)), &eval_points),
            evaluate_base_polynomial(&mut transcript, r1cs.witness, &eval_points),
        ];
        folded_polynomials_evaluations
        .iter()
        .flatten()
        .for_each(|e| transcript.append_scalar(b"eval", e));

        let open_chal = transcript.get_challenge::<E::Fr>(b"open-chal");
        let open_chal_len = tensorcheck_challenges.len() + 3; // adjuct with the numebr of base polynomials

        // do this for every base polynomial
        let open_chals = powers(open_chal, open_chal_len);
        // do this foe each element.
        let (_, proof_w) = ck.open_multi_points(&r1cs.witness, &eval_points);
        let (_, proof) = ck.open_folding(tensorcheck_foldings, &eval_points, &open_chals[3..]);
        let evaluation_proof = proof_w + proof;

        todo!();


        // // let commitments = Vec::new();
        // // let evaluations = Vec::new();
        // // end_timer!(consistency_check_time);

        // // Proof {
        // //     first_sumcheck_messages,
        // //     second_sumcheck_messages,
        // //     third_sumcheck_messages,
        // //     ep_sumcheck_messages,
        // //     commitments,
        // //     proofs,
        // //     evaluations,
        // // }
    }
}
