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
use crate::misc::{evaluate_be, hadamard, powers, powers2, strip_last, MatrixElement};
use crate::psnark::streams::plookup::plookup_streams;
use crate::psnark::streams::{
    HadamardStreamer, IndexStream, LineStream, LookupStreamer, TensorIStreamer, TensorStreamer,
    ValStream,
};
use crate::sumcheck::proof::Sumcheck;
use crate::sumcheck::ElasticProver;

use crate::sumcheck::streams::FoldedPolynomialTree;
use crate::tensorcheck::{evaluate_folding, TensorCheckProof};
use crate::transcript::GeminiTranscript;
use crate::{lincomb, PROTOCOL_NAME};

fn inner_product_uncheck<F: Field, I, J>(lhs: I, rhs: J) -> F
where
    I: Iterator,
    J: Iterator,
    I::Item: Borrow<F>,
    J::Item: Borrow<F>,
{
    lhs.zip(rhs).map(|(x, y)| *x.borrow() * y.borrow()).sum()
}

fn evaluate_base_polynomial<I, F>(
    transcript: &mut Transcript,
    base_polynomial: &I,
    eval_points: &[F; 3],
) -> [F; 3]
where
    F: Field,
    I: Iterable,
    I::Item: Borrow<F>,
{
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
        let witness_commitment = ck.commit(&r1cs.witness);
        end_timer!(witness_commitment_time);

        // send witness, receive challenge.
        transcript.append_commitment(b"witness", &witness_commitment);
        let alpha = transcript.get_challenge(b"alpha");

        // send evaluation of zc(alpha)
        let zc_alpha = evaluate_be(r1cs.z_c.iter(), &alpha);
        transcript.append_scalar(b"zc(alpha)", &zc_alpha);

        // run the sumcheck for z_a and z_b with twist alpha
        let sumcheck_time = start_timer!(|| "First sumcheck");
        let sumcheck1 = Sumcheck::new_space(&mut transcript, r1cs.z_a, r1cs.z_b, alpha);
        end_timer!(sumcheck_time);

        let len = sumcheck1.challenges.len();
        let r_b_short = &sumcheck1.challenges;
        let r_c_short = &powers2(alpha, len);
        let r_a_short = &hadamard(r_b_short, r_c_short);

        let r_a = TensorStreamer::new(&r_a_short, 1 << len);
        // Never actually used, but in the mind of the prover.
        // let r_b = TensorStreamer::new(&r_b_short, 1 << len);
        // let r_c = TensorStreamer::new(&r_c_short, 1 << len);

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

        let r_a_star = TensorIStreamer::new(&r_a_short, row, 1 << len);
        let r_b_star = TensorIStreamer::new(&r_b_short, row, 1 << len);
        let r_c_star = TensorIStreamer::new(&r_c_short, row, 1 << len);

        let val_a = ValStream::new(r1cs.a_colm, r1cs.nonzero);
        let val_b = ValStream::new(r1cs.b_colm, r1cs.nonzero);
        let val_c = ValStream::new(r1cs.c_colm, r1cs.nonzero);
        // XXX derive val GENERIC

        let r_a_star_val_a = HadamardStreamer::new(r_a_star.clone(), val_a);
        let r_b_star_val_b = HadamardStreamer::new(r_b_star.clone(), val_b);
        let r_c_star_val_c = HadamardStreamer::new(r_c_star.clone(), val_c);

        let rb_star_commitment = ck.commit(&r_b_star);
        let rc_star_commitment = ck.commit(&r_c_star);
        let z_star_commitment = ck.commit(&z_star);

        // send s0 s1 s2
        let s0 = inner_product_uncheck(z_star.iter(), r_a_star.iter());
        let s1 = inner_product_uncheck(z_star.iter(), r_b_star.iter());
        let s2 = inner_product_uncheck(z_star.iter(), r_c_star.iter());
        let z_star_rs = [s0, s1, s2];

        transcript.append_commitment(b"rb*", &rb_star_commitment);
        transcript.append_commitment(b"rb*", &rc_star_commitment);
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
        let r_a_star_mu = evaluate_be(r_a_star.iter(), &mu);

        // // PLOOKUP PROTOCOL
        let y = transcript.get_challenge(b"y");
        let z = transcript.get_challenge(b"zeta");
        // // ENTRY PRODUCT FOR rA rB rC
        let (pl_set_r, pl_subset_r, pl_sorted_r) = plookup_streams(&r_a, &r_a_star, &row, y, z);
        let (pl_set_z, pl_subset_z, pl_sorted_z) = plookup_streams(&r1cs.z, &z_star, &col, y, z);

        // compute the products to send to the verifier.
        // XXXX. There is no need to compute the sorted ones as they can be derived.
        let set_r_ep = pl_set_r.iter().product();
        let subset_r_ep = pl_subset_r.iter().product();
        let sorted_r_ep = pl_sorted_r.iter().product();
        let set_z_ep = pl_set_z.iter().product();
        let subset_z_ep = pl_subset_z.iter().product();
        let sorted_z_ep = pl_sorted_r.iter().product();

        // compute the commitments to the sorted polynomials
        let sorted_r_commitment = ck.commit(&pl_sorted_r);
        let sorted_z_commitment = ck.commit(&pl_sorted_z);

        transcript.append_scalar(b"r_a_star_mu", &r_a_star_mu);
        transcript.append_scalar(b"set_r_ep", &set_r_ep);
        transcript.append_scalar(b"subset_r_ep", &subset_r_ep);
        transcript.append_scalar(b"set_z_ep", &set_z_ep);
        transcript.append_scalar(b"subset_z_ep", &subset_z_ep);
        transcript.append_commitment(b"sorted_r_commitment", &sorted_r_commitment);
        transcript.append_commitment(b"sorted_z_commitment", &sorted_z_commitment);

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
                set_r_ep,
                subset_r_ep,
                sorted_r_ep,
                set_z_ep,
                subset_z_ep,
                sorted_z_ep,
            ],
        );
        // XXX missing the twists?
        let ep_r = TensorStreamer::new(&sumcheck2.challenges, r_a_star.len());
        let lhs_r_a_star = HadamardStreamer::new(r_a_star.clone(), ep_r.clone());
        let lhs_r_b_star = HadamardStreamer::new(r_b_star.clone(), ep_r.clone());
        let lhs_r_c_star = HadamardStreamer::new(r_c_star.clone(), ep_r);
        provers.push(Box::new(ElasticProver::new(
            lhs_r_a_star,
            val_a,
            E::Fr::one(),
        )));
        provers.push(Box::new(ElasticProver::new(
            lhs_r_b_star,
            val_b,
            E::Fr::one(),
        )));
        provers.push(Box::new(ElasticProver::new(
            lhs_r_c_star,
            val_c,
            E::Fr::one(),
        )));
        provers.push(Box::new(ElasticProver::new(
            r_b_star.clone(),
            r_c_star.clone(),
            mu,
        )));

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
        let tc_challenges = powers(tc_chal, 2 * 3 + 4);

        let body_polynomials_0 = lincomb!(
            (
                pl_set_acc_r,
                pl_subset_acc_r,
                pl_sorted_acc_r,
                pl_set_acc_z,
                pl_subset_acc_z,
                pl_sorted_acc_z,
                pl_set_acc_z,
                pl_subset_acc_z,
                pl_sorted_acc_z
            ),
            &tc_challenges
        );
        let body_polynomials_1 = lincomb!(
            (
                pl_set_sh_r,
                pl_subset_sh_r,
                pl_sorted_sh_r,
                pl_set_sh_z,
                pl_subset_sh_z,
                pl_sorted_sh_z,
                val_a,
                val_b,
                val_c,
                r_c_star
            ),
            &tc_challenges
        );
        let body_polynomials_2 = z_star;
        let body_polynomials_3 = lincomb!((r_b_star, r_c_star), &tc_challenges);
        let body_polynomials_4 = r_b_star.clone();

        let psi_squares = powers2(E::Fr::one(), sumcheck3.challenges.len());
        let mu_squares = powers2(mu, sumcheck3.challenges.len());

        let tensorcheck_challenges_0 = hadamard(&sumcheck3.challenges, &psi_squares);
        let tensorcheck_challenges_0 = strip_last(&tensorcheck_challenges_0);

        let tensorcheck_challenges_1 = strip_last(&sumcheck3.challenges);

        let tensorcheck_challenges_2 = strip_last(&sumcheck2.challenges);

        let tensorcheck_challenges_3 = hadamard(&sumcheck2.challenges, &sumcheck3.challenges);
        let tensorcheck_challenges_3 = strip_last(&tensorcheck_challenges_3);

        let tensorcheck_challenges_4 = hadamard(&sumcheck3.challenges, &mu_squares);
        let tensorcheck_challenges_4 = strip_last(&tensorcheck_challenges_4);

        let tensorcheck_foldings_0 =
            FoldedPolynomialTree::new(&body_polynomials_0, tensorcheck_challenges_0);
        let tensorcheck_foldings_1 =
            FoldedPolynomialTree::new(&body_polynomials_1, tensorcheck_challenges_1);
        let tensorcheck_foldings_2 =
            FoldedPolynomialTree::new(&body_polynomials_2, tensorcheck_challenges_2);
        let tensorcheck_foldings_3 =
            FoldedPolynomialTree::new(&body_polynomials_3, tensorcheck_challenges_3);
        let tensorcheck_foldings_4 =
            FoldedPolynomialTree::new(&body_polynomials_4, tensorcheck_challenges_4);

        let mut folded_polynomials_commitments = Vec::new();
        folded_polynomials_commitments.extend(ck.commit_folding(&tensorcheck_foldings_0));
        folded_polynomials_commitments.extend(ck.commit_folding(&tensorcheck_foldings_1));
        folded_polynomials_commitments.extend(ck.commit_folding(&tensorcheck_foldings_2));
        folded_polynomials_commitments.extend(ck.commit_folding(&tensorcheck_foldings_3));
        folded_polynomials_commitments.extend(ck.commit_folding(&tensorcheck_foldings_4));

        // add commitments to transcript
        folded_polynomials_commitments
            .iter()
            .for_each(|c| transcript.append_commitment(b"commitment", c));

        let eval_chal = transcript.get_challenge::<E::Fr>(b"evaluation-chal");
        let eval_points = [eval_chal.square(), eval_chal, -eval_chal];

        let mut folded_polynomials_evaluations = vec![];

        folded_polynomials_evaluations.extend(
            evaluate_folding(&tensorcheck_foldings_0, eval_points[1])
                .into_iter()
                .zip(evaluate_folding(&tensorcheck_foldings_0, eval_points[2]))
                .map(|(x, y)| [x, y]),
        );

        folded_polynomials_evaluations.extend(
            evaluate_folding(&tensorcheck_foldings_1, eval_points[1])
                .into_iter()
                .zip(evaluate_folding(&tensorcheck_foldings_1, eval_points[2]))
                .map(|(x, y)| [x, y]),
        );
        folded_polynomials_evaluations.extend(
            evaluate_folding(&tensorcheck_foldings_2, eval_points[1])
                .into_iter()
                .zip(evaluate_folding(&tensorcheck_foldings_2, eval_points[2]))
                .map(|(x, y)| [x, y]),
        );
        folded_polynomials_evaluations.extend(
            evaluate_folding(&tensorcheck_foldings_3, eval_points[1])
                .into_iter()
                .zip(evaluate_folding(&tensorcheck_foldings_3, eval_points[2]))
                .map(|(x, y)| [x, y]),
        );
        folded_polynomials_evaluations.extend(
            evaluate_folding(&tensorcheck_foldings_4, eval_points[1])
                .into_iter()
                .zip(evaluate_folding(&tensorcheck_foldings_4, eval_points[2]))
                .map(|(x, y)| [x, y]),
        );

        let base_polynomials_evaluations = vec![
            evaluate_base_polynomial(&mut transcript, &r1cs.witness, &eval_points),
            evaluate_base_polynomial(&mut transcript, &r_a_star, &eval_points),
            evaluate_base_polynomial(&mut transcript, &r_b_star, &eval_points),
            evaluate_base_polynomial(&mut transcript, &r_c_star, &eval_points),
            evaluate_base_polynomial(&mut transcript, &z_star, &eval_points),
            // evaluate_base_polynomial(&mut transcript, row, &eval_points),
            // evaluate_base_polynomial(&mut transcript, col, &eval_points),
            evaluate_base_polynomial(&mut transcript, &val_a, &eval_points),
            evaluate_base_polynomial(&mut transcript, &val_b, &eval_points),
            evaluate_base_polynomial(&mut transcript, &val_c, &eval_points),
            evaluate_base_polynomial(&mut transcript, &pl_sorted_r, &eval_points),
            evaluate_base_polynomial(&mut transcript, &pl_sorted_z, &eval_points),
        ];

        base_polynomials_evaluations
            .iter()
            .flatten()
            .for_each(|e| transcript.append_scalar(b"eval", e));
        folded_polynomials_evaluations
            .iter()
            .flatten()
            .for_each(|e| transcript.append_scalar(b"eval", e));
        // XXXX are the base polynomials added in the snark??

        let open_chal = transcript.get_challenge::<E::Fr>(b"open-chal");
        let open_chal_len = folded_polynomials_evaluations.len() * tensorcheck_foldings_4.len()
            + 3 * base_polynomials_evaluations.len(); // adjuct with the numebr of base polynomials
        let open_chals = powers(open_chal, open_chal_len);

        // do this foe each element.
        let evaluation_proof: crate::kzg::EvaluationProof<E> = [
            ck.open_multi_points(&r1cs.witness, &eval_points).1,
            ck.open_multi_points(&r_a_star, &eval_points).1,
            ck.open_multi_points(&r_b_star, &eval_points).1,
            ck.open_multi_points(&r_c_star, &eval_points).1,
            ck.open_multi_points(&z_star, &eval_points).1,
            ck.open_multi_points(&val_a, &eval_points).1,
            ck.open_multi_points(&val_b, &eval_points).1,
            ck.open_multi_points(&val_c, &eval_points).1,
            ck.open_multi_points(&pl_sorted_r, &eval_points).1,
            ck.open_multi_points(&pl_sorted_z, &eval_points).1,
            ck.open_folding(tensorcheck_foldings_0, &eval_points, &open_chals[3..])
                .1,
            ck.open_folding(tensorcheck_foldings_1, &eval_points, &open_chals[3..])
                .1,
            ck.open_folding(tensorcheck_foldings_2, &eval_points, &open_chals[3..])
                .1,
            ck.open_folding(tensorcheck_foldings_3, &eval_points, &open_chals[3..])
                .1,
            ck.open_folding(tensorcheck_foldings_4, &eval_points, &open_chals[3..])
                .1,
        ]
        .into_iter()
        .sum();

        let tensor_check_proof = TensorCheckProof {
            folded_polynomials_commitments,
            folded_polynomials_evaluations,
            evaluation_proof,
            base_polynomials_evaluations,
        };

        Proof {
            witness_commitment,
            zc_alpha,
            first_sumcheck_msgs: sumcheck1.prover_messages(),
            rb_star_commitment,
            rc_star_commitment,
            z_star_commitment,
            z_star_rs,
            second_sumcheck_msgs: sumcheck2.prover_messages(),
            set_r_ep,
            subset_r_ep,
            sorted_r_ep,
            sorted_r_commitment,
            set_z_ep,
            subset_z_ep,
            sorted_z_ep,
            sorted_z_commitment,
            ep_msgs: msgs,
            third_sumcheck_msgs: sumcheck3.prover_messages(),
            tensor_check_proof,
        }
    }
}
