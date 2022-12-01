//! Space-efficient preprocessing SNARK for R1CS.
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_std::borrow::Borrow;
use ark_std::boxed::Box;
use ark_std::vec::Vec;
use ark_std::One;
use merlin::Transcript;

use crate::circuit::R1csStream;
use crate::iterable::slice::IterableRange;
use crate::iterable::Iterable;
use crate::kzg::{CommitterKeyStream, EvaluationProof};
use crate::misc::{evaluate_be, hadamard, ip_unsafe, powers, powers2, strip_last, MatrixElement};
use crate::psnark::streams::{
    AlgebraicHash, HadamardStreamer, IntoField, JointColStream, JointRowStream, JointValStream,
    LookupStreamer, LookupTensorStreamer, Tensor,
};
use crate::psnark::{Index, Proof};
use crate::subprotocols::entryproduct::streams::entry_product_streams;
use crate::subprotocols::entryproduct::EntryProduct;
use crate::subprotocols::plookup::streams::{plookup_streams, SortedStreamer};
use crate::subprotocols::sumcheck::proof::Sumcheck;
use crate::subprotocols::sumcheck::streams::FoldedPolynomialTree;
use crate::subprotocols::sumcheck::ElasticProver;
use crate::subprotocols::tensorcheck::{evaluate_folding, TensorcheckProof};
use crate::transcript::GeminiTranscript;
use crate::{lincomb, PROTOCOL_NAME};

#[cfg(feature = "parallel")]
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};

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
    let mut evaluations_w = [F::zero(); 3];
    cfg_iter!(eval_points)
        .zip(cfg_iter_mut!(evaluations_w))
        .for_each(|(eval_point, dst)| *dst = evaluate_be(base_polynomial.iter(), eval_point));

    evaluations_w
        .iter()
        .for_each(|e| transcript.append_serializable(b"eval", &e));
    evaluations_w
}

impl<E: Pairing> Proof<E> {
    /// Given as input the _streaming_ R1CS instance `r1cs`
    /// and the _streaming_ committer key `ck`,
    /// return a new _preprocessing_ SNARK using the elastic prover.
    pub fn new_elastic<SM, SG, SZ, SW>(
        ck: &CommitterKeyStream<E, SG>,
        r1cs: &R1csStream<SM, SZ, SW>,
        index: &Index<E>,
        max_msm_buffer: usize,
    ) -> Proof<E>
    where
        SM: Iterable + Copy,
        SZ: Iterable + Copy,
        SW: Iterable + Copy,
        SG: Iterable,
        SM::Item: Borrow<MatrixElement<E::ScalarField>>,
        SZ::Item: Borrow<E::ScalarField> + Copy,
        SW::Item: Borrow<E::ScalarField>,
        SZ::Item: Borrow<E::ScalarField>,
        SG::Item: Borrow<E::G1Affine>,
    {
        let psnark_time = start_timer!(|| module_path!());
        let mut transcript = Transcript::new(PROTOCOL_NAME);
        // send the vector w
        let witness_commitment_time = start_timer!(|| "Commitment to w");
        let witness_commitment = ck.commit(&r1cs.witness);
        end_timer!(witness_commitment_time);

        // send witness, receive challenge.
        transcript.append_serializable(b"witness", &witness_commitment);
        transcript.append_serializable(b"ck", &ck.powers_of_g2);
        transcript.append_serializable(b"instance", &index.as_slice());
        let alpha = transcript.get_challenge(b"alpha");

        // send evaluation of zc(alpha)
        let zc_alpha = evaluate_be(r1cs.z_c.iter(), &alpha);
        transcript.append_serializable(b"zc(alpha)", &zc_alpha);

        // run the sumcheck for z_a and z_b with twist alpha
        let sumcheck_time = start_timer!(|| "sumcheck1");
        let sumcheck1 = Sumcheck::new_space(&mut transcript, r1cs.z_a, r1cs.z_b, alpha);
        end_timer!(sumcheck_time);

        let row_sorted = JointRowStream::new(
            &r1cs.a_rowmaj,
            &r1cs.b_rowmaj,
            &r1cs.c_rowmaj,
            r1cs.nonzero,
            r1cs.joint_len,
        );
        let row = JointColStream::new(
            &r1cs.a_colmaj,
            &r1cs.b_colmaj,
            &r1cs.c_colmaj,
            r1cs.nonzero,
            r1cs.joint_len,
        );
        // When considering the row-major streams,
        // the sparse representation is (val, row)
        // which ends up filled in SparseMatrixStream with (col, row, val)
        // and therefore with JointRowStream cut in the first element, col
        // (Yes I know the name is miserable.)
        let col = JointRowStream::new(
            &r1cs.a_colmaj,
            &r1cs.b_colmaj,
            &r1cs.c_colmaj,
            r1cs.nonzero,
            r1cs.joint_len,
        );
        let val_a = JointValStream::new(
            &r1cs.a_colmaj,
            &r1cs.b_colmaj,
            &r1cs.c_colmaj,
            r1cs.nonzero,
            r1cs.joint_len,
        );
        let val_b = JointValStream::new(
            &r1cs.b_colmaj,
            &r1cs.c_colmaj,
            &r1cs.a_colmaj,
            r1cs.nonzero,
            r1cs.joint_len,
        );
        let val_c = JointValStream::new(
            &r1cs.c_colmaj,
            &r1cs.b_colmaj,
            &r1cs.a_colmaj,
            r1cs.nonzero,
            r1cs.joint_len,
        );
        // lookup in z for the nonzero positions
        let z_star = LookupStreamer::new(&r1cs.z, &col);
        // compose the randomness for the A-, B-, C-matrices
        let len = sumcheck1.challenges.len();
        let r_short = &sumcheck1.challenges;
        let alpha_short = &powers2(alpha, len);
        let ralpha_short = &hadamard(r_short, alpha_short);
        // expand the randomness for each matrix
        let rs = Tensor(r_short);
        let alphas = Tensor(alpha_short);
        // lookup in the randomness for the nonzero positions
        let ralpha_star = LookupTensorStreamer::new(ralpha_short, &row);
        let r_star = LookupTensorStreamer::new(r_short, &row);
        let alpha_star = LookupTensorStreamer::new(alpha_short, &row);

        // commit to the looked up vectors
        let ralpha_star_commitment = ck.commit(&ralpha_star);
        let r_star_commitment = ck.commit(&r_star);
        let alpha_star_commitment = ck.commit(&alpha_star);
        let r_star_commitments = [
            ralpha_star_commitment,
            r_star_commitment,
            alpha_star_commitment,
        ];
        let z_star_commitment = ck.commit(&z_star);

        transcript.append_serializable(b"ra*", &ralpha_star_commitment);
        transcript.append_serializable(b"rb*", &r_star_commitment);
        transcript.append_serializable(b"rc*", &alpha_star_commitment);
        transcript.append_serializable(b"z*", &z_star_commitment);

        // second sumcheck
        // batch the randomness for the three matrices and invoke the sumcheck protocol.
        let challenge = transcript.get_challenge::<E::ScalarField>(b"chal");
        let challenges = powers(challenge, 3);
        // assert_eq!(val_a.len(), val_b.len());
        assert_eq!(val_a.len(), val_c.len());
        let ralpha_star_val_a = HadamardStreamer::new(&ralpha_star, &val_a);
        let r_star_val_b = HadamardStreamer::new(&r_star, &val_b);
        let alpha_star_val_c = HadamardStreamer::new(&alpha_star, &val_c);
        let rhs = lincomb!(
            (ralpha_star_val_a, r_star_val_b, alpha_star_val_c),
            &challenges
        );

        let sumcheck_time = start_timer!(|| "sumcheck2");
        let sumcheck2 = Sumcheck::new_elastic(&mut transcript, z_star, rhs, E::ScalarField::one());
        end_timer!(sumcheck_time);

        // Lookup protocol (plookup) for r_a \subset r, z* \subset r
        let zeta = transcript.get_challenge(b"zeta");

        let idx_r = IterableRange(rs.len());
        let idx_alpha = IterableRange(alphas.len());
        let idx_z = IterableRange(r1cs.z.len());

        let hashed_alpha = AlgebraicHash::new(&alphas, &idx_alpha, zeta);
        let hashed_alphastar = AlgebraicHash::new(&alpha_star, &row, zeta);
        let hashed_r = AlgebraicHash::new(&rs, &idx_r, zeta);
        let hashed_rstar = AlgebraicHash::new(&r_star, &row, zeta);
        let hashed_z = AlgebraicHash::new(&r1cs.z, &idx_z, zeta);
        let hashed_zstar = AlgebraicHash::new(&z_star, &col, zeta);

        let sorted_r = SortedStreamer::new(&hashed_r, &row_sorted);
        let sorted_alpha = SortedStreamer::new(&hashed_alpha, &row_sorted);
        let sorted_z = SortedStreamer::new(&hashed_z, &col);
        // compute the commitments to the sorted polynomials
        let sorted_r_commitment = ck.commit(&sorted_r);
        let sorted_alpha_commitment = ck.commit(&sorted_alpha);
        let sorted_z_commitment = ck.commit(&sorted_z);

        transcript.append_serializable(b"sorted_alpha_commitment", &sorted_alpha_commitment);
        transcript.append_serializable(b"sorted_r_commitment", &sorted_r_commitment);
        transcript.append_serializable(b"sorted_z_commitment", &sorted_z_commitment);

        let gamma = transcript.get_challenge(b"gamma");
        let chi = transcript.get_challenge(b"chi");

        let (pl_set_alpha, pl_subset_alpha, pl_sorted_alpha) =
            plookup_streams(&hashed_alphastar, &hashed_alpha, &row_sorted, gamma, chi);
        let (pl_set_r, pl_subset_r, pl_sorted_r) =
            plookup_streams(&hashed_rstar, &hashed_r, &row_sorted, gamma, chi);
        let (pl_set_z, pl_subset_z, pl_sorted_z) =
            plookup_streams(&hashed_zstar, &hashed_z, &col, gamma, chi);
        // compute the products to send to the verifier.
        // XXXX. There is no need to compute the sorted ones as they can be derived.
        let set_alpha_ep = pl_set_alpha.iter().product();
        let subset_alpha_ep = pl_subset_alpha.iter().product();
        let sorted_alpha_ep = pl_sorted_alpha.iter().product::<E::ScalarField>();
        let set_r_ep = pl_set_r.iter().product();
        let subset_r_ep = pl_subset_r.iter().product();
        let sorted_r_ep = pl_sorted_r.iter().product::<E::ScalarField>();
        let set_z_ep = pl_set_z.iter().product();
        let subset_z_ep = pl_subset_z.iter().product();
        let sorted_z_ep = pl_sorted_z.iter().product::<E::ScalarField>();

        transcript.append_serializable(b"set_r_ep", &set_alpha_ep);
        transcript.append_serializable(b"subset_r_ep", &subset_alpha_ep);
        transcript.append_serializable(b"set_r_ep", &set_r_ep);
        transcript.append_serializable(b"subset_r_ep", &subset_r_ep);
        transcript.append_serializable(b"set_z_ep", &set_z_ep);
        transcript.append_serializable(b"subset_z_ep", &subset_z_ep);

        // _nota bene_: the variable `ep_r` needs to be defined _before_ `provers` is allocated,
        // so that its lifetime will not conflict with the lifetime of the `provers`.
        let ep_r = Tensor(&sumcheck2.challenges);
        let lhs_ralpha_star = HadamardStreamer::new(&ralpha_star, &ep_r);
        let lhs_r_star = HadamardStreamer::new(&r_star, &ep_r);
        let lhs_alpha_star = HadamardStreamer::new(&alpha_star, &ep_r);

        // compute the entry product so to verify the lookup relation.
        let EntryProduct {
            msgs,
            chal: psi,
            mut provers,
        } = EntryProduct::new_elastic_batch(
            &mut transcript,
            ck,
            (
                &pl_set_r,
                &pl_subset_r,
                &pl_sorted_r,
                &pl_set_alpha,
                &pl_subset_alpha,
                &pl_sorted_alpha,
                &pl_set_z,
                &pl_subset_z,
                &pl_sorted_z,
            ),
            &[
                set_r_ep,
                subset_r_ep,
                sorted_r_ep,
                set_alpha_ep,
                subset_alpha_ep,
                sorted_alpha_ep,
                set_z_ep,
                subset_z_ep,
                sorted_z_ep,
            ],
        );

        // At the end of the entry product protocol, we have some inneer-product claims.
        // We don't use them yet. Instead:
        // ask an evaluation of r_a* at a random point

        let (pl_set_sh_r, pl_set_acc_r) = entry_product_streams(&pl_set_r);
        let (pl_subset_sh_r, pl_subset_acc_r) = entry_product_streams(&pl_subset_r);
        let (pl_sorted_sh_r, pl_sorted_acc_r) = entry_product_streams(&pl_sorted_r);
        let (pl_set_sh_alpha, pl_set_acc_alpha) = entry_product_streams(&pl_set_alpha);
        let (pl_subset_sh_alpha, pl_subset_acc_alpha) = entry_product_streams(&pl_subset_alpha);
        let (pl_sorted_sh_alpha, pl_sorted_acc_alpha) = entry_product_streams(&pl_sorted_alpha);
        let (pl_set_sh_z, pl_set_acc_z) = entry_product_streams(&pl_set_z);
        let (pl_subset_sh_z, pl_subset_acc_z) = entry_product_streams(&pl_subset_z);
        let (pl_sorted_sh_z, pl_sorted_acc_z) = entry_product_streams(&pl_sorted_z);

        let open_chal = transcript.get_challenge::<E::ScalarField>(b"open-chal");
        let open_chals = powers(open_chal, 10);
        let polynomial = lincomb!(
            (
                ralpha_star,
                pl_set_acc_r,
                pl_subset_acc_r,
                pl_sorted_acc_r,
                pl_set_acc_alpha,
                pl_subset_acc_alpha,
                pl_sorted_acc_alpha,
                pl_set_acc_z,
                pl_subset_acc_z,
                pl_sorted_acc_z
            ),
            &open_chals
        );
        let ralpha_star_acc_mu_proof = ck.open(&polynomial, &psi, max_msm_buffer).1;

        let ralpha_star_acc_mu_evals = vec![
            evaluate_be(ralpha_star.iter(), &psi),
            evaluate_be(pl_set_acc_r.iter(), &psi),
            evaluate_be(pl_subset_acc_r.iter(), &psi),
            evaluate_be(pl_sorted_acc_r.iter(), &psi),
            evaluate_be(pl_set_acc_alpha.iter(), &psi),
            evaluate_be(pl_subset_acc_alpha.iter(), &psi),
            evaluate_be(pl_sorted_acc_alpha.iter(), &psi),
            evaluate_be(pl_set_acc_z.iter(), &psi),
            evaluate_be(pl_subset_acc_z.iter(), &psi),
            evaluate_be(pl_sorted_acc_z.iter(), &psi),
        ];
        // compute the claimed entry products for
        // <r_a* \otimes (sumcheck chals), val_a>
        // <r_b* \otimes (sumcheck chals), val_b>
        // <r_c* \otimes (sumcheck chals), val_c> (not needed as it can be derived)
        let r_val_chal_a = ip_unsafe(lhs_ralpha_star.iter(), val_a.iter());
        let r_val_chal_b = ip_unsafe(lhs_r_star.iter(), val_b.iter());

        ralpha_star_acc_mu_evals
            .iter()
            .for_each(|e| transcript.append_serializable(b"ralpha_star_acc_mu", e));
        transcript.append_serializable(b"ralpha_star_mu_proof", &ralpha_star_acc_mu_proof);

        // Add to the list of inner-products claims (obtained from the entry product)
        // additional inner products:
        provers.push(Box::new(ElasticProver::new(
            lhs_ralpha_star,
            val_a,
            E::ScalarField::one(),
        )));
        provers.push(Box::new(ElasticProver::new(
            lhs_r_star,
            val_b,
            E::ScalarField::one(),
        )));
        provers.push(Box::new(ElasticProver::new(
            lhs_alpha_star,
            val_c,
            E::ScalarField::one(),
        )));
        provers.push(Box::new(ElasticProver::new(
            r_star.clone(),
            alpha_star.clone(),
            psi,
        )));

        let sumcheck_time = start_timer!(|| "sumcheck3");
        let sumcheck3 = Sumcheck::prove_batch(&mut transcript, provers);
        end_timer!(sumcheck_time);

        // tensorcheck protocol
        let tc_time = start_timer!(|| "tensorcheck");

        let tc_chal = transcript.get_challenge::<E::ScalarField>(b"batch_challenge");
        let tc_challenges = powers(tc_chal, 13);

        let body_polynomials_0 = &lincomb!(
            (
                pl_set_acc_r,
                pl_subset_acc_r,
                pl_sorted_acc_r,
                pl_set_acc_alpha,
                pl_subset_acc_alpha,
                pl_sorted_acc_alpha,
                pl_set_acc_z,
                pl_subset_acc_z,
                pl_sorted_acc_z,
                r_star
            ),
            &tc_challenges
        );
        let body_polynomials_1 = &lincomb!(
            (
                pl_set_sh_r,
                pl_subset_sh_r,
                pl_sorted_sh_r,
                pl_set_sh_alpha,
                pl_subset_sh_alpha,
                pl_sorted_sh_alpha,
                pl_set_sh_z,
                pl_subset_sh_z,
                pl_sorted_sh_z,
                val_a,
                val_b,
                val_c,
                alpha_star
            ),
            &tc_challenges
        );
        let body_polynomials_2 = &z_star;
        let body_polynomials_3 = &lincomb!((ralpha_star, r_star, alpha_star), &tc_challenges);

        let psi_squares = powers2(psi, sumcheck3.challenges.len());
        // 1st challenges:
        let tensorcheck_challenges_0 = hadamard(&sumcheck3.challenges, &psi_squares);
        let tensorcheck_challenges_0 = strip_last(&tensorcheck_challenges_0);
        // 2nd challenges:
        let tensorcheck_challenges_1 = strip_last(&sumcheck3.challenges);
        // 3rd challenges:
        let tensorcheck_challenges_2 = strip_last(&sumcheck2.challenges);
        // 4th challenges:
        let tensorcheck_challenges_3 = hadamard(
            &sumcheck2.challenges,
            &sumcheck3.challenges[..sumcheck2.challenges.len()],
        );
        let tensorcheck_challenges_3 = strip_last(&tensorcheck_challenges_3);

        let tensorcheck_foldings_0 =
            FoldedPolynomialTree::new(body_polynomials_0, tensorcheck_challenges_0);
        let tensorcheck_foldings_1 =
            FoldedPolynomialTree::new(body_polynomials_1, tensorcheck_challenges_1);
        let tensorcheck_foldings_2 =
            FoldedPolynomialTree::new(body_polynomials_2, tensorcheck_challenges_2);
        let tensorcheck_foldings_3 =
            FoldedPolynomialTree::new(body_polynomials_3, tensorcheck_challenges_3);

        let mut folded_polynomials_commitments = Vec::new();
        folded_polynomials_commitments
            .extend(ck.commit_folding(&tensorcheck_foldings_0, max_msm_buffer));
        folded_polynomials_commitments
            .extend(ck.commit_folding(&tensorcheck_foldings_1, max_msm_buffer));
        folded_polynomials_commitments
            .extend(ck.commit_folding(&tensorcheck_foldings_2, max_msm_buffer));
        folded_polynomials_commitments
            .extend(ck.commit_folding(&tensorcheck_foldings_3, max_msm_buffer));

        // add commitments to transcript
        folded_polynomials_commitments
            .iter()
            .for_each(|c| transcript.append_serializable(b"commitment", c));

        let eval_chal = transcript.get_challenge::<E::ScalarField>(b"evaluation-chal");

        let eval_points = [eval_chal.square(), eval_chal, -eval_chal];

        let evaluations_time = start_timer!(|| "evaluations");
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

        let field_row = IntoField::<_, E::ScalarField>::new(&row);
        let field_col = IntoField::<_, E::ScalarField>::new(&col);
        let base_polynomials_evaluations = vec![
            evaluate_base_polynomial(&mut transcript, &r1cs.witness, &eval_points),
            evaluate_base_polynomial(&mut transcript, &ralpha_star, &eval_points),
            evaluate_base_polynomial(&mut transcript, &r_star, &eval_points),
            evaluate_base_polynomial(&mut transcript, &alpha_star, &eval_points),
            evaluate_base_polynomial(&mut transcript, &z_star, &eval_points),
            evaluate_base_polynomial(&mut transcript, &field_row, &eval_points),
            evaluate_base_polynomial(&mut transcript, &field_col, &eval_points),
            evaluate_base_polynomial(&mut transcript, &val_a, &eval_points),
            evaluate_base_polynomial(&mut transcript, &val_b, &eval_points),
            evaluate_base_polynomial(&mut transcript, &val_c, &eval_points),
            // sorted polynomials r*, alpha*, z*
            evaluate_base_polynomial(&mut transcript, &sorted_r, &eval_points),
            evaluate_base_polynomial(&mut transcript, &sorted_alpha, &eval_points),
            evaluate_base_polynomial(&mut transcript, &sorted_z, &eval_points),
            // accumulated polynomials r*
            evaluate_base_polynomial(&mut transcript, &pl_set_acc_r, &eval_points),
            evaluate_base_polynomial(&mut transcript, &pl_subset_acc_r, &eval_points),
            evaluate_base_polynomial(&mut transcript, &pl_sorted_acc_r, &eval_points),
            // accumulated polynomials alpha*
            evaluate_base_polynomial(&mut transcript, &pl_set_acc_alpha, &eval_points),
            evaluate_base_polynomial(&mut transcript, &pl_subset_acc_alpha, &eval_points),
            evaluate_base_polynomial(&mut transcript, &pl_sorted_acc_alpha, &eval_points),
            // accumulated polynomials z*
            evaluate_base_polynomial(&mut transcript, &pl_set_acc_z, &eval_points),
            evaluate_base_polynomial(&mut transcript, &pl_subset_acc_z, &eval_points),
            evaluate_base_polynomial(&mut transcript, &pl_sorted_acc_z, &eval_points),
        ];
        end_timer!(evaluations_time);

        folded_polynomials_evaluations
            .iter()
            .flatten()
            .for_each(|e| transcript.append_serializable(b"eval", e));

        let open_chal = transcript.get_challenge::<E::ScalarField>(b"open-chal");

        let open_chal_len = folded_polynomials_evaluations.len() * tensorcheck_foldings_2.depth()
            + 3 * base_polynomials_evaluations.len();
        let open_chals = powers(open_chal, open_chal_len);

        let open_chals_0 = &open_chals[22..];
        let open_chals_1 = &open_chals_0[tensorcheck_foldings_0.depth()..];
        let open_chals_2 = &open_chals_1[tensorcheck_foldings_1.depth()..];
        let open_chals_3 = &open_chals_2[tensorcheck_foldings_2.depth()..];

        let partial_eval_stream = lincomb!(
            (
                r1cs.witness,
                ralpha_star,
                r_star,
                alpha_star,
                z_star,
                field_row,
                field_col,
                val_a,
                val_b,
                val_c,
                sorted_r,
                sorted_alpha,
                sorted_z,
                pl_set_acc_r,
                pl_subset_acc_r,
                pl_sorted_acc_r,
                pl_set_acc_alpha,
                pl_subset_acc_alpha,
                pl_sorted_acc_alpha,
                pl_set_acc_z,
                pl_subset_acc_z,
                pl_sorted_acc_z
            ),
            &open_chals[..22]
        );
        // do this for each element.
        let open_time = start_timer!(|| "opening time");
        let evaluation_proof = EvaluationProof(
            ck.open_multi_points(&partial_eval_stream, &eval_points, max_msm_buffer)
                .1
                 .0
                + ck.open_folding(
                    tensorcheck_foldings_0,
                    &eval_points,
                    open_chals_0,
                    max_msm_buffer,
                )
                .1
                 .0
                + ck.open_folding(
                    tensorcheck_foldings_1,
                    &eval_points,
                    open_chals_1,
                    max_msm_buffer,
                )
                .1
                 .0
                + ck.open_folding(
                    tensorcheck_foldings_2,
                    &eval_points,
                    open_chals_2,
                    max_msm_buffer,
                )
                .1
                 .0
                + ck.open_folding(
                    tensorcheck_foldings_3,
                    &eval_points,
                    open_chals_3,
                    max_msm_buffer,
                )
                .1
                 .0,
        );
        end_timer!(open_time);

        let tensorcheck_proof = TensorcheckProof {
            folded_polynomials_commitments,
            folded_polynomials_evaluations,
            evaluation_proof,
            base_polynomials_evaluations,
        };
        end_timer!(tc_time);

        end_timer!(psnark_time);
        Proof {
            witness_commitment,
            zc_alpha,
            first_sumcheck_msgs: sumcheck1.prover_messages(),
            r_star_commitments,
            z_star_commitment,
            second_sumcheck_msgs: sumcheck2.prover_messages(),
            set_r_ep,
            subset_r_ep,
            sorted_r_commitment,
            set_alpha_ep,
            subset_alpha_ep,
            sorted_alpha_commitment,
            set_z_ep,
            subset_z_ep,
            sorted_z_commitment,
            ep_msgs: msgs,
            ralpha_star_acc_mu_evals,
            ralpha_star_acc_mu_proof,
            rstars_vals: [r_val_chal_a, r_val_chal_b],
            third_sumcheck_msgs: sumcheck3.prover_messages(),
            tensorcheck_proof,
        }
    }
}
