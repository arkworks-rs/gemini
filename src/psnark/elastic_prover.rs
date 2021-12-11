//! Space-efficient preprocessing SNARK for R1CS.
use ark_ec::PairingEngine;
use ark_ff::Field;
use ark_std::borrow::Borrow;
use ark_std::One;
use merlin::Transcript;

// use crate::psnark::streams::memcheck::memcheck_streams;
// use crate::psnark::streams::plookup::plookup_streams;
use crate::psnark::Proof;

use crate::circuit::R1csStream;
use crate::kzg::CommitterKeyStream;
use crate::misc::{expand_tensor, powers, MatrixElement};
use crate::psnark::streams::plookup::plookup_streams;
use crate::psnark::streams::{
    HadamardStreamer, IndexStream, LineStream, LookupStreamer, TensorIStreamer, TensorStreamer,
    ValStream,
};
use crate::stream::Streamer;
use crate::sumcheck::proof::Sumcheck;
use crate::sumcheck::space_prover::SpaceProver;
use crate::sumcheck::streams::FoldedPolynomialTree;
use crate::transcript::GeminiTranscript;
use crate::PROTOCOL_NAME;
use crate::{entry_product, lincomb};

impl<E: PairingEngine> Proof<E> {
    /// Given as input the _streaming_ R1CS instance `r1cs`
    /// and the _streaming_ committer key `ck`,
    /// return a new _preprocessing_ SNARK using the elastic prover.
    pub fn new_elastic<SM, SG, SZ, SW>(
        r1cs: R1csStream<SM, SZ, SW>,
        ck: CommitterKeyStream<E, SG>,
    ) -> Proof<E>
    where
        SM: Streamer + Copy,
        SZ: Streamer + Copy,
        SW: Streamer,
        SG: Streamer,
        SM::Item: Borrow<MatrixElement<E::Fr>>,
        SZ::Item: Borrow<E::Fr> + Copy,
        SW::Item: Borrow<E::Fr> + Copy,
        SZ::Item: Borrow<E::Fr> + Copy,
        SZ::Item: Borrow<E::Fr> + Copy,
        SG::Item: Borrow<E::G1Affine>,
    {
        let _ahp_proof_time = start_timer!(|| "AP::Prove");
        let one = E::Fr::one();

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
        let r_c_short = (0..len)
            .map(|x| alpha.pow([1 << x as u64]))
            .collect::<Vec<_>>();
        let r_a_short = r_b_short
            .iter()
            .zip(r_c_short.iter())
            .map(|(&x, y)| x * y)
            .collect::<Vec<_>>();

        let r_a_expanded = expand_tensor(&r_a_short);
        let r_b_expanded = expand_tensor(r_b_short);
        let r_c_expanded = expand_tensor(&r_c_short);

        let r_a = TensorStreamer::new(&r_a_expanded, 1 << len);
        let r_b = TensorStreamer::new(&r_b_expanded, 1 << len);
        let r_c = TensorStreamer::new(&r_c_expanded, 1 << len);

        let row_a = LineStream::new(r1cs.a_colm);
        let row_b = LineStream::new(r1cs.b_colm);
        let row_c = LineStream::new(r1cs.c_colm);

        let col_a = IndexStream::new(r1cs.a_colm);
        let col_b = IndexStream::new(r1cs.b_colm);
        let col_c = IndexStream::new(r1cs.c_colm);

        let z_a_star = LookupStreamer {
            items: r1cs.z_a,
            indices: col_a,
        };
        let z_b_star = LookupStreamer {
            items: r1cs.z_b,
            indices: col_b,
        };
        let z_c_star = LookupStreamer {
            items: r1cs.z_c,
            indices: col_c,
        };

        let r_a_star = TensorIStreamer::new(&r_a_expanded, row_a, 1 << len);
        let r_b_star = TensorIStreamer::new(&r_b_expanded, row_b, 1 << len);
        let r_c_star = TensorIStreamer::new(&r_c_expanded, row_c, 1 << len);

        let val_a = ValStream::new(r1cs.a_colm, r1cs.nonzero);
        let val_b = ValStream::new(r1cs.b_colm, r1cs.nonzero);
        let val_c = ValStream::new(r1cs.c_colm, r1cs.nonzero);

        let rz_a_star = HadamardStreamer::new(r_a_star, z_a_star);
        let rz_b_star = HadamardStreamer::new(r_b_star, z_b_star);
        let rz_c_star = HadamardStreamer::new(r_c_star, z_c_star);

        let mut ip_val_rz_a = SpaceProver::new(val_a, rz_a_star, one);
        let mut ip_val_rz_b = SpaceProver::new(val_b, rz_b_star, one);
        let mut ip_val_rz_c = SpaceProver::new(val_c, rz_c_star, one);

        let second_sumcheck_time = start_timer!(|| "Second sumcheck");
        let second_sumcheck = Sumcheck::prove_batch(
            &mut transcript,
            [&mut ip_val_rz_a, &mut ip_val_rz_b, &mut ip_val_rz_c],
        );
        end_timer!(second_sumcheck_time);
        let second_sumcheck_messages = second_sumcheck.prover_messages();

        let mut ip_r_z_star_a = SpaceProver::new(r_a_star, z_a_star, one);
        let mut ip_r_z_star_b = SpaceProver::new(r_a_star, z_a_star, one);
        let mut ip_r_z_star_c = SpaceProver::new(r_c_star, z_c_star, one);

        let third_sumcheck_time = start_timer!(|| "Third sumcheck");
        let third_sumcheck = Sumcheck::prove_batch(
            &mut transcript,
            [&mut ip_r_z_star_a, &mut ip_r_z_star_b, &mut ip_r_z_star_c],
        );
        end_timer!(third_sumcheck_time);
        let third_sumcheck_messages = third_sumcheck.prover_messages();

        // PLOOKUP PROTOCOL
        let y = transcript.get_challenge(b"y");
        let z = transcript.get_challenge(b"zeta");

        let entry_product_time = start_timer!(|| "Entry product");

        let (pl_set_a, pl_subset_a, pl_sorted_a) = plookup_streams(&r_a, &r_a_star, &row_a, y, z);

        let (pl_set_b, pl_subset_b, ps_sorted_b) = plookup_streams(&r_b, &r_b_star, &row_b, y, z);

        let (pl_set_c, pl_subset_c, pl_sorted_c) = plookup_streams(&r_c, &r_c_star, &row_c, y, z);

        let (msgs, provers) = entry_product::new_elastic_batch(
            &mut transcript,
            &ck,
            (
                &pl_set_a,
                &pl_subset_a,
                &pl_sorted_a,
                // pl_set_b,
                // pl_subset_b,
                // pl_sorted_b,
                // pl_set_c,
                // pl_subset_c,
                // pl_sorted_c,
            ),
            &[
                E::Fr::one(),
            ],
        );
        todo!();

        // // let (
        // //     (memcheck_init_sh_a, memcheck_init_acc_a),
        // //     (memcheck_read_sh_a, memcheck_read_acc_a),
        // //     (memcheck_write_sh_a, memcheck_write_acc_a),
        // //     (memcheck_audit_sh_a, memcheck_audit_acc_a),
        // // ) = memcheck_streams(r1cs.z_a, z_a_star, col_a, y, z);
        // // let (
        // //     (memcheck_init_sh_b, memcheck_init_acc_b),
        // //     (memcheck_read_sh_b, memcheck_read_acc_b),
        // //     (memcheck_write_sh_b, memcheck_write_acc_b),
        // //     (memcheck_audit_sh_b, memcheck_audit_acc_b),
        // // ) = memcheck_streams(r1cs.z_b, z_b_star, col_b, y, z);
        // // let (
        // //     (memcheck_init_sh_c, memcheck_init_acc_c),
        // //     (memcheck_read_sh_c, memcheck_read_acc_c),
        // //     (memcheck_write_sh_c, memcheck_write_acc_c),
        // //     (memcheck_audit_sh_c, memcheck_audit_acc_c),
        // // ) = memcheck_streams(r1cs.z_c, z_c_star, col_c, y, z);

        // // let mut memcheck_init_sumcheck_a =
        // //     SpaceProver::new(memcheck_init_sh_a, memcheck_init_acc_a, one);
        // // let mut memcheck_read_sumcheck_a =
        // //     SpaceProver::new(memcheck_read_sh_a, memcheck_read_acc_a, one);
        // // let mut memcheck_write_sumcheck_a =
        // //     SpaceProver::new(memcheck_write_sh_a, memcheck_write_acc_a, one);
        // // let mut memcheck_audit_sumcheck_a =
        // //     SpaceProver::new(memcheck_audit_sh_a, memcheck_audit_acc_a, one);
        // // let mut memcheck_init_sumcheck_b =
        // //     SpaceProver::new(memcheck_init_sh_b, memcheck_init_acc_b, one);
        // // let mut memcheck_read_sumcheck_b =
        // //     SpaceProver::new(memcheck_read_sh_b, memcheck_read_acc_b, one);
        // // let mut memcheck_write_sumcheck_b =
        // //     SpaceProver::new(memcheck_write_sh_b, memcheck_write_acc_b, one);
        // // let mut memcheck_audit_sumcheck_b =
        // //     SpaceProver::new(memcheck_audit_sh_b, memcheck_audit_acc_b, one);
        // // let mut memcheck_init_sumcheck_c =
        // //     SpaceProver::new(memcheck_init_sh_c, memcheck_init_acc_c, one);
        // // let mut memcheck_read_sumcheck_c =
        // //     SpaceProver::new(memcheck_read_sh_c, memcheck_read_acc_c, one);
        // // let mut memcheck_write_sumcheck_c =
        // //     SpaceProver::new(memcheck_write_sh_c, memcheck_write_acc_c, one);
        // // let mut memcheck_audit_sumcheck_c =
        // //     SpaceProver::new(memcheck_audit_sh_c, memcheck_audit_acc_c, one);
        // let mut ep_set_sumcheck_a = SpaceProver::new(&pl_set_sh_a, &pl_set_acc_a, one);
        // let mut ep_subset_sumcheck_a = SpaceProver::new(&pl_subset_sh_a, &pl_subset_acc_a, one);
        // let mut ep_sorted_sumcheck_a = SpaceProver::new(&pl_sorted_sh_a, &pl_sorted_acc_a, one);
        // let mut ep_set_sumcheck_b = SpaceProver::new(&pl_set_sh_b, &pl_set_acc_b, one);
        // let mut ep_subset_sumcheck_b = SpaceProver::new(&pl_subset_sh_b, &pl_subset_acc_b, one);
        // let mut ep_sorted_sumcheck_b = SpaceProver::new(&pl_sorted_sh_b, &pl_sorted_acc_b, one);
        // let mut ep_set_sumcheck_c = SpaceProver::new(&pl_set_sh_c, &pl_set_acc_c, one);
        // let mut ep_subset_sumcheck_c = SpaceProver::new(&pl_subset_sh_c, &pl_subset_acc_c, one);
        // let mut ep_sorted_sumcheck_c = SpaceProver::new(&pl_sorted_sh_c, &pl_sorted_acc_c, one);

        // let ep_sumcheck = Sumcheck::prove_batch(
        //     &mut transcript,
        //     [
        //         // plookup A
        //         &mut ep_set_sumcheck_a,
        //         &mut ep_subset_sumcheck_a,
        //         &mut ep_sorted_sumcheck_a,
        //         // plookup B
        //         &mut ep_set_sumcheck_b,
        //         &mut ep_subset_sumcheck_b,
        //         &mut ep_sorted_sumcheck_b,
        //         // plookup C
        //         &mut ep_set_sumcheck_c,
        //         &mut ep_subset_sumcheck_c,
        //         &mut ep_sorted_sumcheck_c,
        //         // // memcheck A
        //         // &mut memcheck_init_sumcheck_a,
        //         // &mut memcheck_read_sumcheck_a,
        //         // &mut memcheck_write_sumcheck_a,
        //         // &mut memcheck_audit_sumcheck_a,
        //         // // memcheck B
        //         // &mut memcheck_init_sumcheck_b,
        //         // &mut memcheck_read_sumcheck_b,
        //         // &mut memcheck_write_sumcheck_b,
        //         // &mut memcheck_audit_sumcheck_b,
        //         // // memcheck C
        //         // &mut memcheck_init_sumcheck_c,
        //         // &mut memcheck_read_sumcheck_c,
        //         // &mut memcheck_write_sumcheck_c,
        //         // &mut memcheck_audit_sumcheck_c,
        //     ],
        // );
        // let ep_sumcheck_messages = ep_sumcheck.prover_messages();

        // end_timer!(entry_product_time);

        // let eta = transcript.get_challenge(b"eta");
        // let eta_batch_challenges = powers(eta, 3);
        // let vals_stream = lincomb!((val_a, val_b, val_c), &eta_batch_challenges);
        // let vals_challenges = &first_sumcheck.challenges;

        // let rstars_stream = lincomb!((r_a_star, r_b_star, r_c_star), &eta_batch_challenges);
        // let rstars_challenges = &first_sumcheck.challenges;

        // let zstars_stream = lincomb!((z_a_star, z_b_star, z_c_star), &eta_batch_challenges);
        // let zstars_challenges = &first_sumcheck.challenges;

        // let gamma = transcript.get_challenge::<E::Fr>(b"gamma");
        // let gammas = powers(gamma, vals_challenges.len() * 2000);
        // let beta = transcript.get_challenge::<E::Fr>(b"beta");

        // let consistency_check_time = start_timer!(|| "Consistency check");

        // todo!();
        // let ep_lincomb = crate::lincomb!(
        //     (
        //         // memcheck_init_sh_a,
        //         // memcheck_init_sh_b,
        //         // memcheck_init_sh_c,
        //         // memcheck_init_acc_a,
        //         // memcheck_init_acc_b,
        //         // memcheck_init_acc_c,
        //         // memcheck_read_sh_a,
        //         // memcheck_read_sh_b,
        //         // memcheck_read_sh_c,
        //         // memcheck_read_acc_a,
        //         // memcheck_read_acc_b,
        //         // memcheck_read_acc_c,
        //         // memcheck_write_sh_a,
        //         // memcheck_write_sh_b,
        //         // memcheck_write_sh_c,
        //         // memcheck_write_acc_a,
        //         // memcheck_write_acc_b,
        //         // memcheck_write_acc_c,
        //         // memcheck_audit_sh_a,
        //         // memcheck_audit_sh_b,
        //         // memcheck_audit_sh_c,
        //         // memcheck_audit_acc_a,
        //         // memcheck_audit_acc_b,
        //         // memcheck_audit_acc_c,
        //         // pl_sorted_sh_a,
        //         // pl_sorted_sh_b,
        //         // pl_sorted_sh_c,
        //         // pl_sorted_acc_a,
        //         // pl_sorted_acc_b,
        //         // pl_sorted_acc_c,
        //         // pl_set_sh_a,
        //         // pl_set_sh_b,
        //         // pl_set_sh_c,
        //         // pl_set_acc_a,
        //         // pl_set_acc_b,
        //         // pl_set_acc_c,
        //         // pl_subset_sh_a,
        //         // pl_subset_sh_b,
        //         // pl_subset_sh_c,
        //         // pl_subset_acc_a,
        //         // pl_subset_acc_b,
        //         // pl_subset_acc_c
        //     ),
        //     &gammas
        // );

        // // XXX. check challenges here.
        // let ep_folds = FoldedPolynomialTree::new(&ep_lincomb, &ep_sumcheck.challenges);
        // let vals_folds = FoldedPolynomialTree::new(&vals_stream, vals_challenges);
        // let rstars_folds = FoldedPolynomialTree::new(&rstars_stream, rstars_challenges);
        // let zstars_folds = FoldedPolynomialTree::new(&zstars_stream, zstars_challenges);

        // let evaluation_points = [beta.square(), beta, -beta];
        // let (_reminders, ep_proof) = ck.open_folding(ep_folds, &evaluation_points, &gammas);
        // let (_reminders, vals_proof) = ck.open_folding(vals_folds, &evaluation_points, &gammas);
        // let (_reminders, zstars_proof) = ck.open_folding(zstars_folds, &evaluation_points, &gammas);
        // let (_reminders, rstars_proof) = ck.open_folding(rstars_folds, &evaluation_points, &gammas);
        // let proofs = ep_proof + vals_proof + zstars_proof + rstars_proof;

        // let commitments = Vec::new();
        // let evaluations = Vec::new();
        // end_timer!(consistency_check_time);

        // Proof {
        //     first_sumcheck_messages,
        //     second_sumcheck_messages,
        //     third_sumcheck_messages,
        //     ep_sumcheck_messages,
        //     commitments,
        //     proofs,
        //     evaluations,
        // }
    }
}
