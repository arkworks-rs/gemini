use ark_std::vec::Vec;
use ark_std::{log2, One};
use merlin::Transcript;

use super::module::*;
use crate::errors::VerificationError;
use crate::errors::VerificationResult;
use crate::herring::proof::Sumcheck;
use crate::herring::prover::Prover;
use crate::herring::prover::SumcheckMsg;
use crate::herring::time_prover::halve;
use crate::herring::time_prover::split_fold_into;
use crate::herring::time_prover::Witness;
use crate::herring::TimeProver;
use crate::transcript::GeminiTranscript;
use ark_bls12_381::Fr;
use ark_ec::CurveGroup;
use ark_ec::Group;
use ark_ec::VariableBaseMSM;
use ark_ff::{Field, Zero};
use ark_std::UniformRand;
use rand::Rng;

pub struct InnerProductProof {
    sumcheck: Sumcheck<Bls12Module>,
    batch_challenges: Vec<Fr>,
    foldings_ff: Vec<(FrWrapper, FrWrapper)>,
    foldings_fg1: Vec<(G1, FrWrapper)>,
    foldings_fg2: Vec<(G2, FrWrapper)>,
}

pub struct Crs {
    g1s: Vec<G1>,
    g2s: Vec<G2>,
}

pub struct Vrs {
    vk1: Vec<(Gt, Gt)>,
    vk2: Vec<(Gt, Gt)>,
}

impl Crs {
    pub fn new(rng: &mut impl Rng, d: usize) -> Self {
        let g1s: Vec<G1> = (0..d).map(|_| G1::rand(rng)).collect();
        let g2s: Vec<G2> = (0..d).map(|_| G2::rand(rng)).collect();
        Self { g1s, g2s }
    }

    pub fn commit_g1(&self, scalars: &[Fr]) -> G1 {
        assert!(self.g1s.len() > scalars.len());
        let bases = G1::normalize_batch(&self.g1s);
        G1::msm(&bases, scalars)
    }

    pub fn commit_g2(&self, scalars: &[Fr]) -> G2 {
        assert!(self.g2s.len() > scalars.len());
        let bases = G2::normalize_batch(&self.g2s);
        G2::msm(&bases, scalars)
    }
}

impl<'a> From<&'a Crs> for Vrs {
    fn from(crs: &'a Crs) -> Self {
        let mut vk1 = Vec::new();
        let mut vk2 = Vec::new();

        for j in 1..log2(crs.g1s.len()) {
            let size = 1 << j;

            let g1es = Bls12Module::ip(crs.g1s.iter().step_by(2), crs.g2s.iter().take(size));
            let g1os =
                Bls12Module::ip(crs.g1s.iter().skip(1).step_by(2), crs.g2s.iter().take(size));

            let g2es = Bls12Module::ip(crs.g1s.iter().take(size), crs.g2s.iter().step_by(2));
            let g2os =
                Bls12Module::ip(crs.g1s.iter().take(size), crs.g2s.iter().skip(1).step_by(2));

            vk1.push((g1es, g1os));
            vk2.push((g2es, g2os));
        }

        Self { vk1, vk2 }
    }
}

impl InnerProductProof {
    pub fn verify_transcript(
        &self,
        vrs: &Vrs,
        comm_a: G1,
        comm_b: G2,
        y: Fr,
    ) -> VerificationResult {
        let y = FrWrapper(y);

        let challenges = self
            .sumcheck
            .challenges
            .iter()
            .rev()
            .skip(1)
            .cloned()
            .collect::<Vec<_>>();

        let mut g1s = vrs
            .vk1
            .iter()
            .zip(&challenges)
            .map(|(&(even, odd), challenge)| even + odd * challenge)
            .collect::<Vec<_>>();
        let mut g2s = vrs
            .vk2
            .iter()
            .zip(&challenges)
            .map(|(&(even, odd), challenge)| even + odd * challenge)
            .collect::<Vec<_>>();

        g1s.reverse();
        g2s.reverse();
        g1s.push(Gt::zero());
        g2s.push(Gt::zero());

        let claim_ff = FFModule::p(y, FrWrapper(Fr::one()));
        let claim_fg1 = Bls12Module::p(comm_a, G2::generator());
        let claim_fg2 = Bls12Module::p(G1::generator(), comm_b);
        let mut reduced_claim = claim_ff + claim_fg1 + claim_fg2;
        let rounds = self.sumcheck.messages.len();
        assert_eq!(self.sumcheck.messages.len(), self.sumcheck.challenges.len());
        for i in 0..rounds {
            let SumcheckMsg(a, b) = self.sumcheck.messages[i];
            let challenge = self.sumcheck.challenges[i];
            let g1_claim = g1s[i];
            let g2_claim = g2s[i];
            let batch_challenge = Fr::one(); //&self.batch_challenges[i * 3 + 1];
            let c = reduced_claim - a;
            let sumcheck_polynomial_evaluation = a + b * challenge + c * challenge.square();
            reduced_claim = sumcheck_polynomial_evaluation + g1_claim + g2_claim;
        }

        let mut final_foldings = vec![
            FFModule::p(self.foldings_ff[0].0, self.foldings_ff[0].1),
            G1Module::p(self.foldings_fg1[0].0, self.foldings_fg1[0].1),
            G2Module::p(self.foldings_fg2[0].0, self.foldings_fg2[0].1),
        ];
        final_foldings.extend(
            self.sumcheck
                .final_foldings
                .iter()
                .map(|&(lhs, rhs)| Bls12Module::p(lhs, rhs)),
        );

        let expected = final_foldings.iter().sum();

        if reduced_claim == expected {
            Ok(())
        } else {
            Err(VerificationError)
        }
    }

    pub fn new(transcript: &mut Transcript, crs: &Crs, a: &[Fr], b: &[Fr]) -> Self {
        let a = a.into_iter().map(|&x| FrWrapper(x)).collect::<Vec<_>>();
        let b = b.into_iter().map(|&x| FrWrapper(x)).collect::<Vec<_>>();

        // the full transcript will hold a set of messages, challenges, and batch challenges.
        let mut messages = Vec::new();
        let mut challenges = Vec::new();
        let mut batch_challenges = Vec::new();

        // prover for the claim <a, b>
        let witness_ff: Witness<FFModule> = Witness::new(&a, &b, &Fr::one().into());
        let mut prover_ff = TimeProver::new(witness_ff);
        // prover for the claim <a, G1>
        let witness_fg1: Witness<G1Module> = Witness::new(&crs.g1s, &a, &Fr::one().into());
        let mut prover_fg1 = TimeProver::new(witness_fg1);
        // prover for the claim <b, G2>
        let witness_fg2: Witness<G2Module> = Witness::new(&crs.g2s, &b, &Fr::one().into());
        let mut prover_fg2 = TimeProver::new(witness_fg2);

        // the first verifier message is empty
        let mut verifier_message = None;
        batch_challenges.push(Fr::one());
        batch_challenges.push(Fr::one());
        batch_challenges.push(Fr::one());

        // next_message for all above provers (batched)
        let msg_ff = prover_ff.next_message(verifier_message).unwrap();
        let msg_fg1 = prover_fg1.next_message(verifier_message).unwrap();
        let msg_fg2 = prover_fg2.next_message(verifier_message).unwrap();
        let prover_message = msg_ff + msg_fg1 + msg_fg2;
        transcript.append_serializable(b"prover_message", &prover_message);
        messages.push(prover_message);

        let rounds = prover_ff.rounds();
        assert_eq!(rounds, prover_fg1.rounds());
        assert_eq!(rounds, prover_fg2.rounds());

        // start the recursive step: create a vector of provers, and a vector of folded crs's
        let mut crs1_fold = (&crs.g1s[..1 << rounds]).to_vec();
        let mut crs2_fold = (&crs.g2s[..1 << rounds]).to_vec();
        let mut crs1_chop = (&crs.g1s[..1 << rounds]).to_vec();
        let mut crs2_chop = (&crs.g2s[..1 << rounds]).to_vec();

        let mut provers_gg: Vec<TimeProver<_>> = Vec::new();
        for _ in 0..rounds - 1 {
            // step 2a; the verifier sends round and batch challenge
            let challenge = transcript.get_challenge(b"sumcheck-chal");
            verifier_message = Some(challenge);
            let batch_challenge = Fr::one(); //transcript.get_challenge::<Fr>(b"batch-chal");
            challenges.push(challenge);
            batch_challenges.push(batch_challenge.into());
            batch_challenges.push(batch_challenge.square().into());

            // step 2b: the prover computes folding of g1's
            split_fold_into(&mut crs1_fold, &crs1_chop, &challenge);
            halve(&mut crs1_chop); // XXXXX: does this work for non-2powers?
                                   // [step 2b].. and of g2
            split_fold_into(&mut crs2_fold, &crs2_chop, &challenge);
            halve(&mut crs2_chop);

            // create a prover for the new folded claims in g1
            let witness_g1: Witness<Bls12Module> = Witness::new(&crs1_fold, &crs2_chop, &Fr::one());
            let mut prover_g1fold = TimeProver::new(witness_g1);
            // .. and in g2
            let witness_g2: Witness<Bls12Module> = Witness::new(&crs1_chop, &crs2_fold, &Fr::one());
            let mut prover_g2fold = TimeProver::new(witness_g2);

            // batch the sumcheck messages from all provers obtained thus far
            let ff_message = prover_ff.next_message(verifier_message);
            let fg1_message = prover_fg1.next_message(verifier_message);
            let fg2_message = prover_fg2.next_message(verifier_message);

            let g1fold_message = prover_g1fold.next_message(None);
            let g2fold_message = prover_g2fold.next_message(None);

            let gg_messages = provers_gg
                .iter_mut()
                .map(|prover| prover.next_message(verifier_message).unwrap())
                .collect::<Vec<_>>();

            assert!(ff_message.is_some());
            assert!(fg1_message.is_some());
            assert!(fg2_message.is_some());
            assert!(g1fold_message.is_some());
            assert!(g2fold_message.is_some());

            provers_gg.push(prover_g1fold);
            provers_gg.push(prover_g2fold);

            let prover_messages = ff_message
                .into_iter()
                .chain(fg1_message.into_iter())
                .chain(fg2_message.into_iter())
                .chain(gg_messages.into_iter())
                .chain(g1fold_message)
                .chain(g2fold_message);
            let round_message = SumcheckMsg::ip(prover_messages, batch_challenges.iter().cloned());

            transcript.append_serializable(b"sumcheck-round", &round_message);
            messages.push(round_message);
        }

        let challenge = transcript.get_challenge(b"sumcheck-chal");
        challenges.push(challenge);

        let final_foldings = provers_gg
            .iter_mut()
            .map(|p| {
                p.fold(challenge);
                p.final_foldings().unwrap()
            })
            .collect();
        let sumcheck = Sumcheck {
            messages,
            challenges,
            rounds,
            final_foldings,
        };
        // add messages from the initial provers
        let foldings_ff = vec![{
            prover_ff.fold(challenge);
            prover_ff.final_foldings().unwrap()
        }];
        let foldings_fg1 = vec![{
            prover_fg1.fold(challenge);
            prover_fg1.final_foldings().unwrap()
        }];
        let foldings_fg2 = vec![{
            prover_fg2.fold(challenge);
            prover_fg2.final_foldings().unwrap()
        }];
        InnerProductProof {
            sumcheck,
            batch_challenges,
            foldings_ff,
            foldings_fg1,
            foldings_fg2,
        }
    }
}

#[test]
fn test_correctness() {
    use ark_bls12_381::Fr as FF;
    let d = 1 << 4;
    let rng = &mut rand::thread_rng();
    let mut transcript = Transcript::new(b"gemini-tests");
    let crs = Crs::new(rng, d);
    let a = (0..d / 2).map(|_| FF::rand(rng).into()).collect::<Vec<_>>();
    let b = (0..d / 2).map(|_| FF::rand(rng).into()).collect::<Vec<_>>();
    let vrs = Vrs::from(&crs);
    let ipa = InnerProductProof::new(&mut transcript, &crs, &a, &b);
    let comm_a = crs.commit_g1(&a);
    let comm_b = crs.commit_g2(&b);
    let y = crate::misc::ip(&a, &b);

    let verification = ipa.verify_transcript(&vrs, comm_a, comm_b, y);
    assert!(verification.is_ok())
}
