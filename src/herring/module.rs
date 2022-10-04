use crate::transcript::GeminiTranscript;
use ark_bls12_381::G1Projective;
use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::pairing::Pairing;
use ark_ec::Group;
use ark_ff::Zero;
use ark_ff::{Field, UniformRand};
use ark_std::borrow::Borrow;
use ark_std::iter::Sum;
use ark_std::ops::{Add, AddAssign, BitXor, Mul, Sub};
use rand::Rng;
use crate::errors::VerificationResult;

pub trait Module:
    Send
    + Sync
    + CanonicalSerialize
    + Clone
    + Eq
    + Copy
    + Zero
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Mul<Self::ScalarField, Output = Self>
    + for<'a> Mul<&'a Self::ScalarField, Output = Self>
    + AddAssign<Self>
    + Sum<Self>
{
    type ScalarField: Field;
}

pub trait BilinearModule: Send + Sync {
    type Lhs: Module<ScalarField = Self::ScalarField> + BitXor<Self::Rhs, Output = Self::Target>;
    type Rhs: Module<ScalarField = Self::ScalarField>;
    type Target: Module<ScalarField = Self::ScalarField>;
    type ScalarField: Field;
}

#[derive(CanonicalSerialize, PartialEq, Eq, Clone, Copy)]
struct G1Wrapper(pub G1Projective);

#[derive(CanonicalSerialize, PartialEq, Eq, Clone, Copy)]
struct G2Wrapper(pub G2Projective);

#[derive(CanonicalSerialize, PartialEq, Eq, Clone, Copy)]
struct FrWrapper(pub Fr);

impl From<G1Projective> for G1Wrapper {
    fn from(e: G1Projective) -> Self {
        Self(e)
    }
}

impl From<Fr> for FrWrapper {
    fn from(e: Fr) -> Self {
        Self(e)
    }
}

impl From<G2Projective> for G2Wrapper {
    fn from(e: G2Projective) -> Self {
        Self(e)
    }
}

impl<FF> Mul<FF> for G1Wrapper
where
    FF: Borrow<Fr>,
{
    type Output = Self;

    fn mul(self, rhs: FF) -> Self::Output {
        (self.0 * rhs.borrow()).into()
    }
}

impl<FF> Mul<FF> for FrWrapper
where
    FF: Borrow<Fr>,
{
    type Output = Self;

    fn mul(self, rhs: FF) -> Self::Output {
        (self.0 * rhs.borrow()).into()
    }
}

impl<FF> Mul<FF> for G2Wrapper
where
    FF: Borrow<Fr>,
{
    type Output = Self;

    fn mul(self, rhs: FF) -> Self::Output {
        (self.0 * rhs.borrow()).into()
    }
}

impl AddAssign for G2Wrapper {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
    }
}

impl AddAssign for G1Wrapper {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
    }
}

impl AddAssign for FrWrapper {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
    }
}

impl Add for G1Wrapper {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        (self.0 + rhs.0).into()
    }
}

impl Add for FrWrapper {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        (self.0 + rhs.0).into()
    }
}

impl Add for G2Wrapper {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        (self.0 + rhs.0).into()
    }
}

impl Sum for G1Wrapper {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|accum, item| accum + item)
            .unwrap_or_else(Self::zero)
    }
}

impl Sum for FrWrapper {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|accum, item| accum + item)
            .unwrap_or_else(Self::zero)
    }
}

impl Sum for G2Wrapper {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|accum, item| accum + item)
            .unwrap_or_else(Self::zero)
    }
}

impl Zero for G2Wrapper {
    fn zero() -> Self {
        G2Projective::zero().into()
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl Zero for FrWrapper {
    fn zero() -> Self {
        Fr::zero().into()
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl Zero for G1Wrapper {
    fn zero() -> Self {
        G1Projective::zero().into()
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

use ark_ec::pairing::PairingOutput;
use ark_serialize::*;

#[derive(CanonicalSerialize, PartialEq, Eq, Clone, Copy)]
struct Bls12GT(pub PairingOutput<ark_bls12_381::Bls12_381>);

impl From<PairingOutput<ark_bls12_381::Bls12_381>> for Bls12GT {
    fn from(e: PairingOutput<ark_bls12_381::Bls12_381>) -> Self {
        Self(e)
    }
}

impl<FF: Borrow<Fr>> Mul<FF> for Bls12GT {
    type Output = Self;

    fn mul(self, rhs: FF) -> Self::Output {
        (self.0 * rhs.borrow()).into()
    }
}

impl Zero for Bls12GT {
    fn zero() -> Self {
        PairingOutput::zero().into()
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl AddAssign for Bls12GT {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
    }
}

impl Add for Bls12GT {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        (self.0 + rhs.0).into()
    }
}

impl Sum for Bls12GT {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|accum, item| accum + item)
            .unwrap_or_else(Self::zero)
    }
}

impl Sub for Bls12GT {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Sub for FrWrapper {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Sub for G1Wrapper {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Sub for G2Wrapper {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Module for Bls12GT {
    type ScalarField = Fr;
}

impl Module for G1Wrapper {
    type ScalarField = Fr;
}
impl Module for G2Wrapper {
    type ScalarField = Fr;
}

impl Module for FrWrapper {
    type ScalarField = Fr;
}

use ark_bls12_381::g2::G2Projective;
use merlin::Transcript;

use super::prover::SumcheckMsg;
use super::time_prover::{fold_polynomial_into, TimeProver};

use super::proof::Sumcheck;
use super::Prover;

impl Mul<G2Wrapper> for G1Wrapper {
    type Output = Bls12GT;

    #[inline]
    fn mul(self, rhs: G2Wrapper) -> Self::Output {
        Bls12_381::pairing(self.0, rhs.0).into()
    }
}

impl BitXor<G2Wrapper> for G1Wrapper {
    type Output = Bls12GT;

    #[inline]
    fn bitxor(self, rhs: G2Wrapper) -> Self::Output {
        Bls12_381::pairing(self.0, rhs.0).into()
    }
}

impl BitXor<FrWrapper> for G1Wrapper {
    type Output = Bls12GT;

    #[inline]
    fn bitxor(self, rhs: FrWrapper) -> Self::Output {
        Bls12_381::pairing(self.0, G2Projective::generator() * rhs.0).into()
    }
}

impl BitXor<FrWrapper> for G2Wrapper {
    type Output = Bls12GT;

    fn bitxor(self, rhs: FrWrapper) -> Self::Output {
        Bls12_381::pairing(G1Projective::generator() * rhs.0, self.0).into()
    }
}

impl BitXor<FrWrapper> for FrWrapper {
    type Output = Bls12GT;

    fn bitxor(self, rhs: FrWrapper) -> Self::Output {
        (PairingOutput::generator() * (self.0 * rhs.0)).into()
    }
}

struct Bls12Module {}

impl BilinearModule for Bls12Module {
    type Lhs = G1Wrapper;
    type Rhs = G2Wrapper;
    type Target = Bls12GT;
    type ScalarField = ark_bls12_381::Fr;
}

struct G1Module {}

impl BilinearModule for G1Module {
    type Lhs = G1Wrapper;
    type Rhs = FrWrapper;
    type Target = Bls12GT;
    type ScalarField = Fr;
}

struct G2Module {}

impl BilinearModule for G2Module {
    type Lhs = G2Wrapper;
    type Rhs = FrWrapper;
    type Target = Bls12GT;
    type ScalarField = Fr;
}

struct FFModule {}

impl BilinearModule for FFModule {
    type Lhs = FrWrapper;
    type Rhs = FrWrapper;
    type Target = Bls12GT;
    type ScalarField = Fr;
}

enum BilinearECModule {
    G1G2(Bls12Module),
    G1F(G1Module),
    G2F(G2Module),
    FF(FFModule),
}

use ark_std::vec::Vec;
use ark_std::{log2, One};

use super::time_prover::Witness;
pub struct InnerProductProof {
    sumcheck: Sumcheck<Bls12Module>,
    foldings_ff: Vec<(FrWrapper, FrWrapper)>,
    foldings_fg1: Vec<(G1Wrapper, FrWrapper)>,
    foldings_fg2: Vec<(G2Wrapper, FrWrapper)>,
}

fn ip_unsafe<BM, I, J>(f: I, g: J) -> BM::Target
where
    BM: BilinearModule,
    I: Iterator,
    J: Iterator,
    I::Item: Borrow<BM::Lhs>,
    J::Item: Borrow<BM::Rhs>,
{
    f.zip(g).map(|(x, y)| *x.borrow() ^ *y.borrow()).sum()
}

struct Crs {
    g1s: Vec<G1Wrapper>,
    g2s: Vec<G2Wrapper>,
}

struct Vrs {
    vk1: Vec<(Bls12GT, Bls12GT)>,
    vk2: Vec<(Bls12GT, Bls12GT)>,
}

impl Crs {
    fn new(rng: &mut impl Rng, d: usize) -> Self {
        let g1s: Vec<G1Wrapper> = (0..d + 1).map(|_| G1Projective::rand(rng).into()).collect();
        let g2s: Vec<G2Wrapper> = (0..d + 1).map(|_| G2Projective::rand(rng).into()).collect();
        Self { g1s, g2s }
    }
}

impl From<Crs> for Vrs {
    fn from(crs: Crs) -> Self {
        let mut vk1 = Vec::new();
        let mut vk2 = Vec::new();

        for j in 0..log2(crs.g1s.len()) {
            let size = 1 << j;

            let g1es = ip_unsafe::<Bls12Module, _, _>(
                crs.g1s.iter().step_by(2),
                crs.g2s.iter().take(size),
            );
            let g1os = ip_unsafe::<Bls12Module, _, _>(
                crs.g1s.iter().skip(1).step_by(2),
                crs.g2s.iter().take(size),
            );

            let g2es = ip_unsafe::<Bls12Module, _, _>(
                crs.g1s.iter().take(size),
                crs.g2s.iter().step_by(2),
            );
            let g2os = ip_unsafe::<Bls12Module, _, _>(
                crs.g1s.iter().take(size),
                crs.g2s.iter().skip(1).step_by(2),
            );

            vk1.push((g1es, g1os));
            vk2.push((g2es, g2os));
        }

        Self { vk1, vk2 }
    }
}

impl InnerProductProof {
    fn verify(
        &self,
        transcript: &mut Transcript,
        vrs: &Vrs,
        comm_a: G1Projective,
        comm_b: G2Projective,
        y: Bls12GT,
    ) -> VerificationResult {
        let g1s = vrs
            .vk1
            .iter()
            .zip(&self.sumcheck.challenges)
            .map(|((even, odd), challenge)| *even + *odd * challenge);
        let g2s = vrs
            .vk2
            .iter()
            .zip(&self.sumcheck.challenges)
            .map(|((even, odd), challenge)| *even + *odd * challenge);


        let mut reduced_claim = y;
        for (message, &challenge) in self.sumcheck.messages.iter().zip(self.sumcheck.challenges.iter()) {
            let SumcheckMsg(a, b) = *message;
            let c = reduced_claim - a;
            reduced_claim = a + b * challenge  + c* challenge.square();
        }
        todo!()
    }

    fn new(transcript: &mut Transcript, crs: &Crs, a: &[FrWrapper], b: &[FrWrapper]) -> Self {
        // the full transcript will hold a set of messages, challenges, and batch challenges.
        let mut messages = Vec::new();
        let mut challenges = Vec::new();
        let mut batch_challenges = Vec::new();

        // prover for the claim <a, b>
        let witness_ff: Witness<FFModule> =
            super::time_prover::Witness::new(a, b, &Fr::one().into());
        let mut prover_ff = super::time_prover::TimeProver::new(witness_ff);
        // prover for the claim <a, G1>
        let witness_fg1: Witness<G1Module> =
            super::time_prover::Witness::new(&crs.g1s, a, &Fr::one().into());
        let mut prover_fg1 = super::time_prover::TimeProver::new(witness_fg1);
        // prover for the claim <b, G2>
        let witness_fg2: Witness<G2Module> =
            super::time_prover::Witness::new(&crs.g2s, b, &Fr::one().into());
        let mut prover_fg2 = super::time_prover::TimeProver::new(witness_fg2);

        // next_message for all above provers (batched)
        let batch_challenge: Fr = transcript.get_challenge(b"batch-chal");
        let msg_ff = prover_ff.next_message().unwrap();
        let msg_fg1 = prover_fg1.next_message().unwrap();
        let msg_fg2 = prover_fg2.next_message().unwrap();
        messages.push(msg_ff + msg_fg1 * &batch_challenge + msg_fg2 * &batch_challenge.square());
        batch_challenges.push(batch_challenge);
        batch_challenges.push(batch_challenge.square());

        // start the recursive step: create a vector of provers, and a vector of folded crs's
        let mut last_crs1_fold = crs.g1s.to_vec();
        let mut last_crs2_fold = crs.g2s.to_vec();
        let mut last_crs1_chop = crs.g1s.as_slice();
        let mut last_crs2_chop = crs.g2s.as_slice();

        let rounds = prover_ff.rounds(); // assuming = proverg.rounds()
        let mut gg_provers: Vec<TimeProver<_>> = Vec::new();
        for _ in 0..rounds {
            // step 2a; the verifier sends round and batch challenge
            let round_challenge = transcript.get_challenge(b"sumcheck-chal");
            let batch_challenge = transcript.get_challenge(b"batch-chal");
            challenges.push(round_challenge);
            batch_challenges.push(batch_challenge);
            batch_challenges.push(batch_challenge.square());

            // fold previous polynomials using hte crs given
            prover_ff.fold(round_challenge);
            prover_fg1.fold(round_challenge);
            prover_fg2.fold(round_challenge);
            gg_provers
                .iter_mut()
                .for_each(|prover| prover.fold(round_challenge));

            // step 2b: the prover computes folding of g1's
            let crs1_chop = &last_crs1_chop[..last_crs1_chop.len() / 2]; // XXXXX: does this work for non-2powers?
            fold_polynomial_into(&mut last_crs1_fold, last_crs1_chop, round_challenge);
            last_crs1_chop = &crs1_chop;
            // [step 2b].. and of g2
            fold_polynomial_into(&mut last_crs2_fold, last_crs2_chop, round_challenge);
            let crs2_chop = &last_crs2_chop[..last_crs2_chop.len() / 2];
            last_crs2_chop = &crs2_chop;

            // create a prover for the new folded claims in g1
            let witness_g1: Witness<Bls12Module> =
                Witness::new(&last_crs1_fold, &crs2_chop, &Fr::one());
            let prover_g1fold = TimeProver::new(witness_g1);
            gg_provers.push(prover_g1fold);
            // .. and in g2
            let witness_g2: Witness<Bls12Module> =
                Witness::new(&crs1_chop, &last_crs2_fold, &Fr::one());
            let prover_g2fold = TimeProver::new(witness_g2);
            gg_provers.push(prover_g2fold);

            // batch the sumcheck messages from all provers obtained thus far
            let ff_message = prover_ff.next_message().into_iter();
            let fg1_message = prover_fg1.next_message().into_iter();
            let fg2_message = prover_fg2.next_message().into_iter();
            let gg_messages = gg_provers
                .iter_mut()
                .map(|prover| prover.next_message().unwrap());
            let prover_messages = ff_message
                .chain(fg1_message)
                .chain(fg2_message)
                .chain(gg_messages)
                .collect::<Vec<SumcheckMsg<Bls12GT>>>();
            let round_message = prover_messages
                .iter()
                .zip(&batch_challenges)
                .map(|(&m, c)| m * c)
                .sum();

            transcript.append_serializable(b"sumcheck-round", &round_message);
            messages.push(round_message);
            challenges.push(round_challenge);
        }

        let final_foldings = gg_provers
            .iter()
            .map(|p| p.final_foldings().unwrap())
            .collect();
        let sumcheck = Sumcheck {
            messages,
            challenges,
            rounds,
            final_foldings,
        };
        // add messages from the initial provers
        let foldings_ff = vec![prover_ff.final_foldings().unwrap()];
        let foldings_fg1 = vec![prover_fg1.final_foldings().unwrap()];
        let foldings_fg2 = vec![prover_fg2.final_foldings().unwrap()];
        InnerProductProof {
            sumcheck,
            foldings_ff,
            foldings_fg1,
            foldings_fg2,
        }
    }
}

#[test]
fn test_batching() {
    use ark_std::vec::Vec;
}