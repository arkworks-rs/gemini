use crate::transcript::GeminiTranscript;
use ark_bls12_381::G1Projective;
use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::Group;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, UniformRand};
use ark_ff::{PrimeField, Zero};
use ark_std::borrow::Borrow;
use ark_std::iter::Sum;
use ark_std::ops::{Add, AddAssign, BitXor, Mul, Sub};
use rand::Rng;

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

use ark_serialize::*;

#[derive(CanonicalSerialize, PartialEq, Eq, Clone, Copy)]
struct Bls12GT(pub ark_bls12_381::<Bls12<ark_bls12_381::Parameters> as Pairing>::PairingOutput);

impl From<ark_bls12_381::Fq12> for Bls12GT {
    fn from(e: ark_bls12_381::Fq12) -> Self {
        Self(e)
    }
}

impl<FF: Borrow<Fr>> Mul<FF> for Bls12GT {
    type Output = Self;

    fn mul(self, rhs: FF) -> Self::Output {
        self.0.pow(rhs.borrow().into_bigint()).into()
    }
}

impl Zero for Bls12GT {
    fn zero() -> Self {
        ark_bls12_381::Fq12::zero().into()
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl AddAssign for Bls12GT {
    fn add_assign(&mut self, rhs: Self) {
        self.0 *= rhs.0
    }
}

impl Add for Bls12GT {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        (self.0 * rhs.0).into()
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
        Bls12_381::pairing(self.0, rhs.0).0.into()
    }
}

impl BitXor<G2Wrapper> for G1Wrapper {
    type Output = Bls12GT;

    #[inline]
    fn bitxor(self, rhs: G2Wrapper) -> Self::Output {
        Bls12_381::pairing(self.0, rhs.0).0.into()
    }
}

impl BitXor<FrWrapper> for G1Wrapper {
    type Output = Bls12GT;

    #[inline]
    fn bitxor(self, rhs: FrWrapper) -> Self::Output {
        Bls12_381::pairing(self.0, G2Projective::generator() * rhs.0).0.into()
    }
}

impl BitXor<FrWrapper> for G2Wrapper {
    type Output = Bls12GT;

    fn bitxor(self, rhs: FrWrapper) -> Self::Output {
        Bls12_381::pairing(G1Projective::generator() * rhs.0, self.0).0.into()
    }
}

impl BitXor<FrWrapper> for FrWrapper {
    type Output = Bls12GT;

    fn bitxor(self, rhs: FrWrapper) -> Self::Output {
        Bls12_381::pairing(
            G1Projective::generator(),
            G2Projective::generator(),
        )
        .0.pow((self.0 * rhs.0).into_bigint())
        .into()
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
    foldings_1f: Vec<(G1Wrapper, FrWrapper)>,
    foldings_2f: Vec<(G2Wrapper, FrWrapper)>,
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
        let g1s: Vec<G1Wrapper> = (0..d).map(|_| G1Projective::rand(rng).into()).collect();
        let g2s: Vec<G2Wrapper> = (0..d).map(|_| G2Projective::rand(rng).into()).collect();
        Self { g1s, g2s }
    }
}

impl From<Crs> for Vrs {
    fn from(crs: Crs) -> Self {
        let mut vk1 = Vec::new();
        let mut vk2 = Vec::new();

        for i in 0..log2(crs.g1s.len()) {
            let size = 1 << i;

            let even2 = ip_unsafe::<Bls12Module, _, _>(
                crs.g1s.iter().take(size),
                crs.g2s.iter().step_by(2),
            );
            let odd2 = ip_unsafe::<Bls12Module, _, _>(
                crs.g1s.iter().take(size),
                crs.g2s.iter().skip(1).step_by(2),
            );
            let even1 = ip_unsafe::<Bls12Module, _, _>(
                crs.g1s.iter().step_by(2),
                crs.g2s.iter().take(size),
            );
            let odd1 = ip_unsafe::<Bls12Module, _, _>(
                crs.g1s.iter().skip(1).step_by(2),
                crs.g2s.iter().take(size),
            );

            vk1.push((even1, odd1));
            vk2.push((even2, odd2));
        }

        Self { vk1, vk2 }
    }
}


impl InnerProductProof {
    fn new(
        transcript: &mut Transcript,
        a: &[FrWrapper],
        b: &[FrWrapper],
        crs: &Crs,
    ) -> Self {
        let witness_ff: Witness<FFModule> =
            super::time_prover::Witness::new(a, b, &Fr::one().into());
        let witness_f1: Witness<G1Module> =
            super::time_prover::Witness::new(&crs.g1s, a, &Fr::one().into());
        let witness_f2: Witness<G2Module> =
            super::time_prover::Witness::new(&crs.g2s, b, &Fr::one().into());

        let proverf = super::time_prover::TimeProver::new(witness_ff);
        let proverf1 = super::time_prover::TimeProver::new(witness_f1);
        let proverf2 = super::time_prover::TimeProver::new(witness_f2);

        let rounds = proverf.rounds();

        let mut last_crs1_fold = crs.g1s.to_vec();
        let mut last_crs2_fold = crs.g2s.to_vec();
        let mut last_crs1_chop = crs.g1s.as_slice();
        let mut last_crs2_chop = crs.g2s.as_slice();

        let mut gclaims = Vec::new();
        let mut messages = Vec::new();
        let mut challenges = Vec::new();
        let mut batch_challenges = Vec::new();

        let batch_chal: Fr = transcript.get_challenge(b"batch-chal");
        batch_challenges.push(batch_chal);
        batch_challenges.push(batch_chal.square());

        for _ in 0..rounds {
            let challenge = transcript.get_challenge(b"sumcheck-chal");
            let batch_challenge = transcript.get_challenge(b"batch-chal");
            batch_challenges.push(batch_challenge);
            batch_challenges.push(batch_challenge.square());

            fold_polynomial_into(&mut last_crs1_fold, last_crs1_chop, challenge);
            let crs2_chop = &last_crs2_chop[..last_crs2_chop.len() / 2];

            let crs1_chop = &last_crs1_chop[..last_crs1_chop.len() / 2];
            fold_polynomial_into(&mut last_crs2_fold, last_crs2_chop, challenge);

            last_crs1_chop = &crs1_chop;
            last_crs2_chop = &crs2_chop;

            let crswit1: Witness<Bls12Module> =
                Witness::new(&last_crs1_fold, &crs2_chop, &Fr::one());
            let crswit2: Witness<Bls12Module> =
                Witness::new(&crs1_chop, &last_crs2_fold, &Fr::one());
            let crpro1 = TimeProver::new(crswit1);
            let crpro2 = TimeProver::new(crswit2);
            gclaims.push(crpro1);
            gclaims.push(crpro2);

            let message: SumcheckMsg<Bls12GT> = gclaims
                .iter_mut()
                .map(|p| {
                    p.fold(challenge);
                    p.next_message().unwrap()
                })
                .sum();

            transcript.append_serializable(b"sumcheck-round", &message);
            messages.push(message);
            challenges.push(challenge);
        }
        let final_foldings = gclaims
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
        let foldings_ff = vec![proverf.final_foldings().unwrap()];
        let foldings_1f = vec![proverf1.final_foldings().unwrap()];
        let foldings_2f = vec![proverf2.final_foldings().unwrap()];
        InnerProductProof {
            sumcheck,
            foldings_ff,
            foldings_1f,
            foldings_2f,
        }
    }

}

#[test]
fn test_batching() {
    use ark_std::vec::Vec;
}
