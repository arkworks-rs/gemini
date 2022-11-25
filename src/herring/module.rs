use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::pairing::Pairing;
use ark_ec::pairing::PairingOutput;
use ark_ec::Group;
use ark_ff::Field;
use ark_ff::Zero;
use ark_serialize::*;
use ark_std::borrow::Borrow;
use ark_std::iter::Sum;
use ark_std::ops::{Add, AddAssign, Mul, Sub};

pub(crate) use ark_bls12_381::G1Projective as G1;
pub(crate) use ark_bls12_381::G2Projective as G2;
pub(crate) type Gt = PairingOutput<ark_bls12_381::Bls12_381>;

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
    type Lhs: Module<ScalarField = Self::ScalarField>;
    type Rhs: Module<ScalarField = Self::ScalarField>;
    type Target: Module<ScalarField = Self::ScalarField>;
    type ScalarField: Field;

    fn p(a: impl Borrow<Self::Lhs>, b: impl Borrow<Self::Rhs>) -> Self::Target;

    fn ip<I, J>(f: I, g: J) -> Self::Target
    where
        I: Iterator,
        J: Iterator,
        I::Item: Borrow<Self::Lhs>,
        J::Item: Borrow<Self::Rhs>,
    {
        f.zip(g).map(|(x, y)| Self::p(x.borrow(), y.borrow())).sum()
    }
}

#[derive(CanonicalSerialize, PartialEq, Eq, Clone, Copy)]
pub(crate) struct FrWrapper(pub Fr);

impl<G: Group> Module for G {
    type ScalarField = G::ScalarField;
}

impl From<Fr> for FrWrapper {
    fn from(e: Fr) -> Self {
        Self(e)
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

impl AddAssign for FrWrapper {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
    }
}

impl Add for FrWrapper {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        (self.0 + rhs.0).into()
    }
}

impl Sum for FrWrapper {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|accum, item| accum + item)
            .unwrap_or_else(Self::zero)
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

impl Sub for FrWrapper {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Module for FrWrapper {
    type ScalarField = Fr;
}

pub(crate) struct GtModule {}

impl BilinearModule for GtModule {
    type Lhs = Gt;
    type Rhs = FrWrapper;
    type Target = Gt;
    type ScalarField = ark_bls12_381::Fr;

    fn p(a: impl Borrow<Self::Lhs>, b: impl Borrow<Self::Rhs>) -> Self::Target {
        *a.borrow() * b.borrow().0
    }
}

pub(crate) struct Bls12Module {}

impl BilinearModule for Bls12Module {
    type Lhs = G1;
    type Rhs = G2;
    type Target = Gt;
    type ScalarField = Fr;

    fn p(a: impl Borrow<Self::Lhs>, b: impl Borrow<Self::Rhs>) -> Self::Target {
        Bls12_381::pairing(a.borrow(), b.borrow())
    }

    fn ip<I, J>(f: I, g: J) -> Self::Target
    where
        I: Iterator,
        J: Iterator,
        I::Item: Borrow<Self::Lhs>,
        J::Item: Borrow<Self::Rhs>,
    {
        Bls12_381::multi_pairing(f.map(|x| *x.borrow()), g.map(|x| *x.borrow()))
    }
}

pub(crate) struct G1Module {}

impl BilinearModule for G1Module {
    type Lhs = G1;
    type Rhs = FrWrapper;
    type Target = Gt;
    type ScalarField = Fr;

    fn p(a: impl Borrow<Self::Lhs>, b: impl Borrow<Self::Rhs>) -> Self::Target {
        Bls12_381::pairing(a.borrow(), G2::generator() * b.borrow().0).into()
    }
}

pub(crate) struct G2Module {}

impl BilinearModule for G2Module {
    type Lhs = G2;
    type Rhs = FrWrapper;
    type Target = Gt;
    type ScalarField = Fr;

    fn p(a: impl Borrow<Self::Lhs>, b: impl Borrow<Self::Rhs>) -> Self::Target {
        Bls12_381::pairing(G1::generator() * b.borrow().0, a.borrow()).into()
    }
}

pub(crate) struct FFModule {}

impl BilinearModule for FFModule {
    type Lhs = FrWrapper;
    type Rhs = FrWrapper;
    type Target = Gt;
    type ScalarField = Fr;

    fn p(a: impl Borrow<Self::Lhs>, b: impl Borrow<Self::Rhs>) -> Self::Target {
        Bls12_381::pairing(
            G1::generator() * a.borrow().0 * b.borrow().0,
            G2::generator(),
        )
        .into()
    }
}
