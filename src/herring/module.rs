use core::marker::PhantomData;

use ark_test_curves::bls12_381::{Bls12_381, Fr};
use ark_ec::pairing::Pairing;
use ark_ec::pairing::PairingOutput;
use ark_ec::PrimeGroup;
use ark_ff::Field;
use ark_ff::AdditiveGroup;
use ark_std::borrow::Borrow;

pub(crate) use ark_test_curves::bls12_381::G1Projective as G1;
pub(crate) use ark_test_curves::bls12_381::G2Projective as G2;
pub(crate) type Gt = PairingOutput<ark_test_curves::bls12_381::Bls12_381>;


pub trait BilinearModule: Send + Sync {
    type Lhs: AdditiveGroup<ScalarField = Self::ScalarField>;
    type Rhs: AdditiveGroup<ScalarField = Self::ScalarField>;
    type Target: AdditiveGroup<ScalarField = Self::ScalarField>;
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


pub(crate) struct GtModule {}

impl BilinearModule for GtModule {
    type Lhs = Gt;
    type Rhs = Fr;
    type Target = Gt;
    type ScalarField = Fr;

    fn p(a: impl Borrow<Self::Lhs>, b: impl Borrow<Self::Rhs>) -> Self::Target {
        *a.borrow() * b.borrow()
    }
}

pub(crate) struct GtMod<P: Pairing> {_pairing: PhantomData<P>}

impl<P: Pairing> BilinearModule for GtMod<P> {
    type Lhs = PairingOutput<P>;
    type Rhs = P::ScalarField;
    type Target = PairingOutput<P>;
    type ScalarField = P::ScalarField;

    fn p(a: impl Borrow<Self::Lhs>, b: impl Borrow<Self::Rhs>) -> Self::Target {
        *a.borrow() * b.borrow()
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
    type Rhs = Fr;
    type Target = Gt;
    type ScalarField = Fr;

    fn p(a: impl Borrow<Self::Lhs>, b: impl Borrow<Self::Rhs>) -> Self::Target {
        Bls12_381::pairing(a.borrow(), G2::generator() * b.borrow()).into()
    }
}

pub(crate) struct G2Module {}

impl BilinearModule for G2Module {
    type Lhs = G2;
    type Rhs = Fr;
    type Target = Gt;
    type ScalarField = Fr;

    fn p(a: impl Borrow<Self::Lhs>, b: impl Borrow<Self::Rhs>) -> Self::Target {
        Bls12_381::pairing(G1::generator() * b.borrow(), a.borrow()).into()
    }
}

pub(crate) struct FFModule {}

impl BilinearModule for FFModule {
    type Lhs = Fr;
    type Rhs = Fr;
    type Target = Gt;
    type ScalarField = Fr;

    fn p(a: impl Borrow<Self::Lhs>, b: impl Borrow<Self::Rhs>) -> Self::Target {
        Gt::generator() * (a.borrow() * b.borrow())
    }
}
