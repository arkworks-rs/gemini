use core::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_ec::pairing::PairingOutput;
use ark_ec::VariableBaseMSM;
use ark_ff::AdditiveGroup;
use ark_ff::Field;
use ark_std::borrow::Borrow;
use ark_std::vec::Vec;

pub trait BilinearModule: Send + Sync {
    type Lhs: AdditiveGroup<Scalar = Self::ScalarField>;
    type Rhs: AdditiveGroup<Scalar = Self::ScalarField>;
    type Target: AdditiveGroup<Scalar = Self::ScalarField>;
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

pub(crate) struct GtModule<P: Pairing> {
    _pairing: PhantomData<P>,
}
pub(crate) struct G1Module<P: Pairing> {
    _pairing: PhantomData<P>,
}

pub(crate) struct G2Module<P: Pairing> {
    _pairing: PhantomData<P>,
}

pub(crate) struct FModule<P: Pairing> {
    _pairing: PhantomData<P>,
}

pub(crate) struct PModule<P: Pairing> {
    _pairing: PhantomData<P>,
}

impl<P: Pairing> BilinearModule for GtModule<P> {
    type Lhs = PairingOutput<P>;
    type Rhs = P::ScalarField;
    type Target = PairingOutput<P>;
    type ScalarField = P::ScalarField;

    fn p(a: impl Borrow<Self::Lhs>, b: impl Borrow<Self::Rhs>) -> Self::Target {
        *a.borrow() * b.borrow()
    }
}

impl<P: Pairing> BilinearModule for PModule<P> {
    type Lhs = P::G1;
    type Rhs = P::G2;
    type Target = PairingOutput<P>;
    type ScalarField = P::ScalarField;

    fn p(a: impl Borrow<Self::Lhs>, b: impl Borrow<Self::Rhs>) -> Self::Target {
        P::pairing(a.borrow(), b.borrow())
    }

    fn ip<I, J>(f: I, g: J) -> Self::Target
    where
        I: Iterator,
        J: Iterator,
        I::Item: Borrow<Self::Lhs>,
        J::Item: Borrow<Self::Rhs>,
    {
        P::multi_pairing(f.map(|x| *x.borrow()), g.map(|x| *x.borrow()))
    }
}

impl<P: Pairing> BilinearModule for G1Module<P> {
    type Lhs = P::G1;
    type Rhs = P::ScalarField;
    type Target = P::G1;
    type ScalarField = P::ScalarField;

    fn p(a: impl Borrow<Self::Lhs>, b: impl Borrow<Self::Rhs>) -> Self::Target {
        *a.borrow() * b.borrow()
    }

    fn ip<I, J>(f: I, g: J) -> Self::Target
    where
        I: Iterator,
        J: Iterator,
        I::Item: Borrow<Self::Lhs>,
        J::Item: Borrow<Self::Rhs>,
    {
        let scalars = g.map(|x| *x.borrow()).collect::<Vec<_>>();
        let bases = f.map(|x| (*x.borrow()).into()).collect::<Vec<_>>();
        P::G1::msm_unchecked(&bases, &scalars)
    }
}

impl<P: Pairing> BilinearModule for G2Module<P> {
    type Lhs = P::ScalarField;
    type Rhs = P::G2;
    type Target = P::G2;
    type ScalarField = P::ScalarField;

    fn p(a: impl Borrow<Self::Lhs>, b: impl Borrow<Self::Rhs>) -> Self::Target {
        *b.borrow() * a.borrow()
    }

    fn ip<I, J>(f: I, g: J) -> Self::Target
    where
        I: Iterator,
        J: Iterator,
        I::Item: Borrow<Self::Lhs>,
        J::Item: Borrow<Self::Rhs>,
    {
        let scalars = f.map(|x| *x.borrow()).collect::<Vec<_>>();
        let bases = g.map(|x| (*x.borrow()).into()).collect::<Vec<_>>();
        P::G2::msm_unchecked(&bases, &scalars)
    }
}

impl<P: Pairing> BilinearModule for FModule<P> {
    type Lhs = P::ScalarField;
    type Rhs = P::ScalarField;
    type Target = P::ScalarField;
    type ScalarField = P::ScalarField;

    fn p(a: impl Borrow<Self::Lhs>, b: impl Borrow<Self::Rhs>) -> Self::Target {
        *b.borrow() * a.borrow()
    }

    fn ip<I, J>(f: I, g: J) -> Self::Target
    where
        I: Iterator,
        J: Iterator,
        I::Item: Borrow<Self::Lhs>,
        J::Item: Borrow<Self::Rhs>,
    {
        crate::misc::ip_unsafe(f, g)
    }
}
