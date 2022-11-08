//! An impementation of a space-efficient version of Michele's multilinear extension
//! of Kate et al's polynomial commitment,
//! with optimization from [\[BDFG20\]](https://eprint.iacr.org/2020/081.pdf).
//!

use ark_ec::scalar_mul::variable_base::ChunkedPippenger;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_std::vec::Vec;
use ark_std::{borrow::Borrow, ops::Mul};

use super::EvaluationProofMulti;
use crate::iterable::Iterable;
use crate::multikzg::time::CommitterKeyMulti;
use crate::multikzg::{Commitment, VerifierKeyMulti};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
// use super::VerificationResult;
// use crate::ark_std::Zero;

pub struct CommitterKeyMultiStream<SG, E: Pairing>
where
    SG: Iterable,
    SG::Item: Borrow<E::G1Affine>,
{
    pub(crate) powers_of_g: SG,
    pub(crate) g2: E::G2Affine,
    pub(crate) powers_of_g2: Vec<E::G2Affine>,
}

impl<SG, E: Pairing> Valid for CommitterKeyMultiStream<SG, E>
where
    E: Pairing,
    SG: Iterable<Item = E::G1Affine> + CanonicalDeserialize + CanonicalSerialize,
{
    fn check(&self) -> Result<(), SerializationError> {
        let powers_of_g_check = self.powers_of_g.check();
        let g2_check = self.g2.check();
        let powers_of_g2_check = self.powers_of_g2.check();

        if powers_of_g_check.is_err() {
            powers_of_g_check
        } else if g2_check.is_err() {
            g2_check
        } else if powers_of_g2_check.is_err() {
            powers_of_g2_check
        } else {
            Ok(())
        }
    }
}

impl<SG, E: Pairing> CanonicalSerialize for CommitterKeyMultiStream<SG, E>
where
    E: Pairing,
    SG: Iterable<Item = E::G1Affine> + CanonicalDeserialize + CanonicalSerialize,
{
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.powers_of_g
            .serialize_with_mode(&mut writer, compress)?;
        self.g2.serialize_with_mode(&mut writer, compress)?;
        self.powers_of_g2.serialize_with_mode(&mut writer, compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.powers_of_g.serialized_size(compress)
            + self.g2.serialized_size(compress)
            + self.powers_of_g2.serialized_size(compress)
    }
}

impl<SG, E: Pairing> CanonicalDeserialize for CommitterKeyMultiStream<SG, E>
where
    E: Pairing,
    SG: Iterable<Item = E::G1Affine> + CanonicalDeserialize + CanonicalSerialize + Valid,
{
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let powers_of_g = SG::deserialize_with_mode(&mut reader, compress, validate)?;
        let g2 = E::G2Affine::deserialize_with_mode(&mut reader, compress, validate)?;
        let powers_of_g2 =
            Vec::<E::G2Affine>::deserialize_with_mode(&mut reader, compress, validate)?;

        Ok(Self {
            powers_of_g,
            g2,
            powers_of_g2,
        })
    }
}

/// This struct naively and inefficiently implements both Iterable and CanonicalSerialize/Deserialize
///
#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct TestStreamer<E: Pairing>(Vec<E::G1Affine>);

impl<E: Pairing> Iterable for TestStreamer<E> {
    type Item = E::G1Affine;
    type Iter = <Vec<E::G1Affine> as IntoIterator>::IntoIter;

    fn iter(&self) -> Self::Iter {
        self.0.clone().into_iter()
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

impl<'a, E: Pairing> From<&'a CommitterKeyMulti<E>>
    for CommitterKeyMultiStream<TestStreamer<E>, E>
{
    fn from(ck: &'a CommitterKeyMulti<E>) -> Self {
        let powers_of_g = TestStreamer(ck.powers_of_g.clone());
        let g2 = ck.g2;
        let powers_of_g2 = ck.powers_of_g2.clone();

        CommitterKeyMultiStream {
            powers_of_g,
            g2,
            powers_of_g2,
        }
    }
}

impl<E: Pairing> From<CommitterKeyMultiStream<TestStreamer<E>, E>> for CommitterKeyMulti<E> {
    fn from(ck_stream: CommitterKeyMultiStream<TestStreamer<E>, E>) -> Self {
        let powers_of_g = ck_stream.powers_of_g.0;
        let g2 = ck_stream.g2;
        let powers_of_g2 = ck_stream.powers_of_g2;

        CommitterKeyMulti {
            powers_of_g,
            g2,
            powers_of_g2,
        }
    }
}

impl<E: Pairing> From<&CommitterKeyMultiStream<TestStreamer<E>, E>> for VerifierKeyMulti<E> {
    fn from(ck: &CommitterKeyMultiStream<TestStreamer<E>, E>) -> VerifierKeyMulti<E> {
        let powers_of_g2 = ck.powers_of_g2.to_vec();
        let g = ck.powers_of_g.iter().next().unwrap();
        let g2 = ck.g2;

        VerifierKeyMulti {
            g,
            g2,
            powers_of_g2,
        }
    }
}

impl<SG, E> CommitterKeyMultiStream<SG, E>
where
    E: Pairing,
    SG: Iterable,
    SG::Item: Borrow<E::G1Affine>,
{
    /// Given a polynomial `polynomial` of degree less than `max_degree`, return a commitment to `polynomial`.
    pub fn commit<SF>(&self, polynomial: &SF) -> Commitment<E>
    where
        SF: Iterable,
        SF::Item: Borrow<E::ScalarField>,
    {
        Commitment(stream_pippenger::<_, _, E>(&self.powers_of_g, polynomial))
    }

    // / Given a polynomial `polynomial` and an evaluation point `evaluation_point`,
    // / return the evaluation of `polynomial in `evaluation_point`,
    // / together with an evaluation proof
    pub fn open<SF>(
        &self,
        polynomial: &SF,
        evaluation_point: &[E::ScalarField],
    ) -> (E::ScalarField, EvaluationProofMulti<E>)
    where
        SF: Iterable,
        SF::Item: Borrow<E::ScalarField>,
    {
        use crate::multikzg::division_stream::MultiPolynomialTree;
        use ark_ff::Zero;

        let dim = evaluation_point.len();
        let mut power_of_g_iters = Vec::new();
        for i in 0..dim {
            power_of_g_iters.push(self.powers_of_g.iter().step_by(1 << (i + 1)));
        }
        let mut result = vec![E::G1Affine::zero(); dim];
        let tree = MultiPolynomialTree::new(polynomial, evaluation_point);
        for (i, coef) in tree.iter() {
            if i == dim {
                return (coef, EvaluationProofMulti(result));
            }
            let next_power_of_g: E::G1Affine = *power_of_g_iters[i].next().unwrap().borrow();

            let addend = next_power_of_g.mul(&coef).into_affine();
            result[i] = (result[i] + addend).into_affine();
        }
        (E::ScalarField::zero(), EvaluationProofMulti(result))
    }

    /// Evaluate a single polynomial at a set of points `eval_points`, and provide a single evaluation proof.
    pub fn open_multi_points(
        &self,
        _polynomial: &[E::ScalarField],
        _eval_points: &[E::ScalarField],
    ) -> EvaluationProofMulti<E> {
        todo!();
    }
}

fn stream_pippenger<SF, SG, E: Pairing>(bases: &SG, scalars: &SF) -> E::G1Affine
where
    SF: Iterable,
    SF::Item: Borrow<E::ScalarField>,
    SG: Iterable,
    SG::Item: Borrow<E::G1Affine>,
{
    let mut cp: ChunkedPippenger<E::G1> = ChunkedPippenger::new(1 << 15);
    let zipped = bases.iter().zip(scalars.iter());
    zipped.for_each(|(b, s)| cp.add(b, s.borrow().into_bigint()));
    cp.finalize().into_affine()
}

#[test]
fn test_streaming_commit() {
    use crate::misc::random_unique_vector;
    use ark_bls12_381::Bls12_381;

    let dim = 15;
    let rng = &mut ark_std::test_rng();
    let ck = CommitterKeyMulti::<Bls12_381>::new(dim, rng);
    let ck_stream = CommitterKeyMultiStream::from(&ck);

    let poly = random_unique_vector(dim, rng);
    assert_eq!(ck.commit(&poly), ck_stream.commit(&poly.as_slice()));
}

#[test]
fn test_streaming_open() {
    use crate::misc::random_vector;
    use ark_bls12_381::Bls12_381;

    let dim = 15;
    let rng = &mut ark_std::test_rng();
    let ck = CommitterKeyMulti::<Bls12_381>::new(dim, rng);
    let ck_stream = CommitterKeyMultiStream::from(&ck);

    let poly = random_vector(1 << dim, rng);
    let evaluation_point = random_vector(dim, rng);
    assert_eq!(
        ck.open(&poly, &evaluation_point),
        ck_stream.open(&poly.as_slice(), &evaluation_point.as_slice())
    );
}

#[test]
fn test_end_to_end() {
    use crate::misc::evaluate_multi_poly;
    use crate::misc::random_vector;
    use crate::multikzg::VerifierKeyMulti;
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::Fr;

    let dim = 7;
    let rng = &mut ark_std::test_rng();
    let ck = CommitterKeyMulti::<Bls12_381>::new(dim, rng);
    let ck_streaming = CommitterKeyMultiStream::from(&ck);
    let vk = VerifierKeyMulti::from(&ck_streaming);

    let polynomial: Vec<Fr> = random_vector(1 << dim, rng);
    let polynomial_stream = polynomial.as_slice();

    let alpha: Vec<Fr> = random_vector(dim, rng);
    let commitment = ck_streaming.commit(&polynomial_stream);
    let (evaluation, proof) = ck_streaming.open(&polynomial_stream, &alpha);
    let expected_evaluation = evaluate_multi_poly(&polynomial_stream, &alpha);
    assert_eq!(evaluation, expected_evaluation);
    assert!(vk.verify(&commitment, &alpha, &evaluation, &proof).is_ok())
}

#[test]
fn test_serialize() {
    use ark_bls12_381::Bls12_381;

    let dim = 11;
    let rng = &mut ark_std::test_rng();
    let ck = CommitterKeyMulti::<Bls12_381>::new(dim, rng);
    let ck_streaming = CommitterKeyMultiStream::from(&ck);

    let mut ck_buf = Vec::new();
    assert!(ck_streaming.serialize_compressed(&mut ck_buf).is_ok());
    let deserialized_ck_streaming =
        CommitterKeyMultiStream::<TestStreamer<Bls12_381>, Bls12_381>::deserialize_compressed(
            ck_buf.as_slice(),
        )
        .unwrap();
    let deserialized_ck = CommitterKeyMulti::from(deserialized_ck_streaming);
    assert_eq!(deserialized_ck, ck);
}
