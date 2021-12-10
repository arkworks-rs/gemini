//! Space-efficient implementation of the polynomial commitment of Kate et al.
use ark_poly::Polynomial;
use ark_std::borrow::Borrow;
use ark_std::collections::VecDeque;

use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::{PrimeField, Zero};

use crate::kzg::msm::{ChunkedPippenger, HashMapPippenger};
use crate::kzg::{vanishing_polynomial, MAX_MSM_BUFFER};
use crate::misc::ceil_div;

use crate::stream::{Reversed, Streamer};
use crate::sumcheck::streams::FoldedPolynomialTree;

use super::{time::CommitterKey, VerifierKey};
use super::{Commitment, EvaluationProof};

const LENGTH_MISMATCH_MSG: &str = "Expecting at least one element in the committer key.";

/// The streaming SRS for the polynomial commitment scheme consists of a stream of consecutive powers of g.
/// It also implements functions for `setup`, `commit` and `open`.
#[derive(Clone, Copy)]
pub struct CommitterKeyStream<E, SG>
where
    E: PairingEngine,
    SG: Streamer,
    SG::Item: Borrow<E::G1Affine>,
{
    /// Stream of G1 elements.
    pub powers_of_g: SG,
    /// Two G2 elements needed for the committer.
    pub powers_of_g2: [E::G2Affine; 2],
}

impl<E, SG> CommitterKeyStream<E, SG>
where
    E: PairingEngine,
    SG: Streamer,
    SG::Item: Borrow<E::G1Affine>,
{
    /// Turn a streaming SRS into a normal SRS.
    pub fn as_committer_key(&self, max_degree: usize) -> CommitterKey<E> {
        let offset = self.powers_of_g.len() - max_degree;
        let mut powers_of_g = self
            .powers_of_g
            .stream()
            .skip(offset)
            .map(|x| *x.borrow())
            .collect::<Vec<_>>();
        powers_of_g.reverse();
        let powers_of_g2 = self.powers_of_g2.clone().to_vec();
        CommitterKey {
            powers_of_g,
            powers_of_g2,
        }
    }

    /// Evaluate a single polynomial at the point `alpha`, and provide an evaluation proof along with the evaluation.
    pub fn open<SF>(&self, polynomial: SF, alpha: &E::Fr) -> (E::Fr, EvaluationProof<E>)
    where
        SF: Streamer,
        SF::Item: Borrow<E::Fr>,
    {
        let mut quotient = ChunkedPippenger::new(MAX_MSM_BUFFER);

        let mut bases = self.powers_of_g.stream();
        let scalars = polynomial.stream();

        // align the streams and remove one degree
        bases
            .advance_by(self.powers_of_g.len() - polynomial.len())
            .expect(LENGTH_MISMATCH_MSG);

        let mut previous = E::Fr::zero();
        for (scalar, base) in scalars.zip(bases) {
            quotient.add(base, previous.into_repr());
            let coefficient = previous * alpha + scalar.borrow();
            previous = coefficient;
        }

        let evaluation = previous;
        let evaluation_proof = quotient.finalize().into_affine();
        (evaluation, EvaluationProof(evaluation_proof))
    }

    /// Evaluate a single polynomial at a set of points `points`, and provide an evaluation proof along with evaluations.
    pub fn open_multi_points<SF>(
        &self,
        polynomial: &SF,
        points: &[E::Fr],
    ) -> (Vec<E::Fr>, EvaluationProof<E>)
    where
        SF: Streamer,
        SF::Item: Borrow<E::Fr>,
    {
        let zeros = vanishing_polynomial(points);
        let mut quotient = ChunkedPippenger::new(MAX_MSM_BUFFER);
        let mut bases = self.powers_of_g.stream();
        bases
            .advance_by(self.powers_of_g.len() - polynomial.len() + zeros.degree())
            .unwrap();

        let mut state = VecDeque::<E::Fr>::with_capacity(points.len());

        let mut polynomial_iterator = polynomial.stream();

        (0..points.len()).for_each(|_| {
            state.push_back(*polynomial_iterator.next().unwrap().borrow());
        });

        for coefficient in polynomial_iterator {
            let coefficient = coefficient.borrow();
            let quotient_coefficient = state.pop_front().unwrap();
            state.push_back(*coefficient);
            (0..points.len()).for_each(|i| {
                state[i] -= zeros.coeffs[zeros.degree() - i - 1] * quotient_coefficient;
            });
            let base = bases.next().unwrap();
            quotient.add(base, quotient_coefficient.into_repr());
        }
        let remainder = state.make_contiguous().to_vec();
        let commitment = EvaluationProof(quotient.finalize().into_affine());
        (remainder, commitment)
    }

    /// The commitment procedures, that takes as input a committer key and the streaming coefficients of polynomial, and produces the desired commitment.
    pub fn commit<SF>(&self, polynomial: &SF) -> Commitment<E>
    where
        SF: Streamer,
        SF::Item: Borrow<E::Fr>,
    {
        assert!(self.powers_of_g.len() >= polynomial.len());

        Commitment(
            crate::kzg::msm::stream_pippenger::msm_chunks(&self.powers_of_g, polynomial)
                .into_affine(),
        )
    }

    /// The commitment procedures for our tensor check protocol.
    /// The algorithm takes advantage of the tree structure of folding polynomials in our protocol. Please refer to our paper for more details.
    /// The function takes as input a committer key and the tree structure of all the folding polynomials, and produces the desired commitment for each polynomial.
    pub fn commit_folding<SF>(
        &self,
        polynomials: &FoldedPolynomialTree<E::Fr, SF>,
    ) -> Vec<Commitment<E>>
    where
        SF: Streamer,
        SF::Item: Borrow<E::Fr>,
    {
        let n = polynomials.depth();
        let mut pippengers: Vec<ChunkedPippenger<E::G1Affine>> = Vec::new();
        let mut folded_bases = Vec::new();
        for i in 1..n + 1 {
            let pippenger = ChunkedPippenger::with_size(MAX_MSM_BUFFER / n);
            let mut bases = self.powers_of_g.stream();

            let delta = self.powers_of_g.len() - ceil_div(polynomials.len(), 1 << i);
            bases.advance_by(delta).expect(LENGTH_MISMATCH_MSG);
            folded_bases.push(bases);
            pippengers.push(pippenger);
        }

        for (i, coefficient) in polynomials.stream() {
            let base = folded_bases[i - 1].next().unwrap();
            pippengers[i - 1].add(base.borrow(), coefficient.into_repr());
        }

        pippengers
            .into_iter()
            .map(|p| Commitment(p.finalize().into_affine()))
            .collect::<Vec<_>>()
    }

    /// The commitment procedures for our tensor check protocol.
    /// The algorithm takes advantage of the tree structure of folding polynomials in our protocol. Please refer to our paper for more details.
    /// The function evaluates all the folding polynomials at a set of evaluation points `points` and produces a single batched evaluation proof.
    /// `eta` is the random challenge for batching folding polynomials.
    pub fn open_folding<'a, SF>(
        &self,
        polynomials: FoldedPolynomialTree<'a, E::Fr, SF>,
        points: &[E::Fr],
        etas: &[E::Fr],
    ) -> (Vec<Vec<E::Fr>>, EvaluationProof<E>)
    where
        SG: Streamer,
        SF: Streamer,
        E: PairingEngine,
        SG::Item: Borrow<E::G1Affine>,
        SF::Item: Borrow<E::Fr> + Copy,
    {
        let n = polynomials.depth();
        let mut pippenger = HashMapPippenger::<E::G1Affine>::new(MAX_MSM_BUFFER);
        let mut folded_bases = Vec::new();
        let zeros = vanishing_polynomial(points);
        let mut remainders = vec![VecDeque::new(); n];

        for i in 1..n + 1 {
            let mut bases = self.powers_of_g.stream();
            let delta = self.powers_of_g.len() - ceil_div(polynomials.len(), 1 << i);
            bases.advance_by(delta).expect(LENGTH_MISMATCH_MSG);

            (0..points.len()).for_each(|_| {
                remainders[i - 1].push_back(E::Fr::zero());
            });

            folded_bases.push(bases);
        }

        for (i, coefficient) in polynomials.stream() {
            if i == 0 {
                continue;
            } // XXX. skip the 0th elements automatically

            let base = folded_bases[i - 1].next().unwrap();
            let coefficient = coefficient.borrow();
            let quotient_coefficient = remainders[i - 1].pop_front().unwrap();
            remainders[i - 1].push_back(*coefficient);
            (0..points.len()).for_each(|j| {
                remainders[i - 1][j] -= zeros.coeffs[zeros.degree() - j - 1] * quotient_coefficient;
            });

            let scalar = etas[i - 1] * quotient_coefficient;
            pippenger.add(base, scalar);
        }

        let evaluation_proof = pippenger.finalize().into_affine();
        let remainders = remainders
            .iter_mut()
            .map(|x| x.make_contiguous().to_vec())
            .collect::<Vec<_>>();

        (remainders, EvaluationProof(evaluation_proof))
    }
}

impl<'a, E: PairingEngine> From<&'a CommitterKey<E>>
    for CommitterKeyStream<E, Reversed<'a, E::G1Affine>>
{
    fn from(ck: &'a CommitterKey<E>) -> Self {
        CommitterKeyStream {
            powers_of_g: Reversed::new(&ck.powers_of_g),
            /*
                TODO: Gives more G2 elements
            */
            powers_of_g2: [ck.powers_of_g2[0], ck.powers_of_g2[1]],
        }
    }
}

impl<E, SG> From<&CommitterKeyStream<E, SG>> for VerifierKey<E>
where
    E: PairingEngine,
    SG: Streamer,
    SG::Item: Borrow<E::G1Affine>,
{
    fn from(ck: &CommitterKeyStream<E, SG>) -> Self {
        let powers_of_g2 = ck.powers_of_g2;
        // take the first element from the stream
        let g = *ck
            .powers_of_g
            .stream()
            .last()
            .expect(LENGTH_MISMATCH_MSG)
            .borrow();
        Self {
            powers_of_g2: powers_of_g2.to_vec(),
            powers_of_g: vec![g],
        }
    }
}

#[test]
fn test_open_multi_points() {
    use crate::ark_std::UniformRand;
    use crate::misc::evaluate_be;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::Field;
    use ark_poly::univariate::DensePolynomial;
    use ark_poly::UVPolynomial;
    use ark_std::test_rng;

    let rng = &mut test_rng();
    // f = 80*x^6 + 80*x^5 + 88*x^4 + 3*x^3 + 73*x^2 + 7*x + 24
    let polynomial = [
        Fr::from(80u64),
        Fr::from(80u64),
        Fr::from(88u64),
        Fr::from(3u64),
        Fr::from(73u64),
        Fr::from(7u64),
        Fr::from(24u64),
    ];
    let polynomial_stream = &polynomial[..];
    let beta = Fr::from(53u64);

    let time_ck = CommitterKey::<Bls12_381>::new(200, 3, rng);
    let space_ck = CommitterKeyStream::from(&time_ck);

    let (remainder, _commitment) =
        space_ck.open_multi_points(&polynomial_stream, &[beta.square(), beta, -beta]);
    let evaluation_remainder = evaluate_be(&remainder, &beta);
    assert_eq!(evaluation_remainder, Fr::from(1807299544171u64));

    let (remainder, _commitment) = space_ck.open_multi_points(&polynomial_stream, &[beta]);
    assert_eq!(remainder.len(), 1);

    // get a random polynomial with random coefficient,
    let polynomial = DensePolynomial::rand(100, rng).coeffs().to_vec();
    let polynomial_stream = &polynomial[..];
    let beta = Fr::rand(rng);
    let (_, evaluation_proof_batch) = space_ck.open_multi_points(&polynomial_stream, &[beta]);
    let (_, evaluation_proof_single) = space_ck.open(polynomial_stream, &beta);
    assert_eq!(evaluation_proof_batch, evaluation_proof_single);

    let (remainder, _evaluation_poof) =
        space_ck.open_multi_points(&polynomial_stream, &[beta, -beta, beta.square()]);
    let expected_evaluation = evaluate_be(&remainder, &beta);
    let obtained_evaluation = evaluate_be(&polynomial, &beta);
    assert_eq!(expected_evaluation, obtained_evaluation);
    let expected_evaluation = evaluate_be(&remainder, &beta.square());
    let obtained_evaluation = evaluate_be(&polynomial, &beta.square());
    assert_eq!(expected_evaluation, obtained_evaluation);
    // let expected_evaluation = evaluate_be(&remainder, &beta.square());
    // let obtained_evaluation = evaluate_be(&polynomial, &beta.square());
    // assert_eq!(expected_evaluation, obtained_evaluation);
    // let expected_evaluation = evaluate_be(&remainder, &beta.square());
    // let obtained_evaluation = evaluate_be(&polynomial, &beta.square());
    // assert_eq!(expected_evaluation, obtained_evaluation);
}
