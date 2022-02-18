use crate::iterable::Iterable;
use crate::misc::MatrixElement;
use ark_ff::Field;
use ark_std::borrow::Borrow;
use ark_std::marker::PhantomData;

#[derive(Clone, Copy)]
pub struct SparseMatrixStream<'a, F, S>
where
    S: Iterable,
    F: Field,
    S::Item: Borrow<MatrixElement<F>>,
{
    matrix: &'a S,
    _field: PhantomData<F>,
    len: usize,
}

pub struct SparseMatrixIter<I, F>
where
    I: Iterator,
    F: Field,
    I::Item: Borrow<MatrixElement<F>>,
{
    it: I,
    row: usize,
    _field: PhantomData<F>,
}

impl<'a, F, S> SparseMatrixStream<'a, F, S>
where
    S: Iterable,
    F: Field,
    S::Item: Borrow<MatrixElement<F>>,
{
    fn new(matrix: &'a S, len: usize) -> Self {
        Self {
            matrix,
            len,
            _field: PhantomData,
        }
    }
}

impl<'a, F, S> Iterable for SparseMatrixStream<'a, F, S>
where
    S: Iterable,
    F: Field,
    S::Item: Borrow<MatrixElement<F>>,
{
    type Item = (usize, usize, F);

    type Iter = SparseMatrixIter<S::Iter, F>;

    fn iter(&self) -> Self::Iter {
        Self::Iter {
            it: self.matrix.iter(),
            row: self.len - 1,
            _field: self._field,
        }
    }

    fn len(&self) -> usize {
        self.matrix.len()
    }
}

impl<F, I> Iterator for SparseMatrixIter<I, F>
where
    I: Iterator,
    F: Field,
    I::Item: Borrow<MatrixElement<F>>,
{
    type Item = (usize, usize, F);

    fn next(&mut self) -> Option<Self::Item> {
        let e = self.it.next()?;
        match *e.borrow() {
            MatrixElement::EOL => {
                self.row -= 1;
                self.next()
            }
            MatrixElement::Element((e, i)) => Some((self.row, i, e)),
        }
    }
}

pub struct JointIter<IA, IB, F>
where
    IA: Iterator<Item = (usize, usize, F)>,
    IB: Iterator<Item = (usize, usize, F)>,
    F: Field,
{
    matrix_a: IA,
    matrix_b: IB,
    current_a: Option<(usize, usize, F)>,
    current_b: Option<(usize, usize, F)>,
}

impl<IA, IB, F> Iterator for JointIter<IA, IB, F>
where
    IA: Iterator<Item = (usize, usize, F)>,
    IB: Iterator<Item = (usize, usize, F)>,
    F: Field,
{
    type Item = (usize, usize, F);

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        match (self.current_a, self.current_b) {
            // If all streams are empty, return None
            (None, None) => None,

            // If only the lhs is available, stream it
            (Some(e), None) => {
                self.current_a = self.matrix_a.next();
                Some(e)
            }
            // If only the rhs is available, pad it with zeros
            (None, Some((i, j, _))) => {
                self.current_b = self.matrix_b.next();
                Some((i, j, F::zero()))
            }
            // If only the two are available simultaneously, we have to make a choice:
            (Some((ia, ja, ea)), Some((ib, jb, _))) => {
                // two values on the same coordinate => advance both
                if ia == ib && ja == jb {
                    self.current_a = self.matrix_a.next();
                    self.current_b = self.matrix_b.next();
                    Some((ia, ja, ea))
                // lhs is ahead => advance rhs
                // } else if ja < jb || (ja == jb && ib > ia) {
                } else if ia < ib || (ia == ib && jb > ja) {
                    self.current_b = self.matrix_b.next();
                    Some((ib, jb, F::zero()))
                // rhs is ahed => advance lhs
                // } else if ja > jb || (ja==jb && ia > ib) {
                } else if ia > ib || (ia == ib && ja > jb) {
                    self.current_a = self.matrix_a.next();
                    Some((ia, ja, ea))
                // it should never happen e.g. that ib > ia and jb < ja
                } else {
                    panic!("Format invalid!")
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
pub struct JointValStream<'a, SA, SB, SC, F>
where
    SA: Iterable,
    SB: Iterable,
    SC: Iterable,
    F: Field,
    SA::Item: Borrow<MatrixElement<F>>,
    SB::Item: Borrow<MatrixElement<F>>,
    SC::Item: Borrow<MatrixElement<F>>,
{
    matrix_a: SparseMatrixStream<'a, F, SA>,
    matrix_b: SparseMatrixStream<'a, F, SB>,
    matrix_c: SparseMatrixStream<'a, F, SC>,
    joint_len: usize,
    _field: PhantomData<F>,
}

impl<'a, SA, SB, SC, F> JointValStream<'a, SA, SB, SC, F>
where
    SA: Iterable,
    SB: Iterable,
    SC: Iterable,
    F: Field,
    SA::Item: Borrow<MatrixElement<F>>,
    SB::Item: Borrow<MatrixElement<F>>,
    SC::Item: Borrow<MatrixElement<F>>,
{
    pub fn new(
        matrix_a: &'a SA,
        matrix_b: &'a SB,
        matrix_c: &'a SC,
        len: usize,
        joint_len: usize,
    ) -> Self {
        Self {
            matrix_a: SparseMatrixStream::new(matrix_a, len),
            matrix_b: SparseMatrixStream::new(matrix_b, len),
            matrix_c: SparseMatrixStream::new(matrix_c, len),
            joint_len,

            _field: PhantomData,
        }
    }
}

impl<IA, IB, F> JointIter<IA, IB, F>
where
    IA: Iterator<Item = (usize, usize, F)>,
    IB: Iterator<Item = (usize, usize, F)>,
    F: Field,
{
    fn new(mut matrix_a: IA, mut matrix_b: IB) -> Self {
        let current_a = matrix_a.next();
        let current_b = matrix_b.next();
        Self {
            matrix_a,
            matrix_b,
            current_a,
            current_b,
        }
    }
}

impl<'a, SA, SB, SC, F> Iterable for JointValStream<'a, SA, SB, SC, F>
where
    SA: Iterable,
    SB: Iterable,
    SC: Iterable,
    F: Field,
    SA::Item: Borrow<MatrixElement<F>>,
    SB::Item: Borrow<MatrixElement<F>>,
    SC::Item: Borrow<MatrixElement<F>>,
{
    type Item = F;

    type Iter = TrimValIter<
        JointIter<
            JointIter<SparseMatrixIter<SA::Iter, F>, SparseMatrixIter<SB::Iter, F>, F>,
            SparseMatrixIter<SC::Iter, F>,
            F,
        >,
        F,
    >;

    fn iter(&self) -> Self::Iter {
        let matrix_a = self.matrix_a.iter();
        let matrix_b = self.matrix_b.iter();
        let matrix_c = self.matrix_c.iter();

        TrimValIter(JointIter::new(JointIter::new(matrix_a, matrix_b), matrix_c))
    }

    fn len(&self) -> usize {
        self.joint_len
    }
}

pub struct TrimValIter<I, F>(I)
where
    I: Iterator<Item = (usize, usize, F)>,
    F: Field;

impl<I, F> Iterator for TrimValIter<I, F>
where
    I: Iterator<Item = (usize, usize, F)>,
    F: Field,
{
    type Item = F;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.0.next()?.2)
    }
}

pub struct TrimRowIter<I, F>(I)
where
    I: Iterator<Item = (usize, usize, F)>,
    F: Field;

impl<I, F> Iterator for TrimRowIter<I, F>
where
    I: Iterator<Item = (usize, usize, F)>,
    F: Field,
{
    type Item = usize;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        let item = self.0.next()?;
        Some(item.0)
    }
}

pub struct TrimColIter<I, T>(I)
where
    I: Iterator<Item = (usize, usize, T)>;

impl<I, T> Iterator for TrimColIter<I, T>
where
    I: Iterator<Item = (usize, usize, T)>,
{
    type Item = usize;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        let item = self.0.next()?;
        Some(item.1)
    }
}

#[derive(Clone, Copy)]
pub struct JointRowStream<'a, SA, SB, SC, F>
where
    SA: Iterable,
    SB: Iterable,
    SC: Iterable,
    F: Field,
    SA::Item: Borrow<MatrixElement<F>>,
    SB::Item: Borrow<MatrixElement<F>>,
    SC::Item: Borrow<MatrixElement<F>>,
{
    matrix_a: SparseMatrixStream<'a, F, SA>,
    matrix_b: SparseMatrixStream<'a, F, SB>,
    matrix_c: SparseMatrixStream<'a, F, SC>,
    joint_len: usize,
    _field: PhantomData<F>,
}

impl<'a, SA, SB, SC, F> JointRowStream<'a, SA, SB, SC, F>
where
    SA: Iterable,
    SB: Iterable,
    SC: Iterable,
    F: Field,
    SA::Item: Borrow<MatrixElement<F>>,
    SB::Item: Borrow<MatrixElement<F>>,
    SC::Item: Borrow<MatrixElement<F>>,
{
    pub fn new(
        matrix_a: &'a SA,
        matrix_b: &'a SB,
        matrix_c: &'a SC,
        len: usize,
        joint_len: usize,
    ) -> Self {
        Self {
            matrix_a: SparseMatrixStream::new(matrix_a, len),
            matrix_b: SparseMatrixStream::new(matrix_b, len),
            matrix_c: SparseMatrixStream::new(matrix_c, len),
            joint_len,

            _field: PhantomData,
        }
    }
}

impl<'a, SA, SB, SC, F> Iterable for JointRowStream<'a, SA, SB, SC, F>
where
    SA: Iterable,
    SB: Iterable,
    SC: Iterable,
    F: Field,
    SA::Item: Borrow<MatrixElement<F>>,
    SB::Item: Borrow<MatrixElement<F>>,
    SC::Item: Borrow<MatrixElement<F>>,
{
    type Item = usize;

    type Iter = TrimRowIter<
        JointIter<
            JointIter<SparseMatrixIter<SA::Iter, F>, SparseMatrixIter<SB::Iter, F>, F>,
            SparseMatrixIter<SC::Iter, F>,
            F,
        >,
        F,
    >;

    fn iter(&self) -> Self::Iter {
        let matrix_a = self.matrix_a.iter();
        let matrix_b = self.matrix_b.iter();
        let matrix_c = self.matrix_c.iter();

        TrimRowIter(JointIter::new(JointIter::new(matrix_a, matrix_b), matrix_c))
    }

    fn len(&self) -> usize {
        self.joint_len
    }
}

#[derive(Clone, Copy)]
pub struct JointColStream<'a, SA, SB, SC, F>
where
    SA: Iterable,
    SB: Iterable,
    SC: Iterable,
    F: Field,
    SA::Item: Borrow<MatrixElement<F>>,
    SB::Item: Borrow<MatrixElement<F>>,
    SC::Item: Borrow<MatrixElement<F>>,
{
    matrix_a: SparseMatrixStream<'a, F, SA>,
    matrix_b: SparseMatrixStream<'a, F, SB>,
    matrix_c: SparseMatrixStream<'a, F, SC>,
    joint_len: usize,
    _field: PhantomData<F>,
}

impl<'a, SA, SB, SC, F> JointColStream<'a, SA, SB, SC, F>
where
    SA: Iterable,
    SB: Iterable,
    SC: Iterable,
    F: Field,
    SA::Item: Borrow<MatrixElement<F>>,
    SB::Item: Borrow<MatrixElement<F>>,
    SC::Item: Borrow<MatrixElement<F>>,
{
    pub fn new(
        matrix_a: &'a SA,
        matrix_b: &'a SB,
        matrix_c: &'a SC,
        len: usize,
        joint_len: usize,
    ) -> Self {
        Self {
            matrix_a: SparseMatrixStream::new(matrix_a, len),
            matrix_b: SparseMatrixStream::new(matrix_b, len),
            matrix_c: SparseMatrixStream::new(matrix_c, len),
            joint_len,

            _field: PhantomData,
        }
    }
}

impl<'a, SA, SB, SC, F> Iterable for JointColStream<'a, SA, SB, SC, F>
where
    SA: Iterable,
    SB: Iterable,
    SC: Iterable,
    F: Field,
    SA::Item: Borrow<MatrixElement<F>>,
    SB::Item: Borrow<MatrixElement<F>>,
    SC::Item: Borrow<MatrixElement<F>>,
{
    type Item = usize;

    type Iter = TrimColIter<
        JointIter<
            JointIter<SparseMatrixIter<SA::Iter, F>, SparseMatrixIter<SB::Iter, F>, F>,
            SparseMatrixIter<SC::Iter, F>,
            F,
        >,
        F,
    >;

    fn iter(&self) -> Self::Iter {
        let matrix_a = self.matrix_a.iter();
        let matrix_b = self.matrix_b.iter();
        let matrix_c = self.matrix_c.iter();

        TrimColIter(JointIter::new(JointIter::new(matrix_a, matrix_b), matrix_c))
    }

    fn len(&self) -> usize {
        self.joint_len
    }
}

#[test]
fn test_joint_val() {
    use crate::iterable::dummy::Mat;
    use ark_bls12_381::Fr;

    let a = [
        MatrixElement::EOL,
        MatrixElement::Element((Fr::from(1u64), 1)),
        MatrixElement::EOL,
        MatrixElement::Element((Fr::from(2u64), 0)),
    ];

    let b = [
        MatrixElement::EOL,
        MatrixElement::Element((Fr::from(1u64), 1)),
        MatrixElement::EOL,
        MatrixElement::Element((Fr::from(2u64), 0)),
    ];

    let c = [
        MatrixElement::EOL,
        MatrixElement::Element((Fr::from(1u64), 1)),
        MatrixElement::EOL,
        MatrixElement::Element((Fr::from(2u64), 0)),
    ];
    let a_stream = Mat(&a, 2);
    let b_stream = Mat(&b, 2);
    let c_stream = Mat(&c, 2);
    let joint_a = JointValStream::new(&a_stream, &b_stream, &c_stream, 2, 2);
    assert_eq!(joint_a.len(), joint_a.iter().count());
    let mut joint_a_it = joint_a.iter();
    assert_eq!(joint_a_it.next(), Some(Fr::from(1u64)));
    assert_eq!(joint_a_it.next(), Some(Fr::from(2u64)));
    assert_eq!(joint_a_it.next(), None);
}

#[test]
fn test_matrix() {
    use ark_bls12_381::Fr;
    use ark_std::test_rng;

    use crate::circuit::{
        generate_relation, matrix_into_colmaj, matrix_into_rowmaj, random_circuit, Circuit,
    };
    use crate::iterable::dummy::Mat;

    let rng = &mut test_rng();
    let num_constraints = 16;
    let num_variables = num_constraints;
    let rows = num_variables;

    let circuit: Circuit<Fr> = random_circuit(rng, num_constraints, num_variables);
    let r1cs = generate_relation(circuit);

    let acolm = matrix_into_rowmaj(&r1cs.a);
    let bcolm = matrix_into_rowmaj(&r1cs.b);
    let ccolm = matrix_into_rowmaj(&r1cs.c);

    let a_colm = Mat(acolm.as_slice(), rows);
    let b_colm = Mat(bcolm.as_slice(), rows);
    let c_colm = Mat(ccolm.as_slice(), rows);

    let arowm = matrix_into_colmaj(&r1cs.a, rows);
    let browm = matrix_into_colmaj(&r1cs.b, rows);
    let crowm = matrix_into_colmaj(&r1cs.c, rows);
    let a_rowm = Mat(arowm.as_slice(), rows);
    let b_rowm = Mat(browm.as_slice(), rows);
    let c_rowm = Mat(crowm.as_slice(), rows);

    let nonzero = num_constraints;
    let joint_len = num_constraints * 3;
    let row = JointRowStream::new(&a_colm, &b_colm, &c_colm, nonzero, joint_len);
    let col = JointColStream::new(&a_colm, &b_colm, &c_colm, nonzero, joint_len);
    // in row major, the rows should be plain decreasing
    let mut state = row.iter().next().unwrap();
    for (x, _y) in row.iter().zip(col.iter()) {
        assert!(state >= x);
        state = x;
    }

    let row = JointColStream::new(&a_rowm, &b_rowm, &c_rowm, nonzero, joint_len);
    let col = JointRowStream::new(&a_rowm, &b_rowm, &c_rowm, nonzero, joint_len);
    // in row major, the rows should be plain decreasing
    let mut state = col.iter().next().unwrap();
    for (_x, y) in row.iter().zip(col.iter()) {
        // println!("pos: ({}, {})", x, y);
        assert!(state >= y);
        state = y;
    }
}
