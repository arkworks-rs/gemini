use crate::iterable::Iterable;
use crate::misc::MatrixElement;
use ark_ff::Field;
use ark_std::borrow::Borrow;
use ark_std::marker::PhantomData;

#[derive(Clone, Copy)]
pub struct ValStream<F, S> {
    matrix: S,
    nonzero: usize,
    _field: PhantomData<F>,
}

pub struct ValStreamIter<F, I> {
    matrix_iter: I,
    _field: PhantomData<F>,
}

impl<F, S> ValStream<F, S>
where
    S: Iterable,
    S::Item: Borrow<MatrixElement<F>>,
    F: Field,
{
    pub fn new(matrix: S, nonzero: usize) -> Self {
        Self {
            matrix,
            nonzero,
            _field: PhantomData,
        }
    }
}
impl<F, S> Iterable for ValStream<F, S>
where
    S: Iterable,
    S::Item: Borrow<MatrixElement<F>>,
    F: Field,
{
    type Item = F;

    type Iter = ValStreamIter<F, S::Iter>;

    fn iter(&self) -> Self::Iter {
        let matrix_iter = self.matrix.iter();
        let _field = PhantomData;
        ValStreamIter {
            matrix_iter,
            _field,
        }
    }

    fn len(&self) -> usize {
        self.nonzero
    }
}

impl<F, I> Iterator for ValStreamIter<F, I>
where
    I: Iterator,
    I::Item: Borrow<MatrixElement<F>>,
    F: Field,
{
    type Item = F;
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        loop {
            let e = self.matrix_iter.next();
            if e.is_none() {
                return None;
            } else if let Some(e) = e {
                match *e.borrow() {
                    MatrixElement::EOL => continue,
                    MatrixElement::Element((e, _i)) => return Some(e),
                }
            }
        }
    }
}

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
    counter: usize,
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
            counter: self.len,
            _field: self._field,
        }
    }

    fn len(&self) -> usize {
        todo!()
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
                self.counter -= 1;
                self.next()
            }
            MatrixElement::Element((e, i)) => Some((self.counter, i, e)),
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

pub struct JointValIter<IA, IB, IC, F>
where
    IA: Iterator,
    IB: Iterator,
    IC: Iterator,
    F: Field,
    IA::Item: Borrow<MatrixElement<F>>,
    IB::Item: Borrow<MatrixElement<F>>,
    IC::Item: Borrow<MatrixElement<F>>,
{
    matrix_a: SparseMatrixIter<IA, F>,
    matrix_b: SparseMatrixIter<IB, F>,
    matrix_c: SparseMatrixIter<IC, F>,
    current_a: Option<(usize, usize, F)>,
    current_b: Option<(usize, usize, F)>,
    current_c: Option<(usize, usize, F)>,
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

impl<IA, IB, IC, F> Iterator for JointValIter<IA, IB, IC, F>
where
    IA: Iterator,
    IB: Iterator,
    IC: Iterator,
    F: Field,
    IA::Item: Borrow<MatrixElement<F>>,
    IB::Item: Borrow<MatrixElement<F>>,
    IC::Item: Borrow<MatrixElement<F>>,
{
    type Item = F;

    fn next(&mut self) -> Option<Self::Item> {
        let ea = self.current_a.take();
        let eb = self.current_b.take();
        let ec = self.current_c.take();
        match (ea, eb, ec) {
            // If all streams are empty, return None
            (None, None, None) => None,
            // If the A-matrix stream is not empty, but all other are, return its elements.
            (Some((_, _, e)), None, None) => Some(e),
            // If the A-matrix stream is empty, but one of thers is not, return 0 (the pad).
            (None, _, Some((_, _, _))) | (None, Some((_, _, _)), _) => Some(F::zero()),
            // If the three matrices have an element at the same position,
            // return the current element and advance all three
            (Some((ia, ja, ea)), Some((ib, jb, _)), Some((ic, jc, _)))
                if ia == ib && ja == jb && ic == ib && jc == jc =>
            {
                self.current_a = self.matrix_a.next();
                self.current_b = self.matrix_b.next();
                self.current_c = self.matrix_c.next();
                Some(ea)
            }
            // If the A-matrix stream is not empty, and B-matrix stream is not, but C is
            // *AND* the other matrix stream is at the same stage, then return the current element and advance both
            (Some((ia, ja, ea)), Some((ib, jb, _)), None) if ia == ib && ja == jb => {
                self.current_a = self.matrix_a.next();
                self.current_b = self.matrix_b.next();
                Some(ea)
            }
            // If the A-matrix stream is not empty, and C-matrix stream is not, but B is
            // *AND* the other matrix stream is at the same stage, then return the current element and advance both
            (Some((ia, ja, ea)), None, Some((ib, jb, _))) if ia == ib && ja == jb => {
                self.current_a = self.matrix_a.next();
                self.current_c = self.matrix_c.next();
                Some(ea)
            }
            // If the A-matrix stream is not empty, and one other is not
            // *AND* the other matrix stream is far ahead, then return the current element and advance A
            (Some((ia, ja, ea)), Some((ib, jb, _)), None)
            | (Some((ia, ja, ea)), None, Some((ib, jb, _)))
                if ia >= ib && ja > jb =>
            {
                self.current_a = self.matrix_a.next();
                Some(ea)
            }
            // If the A-matrix stream is not empty, and one other is not
            // *AND* the other matrix stream is behind, return zero.
            (Some((ia, ja, _)), Some((ib, jb, _)), None) if ia < ib || ja < jb => {
                self.current_b = self.matrix_b.next();
                Some(F::zero())
            }
            (Some((ia, ja, _)), None, Some((ib, jb, _))) if ia < ib || ja < jb => {
                self.current_c = self.matrix_c.next();
                Some(F::zero())
            }
            // If all three matrices have a next element,
            // and A is the highest, return A-next
            (Some((ia, ja, ea)), Some((ib, jb, _)), Some((ic, jc, _)))
                if ia >= ib && ja > jb && ia >= ic && ja > jc =>
            {
                self.current_a = self.matrix_a.next();
                Some(ea)
            }
            // If all three matrices have a next element,
            // and the other twos are equal, advance both and return 0.
            (Some((ia, ja, _)), Some((ib, jb, _)), Some((ic, jc, _)))
                if (ia < ib || ja < jb) && ib == ic && jb == jc =>
            {
                self.current_b = self.matrix_b.next();
                self.current_c = self.matrix_c.next();
                Some(F::zero())
            }
            // If all three matrices have a next element,
            // and C is far ahead than B, advance C and return 0.
            (Some((ia, ja, _)), Some((ib, jb, _)), Some((ic, jc, _)))
                if (ia < ib || ja < jb) && (ib <= ic && jb < jc) =>
            {
                self.current_c = self.matrix_c.next();
                Some(F::zero())
            }
            // If all three matrices have a next element,
            // and B is far ahread than C, advance B and return 0.
            (Some((ia, ja, _)), Some((ib, jb, _)), Some((ic, jc, _)))
                if (ia < ib || ja < jb) && (ib >= ic && jb > jc) =>
            {
                self.current_b = self.matrix_b.next();
                Some(F::zero())
            }
            _ => None,
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

    type Iter = JointValIter<SA::Iter, SB::Iter, SC::Iter, F>;

    fn iter(&self) -> Self::Iter {
        let mut matrix_a = self.matrix_a.iter();
        let mut matrix_b = self.matrix_b.iter();
        let mut matrix_c = self.matrix_c.iter();
        let current_a = matrix_a.next().map(|x| *x.borrow());
        let current_b = matrix_b.next().map(|x| *x.borrow());
        let current_c = matrix_c.next().map(|x| *x.borrow());

        Self::Iter {
            matrix_a,
            matrix_b,
            matrix_c,
            current_a,
            current_b,
            current_c,
        }
    }

    fn len(&self) -> usize {
        self.joint_len
    }
}
