//! Library for linear combination of streams.
use ark_ff::Field;
use ark_std::borrow::Borrow;
use ark_std::vec::Vec;

/// The iterator struct for linear combination of streams.
pub struct LinCombIter<'a, F, T> {
    pub t: T,
    pub coeffs: &'a [F],
    pub pads: Vec<usize>,
}

/// The stream struct for linear combination of streams.
#[derive(Clone, Copy)]
pub struct LinCombStream<'a, F, T> {
    pub t: T,
    pub coeffs: &'a [F],
}

// /// Foldings of a lienear combination of polynomials.
// ///
// /// Given as input a sequence of polynomials, take a linear combination of them using `coeffs`, and produce the foldings using `challenges`.
// #[macro_export]
// macro_rules! lincomb_fold {
//     (($($B:expr),*), $challenges:expr, $coeffs:expr) => {
//         crate::sumcheck::streams::FoldedPolynomialTree::new(
//             crate::tensorcheck::streams::LinCombStream{ t: ($($B,)*), coeffs: $coeffs },
//             $challenges
//         )
//     }
// }

/// Stream for the linear combination of some vectors, given the coefficients.
#[macro_export]
macro_rules! lincomb {
    (($($B:expr),*), $coeffs:expr) => {
        $crate::subprotocols::tensorcheck::streams::LinCombStream { t: ($(&$B,)*), coeffs: $coeffs }
    }
}

/// Macro generating the stream for the linear combination of an arbitrary number of elements.
macro_rules! impl_lincomb_iter {
    ($($B:ident),*) => (

        #[allow(non_snake_case)]
        #[allow(unused_assignments)]
        impl<'a, F, $($B),*> LinCombStream<'a, F, ($(&'a $B,)*)>
            where
            F: Field,
            $(
                $B: crate::iterable::Iterable,
                $B::Item: ark_std::borrow::Borrow<F>,
            )*
        {
            /// A new [`Iterable`](crate::iterable::Iterable) that
            /// computes on-the-fly the linear combination of the input streams
            /// with the coefficients.
            pub fn new(t: ($(&'a $B,)*), coeffs: &'a [F]) -> Self {
                Self {t, coeffs}
            }
        }

        #[allow(non_snake_case)]
        #[allow(unused_assignments)]
        impl<'a, F, $($B),*> crate::iterable::Iterable for LinCombStream<'a, F, ($(&'a $B,)*)>
            where
            F: Field,
            $(
                $B: crate::iterable::Iterable,
                $B::Item: ark_std::borrow::Borrow<F>,
            )*
        {
                type Item = F;
                type Iter = LinCombIter<'a, F, ($($B::Iter,)*)>;

                fn len(&self) -> usize {
                    let ($(ref $B,)*) = self.t;
                    let mut len = 0usize;
                    $(
                        len = usize::max(len, $B.len());
                    )*
                    len
                }

                fn iter(&self) -> Self::Iter {
                    let len = self.len();
                    let ($(ref $B,)*) = self.t;
                    let pads = vec![$(len - $B.len(),)*];
                    $(
                        let $B = $B.iter();
                    )*

                    LinCombIter {t: ($($B,)*), coeffs: self.coeffs, pads }
                }
        }

        #[allow(non_snake_case)]
        #[allow(unused_assignments)]
        impl<'a, F, $($B),*> Iterator for LinCombIter<'a, F, ($($B,)*)>
            where
            F: Field,
            $(
                $B: Iterator,
                $B::Item: Borrow<F>,
            )*
        {
            type Item = F;

            fn next(&mut self) -> Option<Self::Item>
            {
                let mut result = F::zero();
                let ($(ref mut $B,)*) = self.t;
                let mut i = 0;
                $(
                    // The padding in first clause guarantees that:
                    // - either the next element is Some(elt)
                    // - all elements are None
                    // Hence, here we can immediately return if the next element is None.
                    if self.pads[i] != 0 {
                        self.pads[i] -= 1
                    } else {
                        let elt = $B.next()?;
                        result += self.coeffs[i] * elt.borrow();
                    }
                    i+=1;
                )*
                result.into()
            }

        }
    );
}

// Lets goooooooo
impl_lincomb_iter!(A0, A1);
impl_lincomb_iter!(A0, A1, A2);
impl_lincomb_iter!(A0, A1, A2, A3);
impl_lincomb_iter!(A0, A1, A2, A3, A4);
impl_lincomb_iter!(A0, A1, A2, A3, A4, A5);
impl_lincomb_iter!(A0, A1, A2, A3, A4, A5, A6);
impl_lincomb_iter!(A0, A1, A2, A3, A4, A5, A6, A7);
impl_lincomb_iter!(A0, A1, A2, A3, A4, A5, A6, A7, A8);
impl_lincomb_iter!(A0, A1, A2, A3, A4, A5, A6, A7, A8, A9);
impl_lincomb_iter!(A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10);
impl_lincomb_iter!(A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11);
impl_lincomb_iter!(A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12);
impl_lincomb_iter!(A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13);
impl_lincomb_iter!(A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14);
impl_lincomb_iter!(A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15);
impl_lincomb_iter!(A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16);
impl_lincomb_iter!(A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20,
    A21
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20,
    A21, A22
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20,
    A21, A22, A23
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20,
    A21, A22, A23, A24
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20,
    A21, A22, A23, A24, A25
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20,
    A21, A22, A23, A24, A25, A26
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20,
    A21, A22, A23, A24, A25, A26, A27
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20,
    A21, A22, A23, A24, A25, A26, A27, A28
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20,
    A21, A22, A23, A24, A25, A26, A27, A28, A29
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20,
    A21, A22, A23, A24, A25, A26, A27, A28, A29, A30
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20,
    A21, A22, A23, A24, A25, A26, A27, A28, A29, A30, A31
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20,
    A21, A22, A23, A24, A25, A26, A27, A28, A29, A30, A31, A32
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20,
    A21, A22, A23, A24, A25, A26, A27, A28, A29, A30, A31, A32, A33
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20,
    A21, A22, A23, A24, A25, A26, A27, A28, A29, A30, A31, A32, A33, A34
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20,
    A21, A22, A23, A24, A25, A26, A27, A28, A29, A30, A31, A32, A33, A34, A35
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20,
    A21, A22, A23, A24, A25, A26, A27, A28, A29, A30, A31, A32, A33, A34, A35, A36
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20,
    A21, A22, A23, A24, A25, A26, A27, A28, A29, A30, A31, A32, A33, A34, A35, A36, A37
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20,
    A21, A22, A23, A24, A25, A26, A27, A28, A29, A30, A31, A32, A33, A34, A35, A36, A37, A38
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20,
    A21, A22, A23, A24, A25, A26, A27, A28, A29, A30, A31, A32, A33, A34, A35, A36, A37, A38, A39
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20,
    A21, A22, A23, A24, A25, A26, A27, A28, A29, A30, A31, A32, A33, A34, A35, A36, A37, A38, A39,
    A40
);
impl_lincomb_iter!(
    A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20,
    A21, A22, A23, A24, A25, A26, A27, A28, A29, A30, A31, A32, A33, A34, A35, A36, A37, A38, A39,
    A40, A41
);

#[test]
fn test_lincomb() {
    use ark_bls12_381::Fr as F;
    use ark_ff::One;
    use ark_std::Zero;

    let a0 = ark_std::iter::repeat(F::one()).take(100);
    let a1 = ark_std::iter::repeat(F::one()).take(100);
    let a2 = ark_std::iter::repeat(F::one()).take(100);
    let a3 = ark_std::iter::repeat(F::one()).take(100);
    let a4 = ark_std::iter::repeat(F::one()).take(100);
    let a5 = ark_std::iter::repeat(F::one()).take(100);
    let a6 = ark_std::iter::repeat(F::one()).take(100);
    let a7 = ark_std::iter::repeat(F::one()).take(100);
    let a8 = ark_std::iter::repeat(F::one()).take(100);
    let a9 = ark_std::iter::repeat(F::one()).take(100);
    let a10 = ark_std::iter::repeat(F::one()).take(100);
    let a11 = ark_std::iter::repeat(F::one()).take(100);
    let a12 = ark_std::iter::repeat(F::one()).take(100);
    let a13 = ark_std::iter::repeat(F::one()).take(100);
    let a14 = ark_std::iter::repeat(F::one()).take(100);
    let a15 = ark_std::iter::repeat(F::one()).take(100);
    let a16 = ark_std::iter::repeat(F::one()).take(100);
    let a17 = ark_std::iter::repeat(F::one()).take(100);
    let a18 = ark_std::iter::repeat(F::one()).take(100);
    let a19 = ark_std::iter::repeat(F::one()).take(100);
    let pads = [0usize; 20];

    let coeffs = ark_std::iter::repeat(F::zero())
        .take(20)
        .collect::<Vec<_>>();
    let lc = LinCombIter {
        t: (
            a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18,
            a19,
        ),
        coeffs: &coeffs,
        pads: pads.to_vec(),
    };
    let expanded = lc.collect::<Vec<_>>();
    assert_eq!(expanded[0], F::zero());
}
