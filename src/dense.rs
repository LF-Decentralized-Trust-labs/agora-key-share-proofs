/*
    Copyright Hyperledger. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::*;
use blsful::inner_types::PrimeField;
use rand::RngCore;
use serde::{
    de::{Error as E, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    marker::PhantomData,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

/// A polynomial over a prime field
#[derive(Clone, PartialEq, Eq)]
pub struct DensePolyPrimeField<F: PrimeField>(
    /// The coefficients of the polynomial
    pub Vec<F>,
);

unsafe impl<F: PrimeField> Send for DensePolyPrimeField<F> {}

unsafe impl<F: PrimeField> Sync for DensePolyPrimeField<F> {}

impl<F: PrimeField> Default for DensePolyPrimeField<F> {
    fn default() -> Self {
        Self(vec![])
    }
}

impl<F: PrimeField> Debug for DensePolyPrimeField<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "PolyPrimeField({:?})", self.0)
    }
}

impl<F: PrimeField> Display for DensePolyPrimeField<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let vals = self
            .0
            .iter()
            .enumerate()
            .map(|(power, c)| {
                let c = hex::encode(c.to_repr().as_ref());
                if power == 0 {
                    c
                } else {
                    format!("{}{}", c, to_super_script_digits(power))
                }
            })
            .collect::<Vec<_>>()
            .join(" + ");
        write!(f, "{}", vals)
    }
}

impl<F: PrimeField> Add<&DensePolyPrimeField<F>> for &DensePolyPrimeField<F> {
    type Output = DensePolyPrimeField<F>;

    fn add(self, rhs: &DensePolyPrimeField<F>) -> Self::Output {
        let mut output = self.clone();
        add_poly(&mut output.0, &rhs.0);
        output
    }
}

impl<F: PrimeField> Add<&DensePolyPrimeField<F>> for DensePolyPrimeField<F> {
    type Output = DensePolyPrimeField<F>;

    fn add(self, rhs: &DensePolyPrimeField<F>) -> Self::Output {
        &self + rhs
    }
}

impl<F: PrimeField> Add<DensePolyPrimeField<F>> for &DensePolyPrimeField<F> {
    type Output = DensePolyPrimeField<F>;

    fn add(self, rhs: DensePolyPrimeField<F>) -> Self::Output {
        self + &rhs
    }
}

impl<F: PrimeField> Add for DensePolyPrimeField<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        &self + &rhs
    }
}

impl<F: PrimeField> AddAssign<&DensePolyPrimeField<F>> for DensePolyPrimeField<F> {
    fn add_assign(&mut self, rhs: &DensePolyPrimeField<F>) {
        add_poly(&mut self.0, &rhs.0);
    }
}

impl<F: PrimeField> AddAssign<DensePolyPrimeField<F>> for DensePolyPrimeField<F> {
    fn add_assign(&mut self, rhs: DensePolyPrimeField<F>) {
        add_poly(&mut self.0, &rhs.0);
    }
}

impl<F: PrimeField> Sub<&DensePolyPrimeField<F>> for &DensePolyPrimeField<F> {
    type Output = DensePolyPrimeField<F>;

    fn sub(self, rhs: &DensePolyPrimeField<F>) -> Self::Output {
        let mut output = self.clone();
        sub_poly(&mut output.0, &rhs.0);
        output
    }
}

impl<F: PrimeField> Sub<&DensePolyPrimeField<F>> for DensePolyPrimeField<F> {
    type Output = DensePolyPrimeField<F>;

    fn sub(self, rhs: &DensePolyPrimeField<F>) -> Self::Output {
        &self - rhs
    }
}

impl<F: PrimeField> Sub<DensePolyPrimeField<F>> for &DensePolyPrimeField<F> {
    type Output = DensePolyPrimeField<F>;

    fn sub(self, rhs: DensePolyPrimeField<F>) -> Self::Output {
        self - &rhs
    }
}

impl<F: PrimeField> Sub for DensePolyPrimeField<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        &self - &rhs
    }
}

impl<F: PrimeField> SubAssign<&DensePolyPrimeField<F>> for DensePolyPrimeField<F> {
    fn sub_assign(&mut self, rhs: &DensePolyPrimeField<F>) {
        sub_poly(&mut self.0, &rhs.0);
    }
}

impl<F: PrimeField> SubAssign<DensePolyPrimeField<F>> for DensePolyPrimeField<F> {
    fn sub_assign(&mut self, rhs: DensePolyPrimeField<F>) {
        sub_poly(&mut self.0, &rhs.0);
    }
}

impl<F: PrimeField> Neg for &DensePolyPrimeField<F> {
    type Output = DensePolyPrimeField<F>;

    fn neg(self) -> Self::Output {
        let mut output = self.clone();
        output.0.iter_mut().for_each(|c| *c = -*c);
        output
    }
}

impl<F: PrimeField> Neg for DensePolyPrimeField<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        -&self
    }
}

impl<F: PrimeField> Mul<&DensePolyPrimeField<F>> for &DensePolyPrimeField<F> {
    type Output = DensePolyPrimeField<F>;

    fn mul(self, rhs: &DensePolyPrimeField<F>) -> Self::Output {
        let mut output = self.clone();
        mul_poly(&mut output.0, &rhs.0);
        output
    }
}

impl<F: PrimeField> Mul<&DensePolyPrimeField<F>> for DensePolyPrimeField<F> {
    type Output = DensePolyPrimeField<F>;

    fn mul(self, rhs: &DensePolyPrimeField<F>) -> Self::Output {
        &self * rhs
    }
}

impl<F: PrimeField> Mul<DensePolyPrimeField<F>> for &DensePolyPrimeField<F> {
    type Output = DensePolyPrimeField<F>;

    fn mul(self, rhs: DensePolyPrimeField<F>) -> Self::Output {
        self * &rhs
    }
}

impl<F: PrimeField> Mul for DensePolyPrimeField<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        &self * &rhs
    }
}

impl<F: PrimeField> Mul<&F> for &DensePolyPrimeField<F> {
    type Output = DensePolyPrimeField<F>;

    fn mul(self, rhs: &F) -> Self::Output {
        self * *rhs
    }
}

impl<F: PrimeField> Mul<F> for &DensePolyPrimeField<F> {
    type Output = DensePolyPrimeField<F>;

    fn mul(self, rhs: F) -> Self::Output {
        let output = self.0.iter().map(|s| *s * rhs).collect();
        DensePolyPrimeField(output)
    }
}

impl<F: PrimeField> Mul<&F> for DensePolyPrimeField<F> {
    type Output = Self;

    fn mul(self, rhs: &F) -> Self::Output {
        &self * *rhs
    }
}

impl<F: PrimeField> Mul<F> for DensePolyPrimeField<F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        &self * rhs
    }
}

impl<F: PrimeField> MulAssign<&DensePolyPrimeField<F>> for DensePolyPrimeField<F> {
    fn mul_assign(&mut self, rhs: &DensePolyPrimeField<F>) {
        mul_poly(&mut self.0, &rhs.0);
    }
}

impl<F: PrimeField> MulAssign<DensePolyPrimeField<F>> for DensePolyPrimeField<F> {
    fn mul_assign(&mut self, rhs: DensePolyPrimeField<F>) {
        mul_poly(&mut self.0, &rhs.0);
    }
}

impl<F: PrimeField> MulAssign<&F> for DensePolyPrimeField<F> {
    fn mul_assign(&mut self, rhs: &F) {
        *self *= *rhs;
    }
}

impl<F: PrimeField> MulAssign<F> for DensePolyPrimeField<F> {
    fn mul_assign(&mut self, rhs: F) {
        self.0.iter_mut().for_each(|coeff| *coeff *= rhs);
    }
}

impl<F: PrimeField> Serialize for DensePolyPrimeField<F> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            self.0
                .iter()
                .map(|sc| hex::encode(sc.to_repr().as_ref()))
                .collect::<Vec<_>>()
                .serialize(s)
        } else {
            let mut bytes = vec![];
            for c in self.0.iter() {
                bytes.extend_from_slice(c.to_repr().as_ref());
            }
            s.serialize_bytes(&bytes)
        }
    }
}

impl<'de, F: PrimeField> Deserialize<'de> for DensePolyPrimeField<F> {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if d.is_human_readable() {
            let scalars = <Vec<String>>::deserialize(d)?;
            let mut coeffs = Vec::with_capacity(scalars.len());
            for s in scalars {
                let mut repr = F::Repr::default();
                let bytes = hex::decode(s).map_err(|e| E::custom(format!("Invalid hex: {}", e)))?;
                repr.as_mut().copy_from_slice(&bytes[..]);
                coeffs.push(
                    Option::from(F::from_repr(repr))
                        .ok_or(E::custom("Invalid scalar".to_string()))?,
                );
            }
            Ok(Self(coeffs))
        } else {
            struct PolyVisitor<F: PrimeField>(PhantomData<F>);

            impl<F: PrimeField> Visitor<'_> for PolyVisitor<F> {
                type Value = DensePolyPrimeField<F>;

                fn expecting(&self, f: &mut Formatter<'_>) -> FmtResult {
                    write!(f, "a byte sequence")
                }

                fn visit_bytes<EE>(self, v: &[u8]) -> Result<Self::Value, EE>
                where
                    EE: E,
                {
                    let mut repr = F::Repr::default();
                    let sc_len = repr.as_ref().len();
                    if v.len() % sc_len != 0 {
                        return Err(E::custom(format!("Invalid length: {}", v.len())));
                    }
                    let mut coeffs = Vec::with_capacity(v.len() / sc_len);
                    for chunk in v.chunks(sc_len) {
                        repr.as_mut().copy_from_slice(chunk);
                        coeffs.push(
                            Option::from(F::from_repr(repr))
                                .ok_or(E::custom("Invalid scalar".to_string()))?,
                        );
                    }
                    Ok(DensePolyPrimeField(coeffs))
                }
            }

            d.deserialize_bytes(PolyVisitor(PhantomData))
        }
    }
}

impl<'a, F: PrimeField> FromIterator<&'a F> for DensePolyPrimeField<F> {
    fn from_iter<T: IntoIterator<Item = &'a F>>(iter: T) -> Self {
        let mut inner = Vec::new();
        for coeff in iter {
            inner.push(*coeff);
        }
        Self(inner)
    }
}

impl<F: PrimeField> FromIterator<F> for DensePolyPrimeField<F> {
    fn from_iter<T: IntoIterator<Item = F>>(iter: T) -> Self {
        Self(Vec::from_iter(iter))
    }
}

impl<F: PrimeField> From<DensePolyPrimeField<F>> for Vec<u8> {
    fn from(p: DensePolyPrimeField<F>) -> Self {
        Self::from(&p)
    }
}

impl<F: PrimeField> From<&DensePolyPrimeField<F>> for Vec<u8> {
    fn from(p: &DensePolyPrimeField<F>) -> Self {
        let mut bytes = vec![];
        for c in p.0.iter() {
            bytes.extend_from_slice(c.to_repr().as_ref());
        }
        bytes
    }
}

impl<F: PrimeField> TryFrom<Vec<u8>> for DensePolyPrimeField<F> {
    type Error = &'static str;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(&bytes[..])
    }
}

impl<F: PrimeField> TryFrom<&Vec<u8>> for DensePolyPrimeField<F> {
    type Error = &'static str;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl<F: PrimeField> TryFrom<&[u8]> for DensePolyPrimeField<F> {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut repr = F::Repr::default();
        let sc_len = repr.as_ref().len();
        if bytes.len() % sc_len != 0 {
            return Err("Invalid length");
        }
        let mut coeffs = Vec::with_capacity(bytes.len() / sc_len);
        for chunk in bytes.chunks(sc_len) {
            repr.as_mut().copy_from_slice(chunk);
            coeffs.push(Option::from(F::from_repr(repr)).expect("Invalid scalar"));
        }
        Ok(Self(coeffs))
    }
}

impl<F: PrimeField> TryFrom<Box<[u8]>> for DensePolyPrimeField<F> {
    type Error = &'static str;

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_ref())
    }
}

impl<F: PrimeField> DensePolyPrimeField<F> {
    /// The zero polynomial
    pub const ZERO: Self = Self(Vec::new());

    /// Check if the polynomial is zero
    pub fn is_zero(&self) -> bool {
        self.0.is_empty() || (self.0.len() == 1 && self.0[0] == F::ZERO)
    }

    /// Create a polynomial with a value of 1
    pub fn one() -> Self {
        Self(vec![F::ONE])
    }

    /// Get the degree of the polynomial
    pub fn degree(&self) -> usize {
        if self.is_zero() {
            0
        } else {
            // debug_assert!(self.0.last().map_or(false, |c| bool::from(!c.is_zero())));
            // self.0.len() - 1
            let last_term_idx = self
                .0
                .iter()
                .rposition(|c| bool::from(!c.is_zero()))
                .unwrap_or_else(|| 0);
            last_term_idx
        }
    }

    /// Check if the polynomial is cyclotomic
    pub fn is_cyclotomic(&self) -> bool {
        let one = F::ONE;
        let m_one = -one;
        let mut seen_one = false;
        if self.0[0] != m_one {
            return false;
        }
        for i in 1..self.0.len() {
            if self.0[i] != F::ZERO {
                if self.0[i] != one {
                    return false;
                }
                if seen_one {
                    return false;
                }
                seen_one = true;
            }
        }
        true
    }

    /// Get the polynomial coefficients
    pub fn coefficients(&self) -> &[F] {
        self.0.as_slice()
    }

    /// Get a mutable reference to the polynomial coefficients
    pub fn coefficients_mut(&mut self) -> &mut [F] {
        self.0.as_mut_slice()
    }

    /// Create a polynomial given the coefficients
    pub fn from_coefficients<B: AsRef<[F]>>(coefficients: B) -> Self {
        let mut out = Self(coefficients.as_ref().to_vec());
        out.trim();
        out
    }

    /// Randomly create a polynomial with the specified degree
    pub fn random(degree: usize, mut rng: impl RngCore) -> Self {
        let mut coeffs = Vec::with_capacity(degree);
        for _ in 0..=degree {
            coeffs.push(F::random(&mut rng));
        }
        Self::from_coefficients(coeffs)
    }

    /// Remove leading coefficients that are zero
    pub fn trim(&mut self) {
        for i in (0..self.0.len()).rev() {
            if !bool::from(self.0[i].is_zero()) {
                self.0.truncate(i + 1);
                return;
            }
        }
    }

    /// Compute the dot product of the two polynomials
    pub fn dot_product(&self, other: &Self) -> F {
        self.0
            .iter()
            .zip(other.0.iter())
            .map(|(a, b)| *a * *b)
            .sum()
    }

    /// Evaluate the polynomial for the given value
    pub fn evaluate(&self, x: &F) -> F {
        if self.is_zero() {
            F::ZERO
        } else {
            // Horner's method
            self.0.iter().rfold(F::ZERO, move |acc, c| acc * x + c)
        }
    }

    /// Remove any leading zero coefficients from the polynomial
    pub fn trim_leading_zeros(&mut self) {
        let mut i = self.0.len();
        while i > 0 && bool::from(self.0[i - 1].is_zero()) {
            i -= 1;
        }
        self.0.truncate(i);
    }

    /// Compute the polynomial division and return the quotient and remainder
    pub fn poly_mod(&self, m: &Self) -> (Self, Self) {
        if m.is_cyclotomic() {
            let degree =
                m.0.iter()
                    .rposition(|c| bool::from(!c.is_zero()))
                    .expect("m is cyclotomic");
            return self.poly_mod_cyclotomic(degree);
        }
        let self_degree = self.degree();
        let m_degree = m.degree();
        let mut self_trimmed = self.clone();
        self_trimmed.trim();
        if self_degree < m_degree {
            return (Self::ZERO, self_trimmed);
        }
        debug_assert!(m_degree > 0);

        let largest_coeff_inv = m.0[m_degree].invert().unwrap();
        let mut coefficients = vec![F::ZERO; self_degree - m_degree + 1];
        let mut remainder = Self(self_trimmed.0.clone());

        let mut degree = remainder.degree();
        while degree >= m_degree {
            let d = degree - m_degree;
            let lc_index = remainder
                .0
                .iter()
                .rposition(|c| bool::from(!c.is_zero()))
                .unwrap_or(remainder.0.len() - 1);
            let c = remainder.0[lc_index] * largest_coeff_inv;

            for i in 0..m_degree {
                remainder.0[i + d] -= c * m.0[i];
            }

            remainder.0.pop();
            remainder.trim();
            coefficients[d] = c;
            degree = remainder.degree();
        }

        (Self(coefficients), remainder)
    }

    fn poly_mod_cyclotomic(&self, degree: usize) -> (Self, Self) {
        if self.0.len() <= degree {
            return (Self::ZERO, self.clone());
        }

        let mut remainder = self.clone();
        let mut div = Vec::with_capacity(self.0.len() - degree);
        (degree..self.0.len()).rev().for_each(|i| {
            let coeff_change = remainder.0[i];
            remainder.0[i - degree] += coeff_change;
            div.push(coeff_change);
        });
        (
            Self(div.into_iter().rev().collect()),
            Self(remainder.0.into_iter().take(degree).collect()),
        )
    }
}

fn add_poly<F: PrimeField>(lhs: &mut Vec<F>, rhs: &[F]) {
    let min_len = core::cmp::min(lhs.len(), rhs.len());

    if lhs.len() == min_len {
        for i in rhs.iter().skip(min_len) {
            lhs.push(*i);
        }
    }
    for (i, item) in rhs[..min_len].iter().enumerate() {
        lhs[i] += item;
    }
}

fn sub_poly<F: PrimeField>(lhs: &mut Vec<F>, rhs: &[F]) {
    let min_len = core::cmp::min(lhs.len(), rhs.len());

    if lhs.len() == min_len {
        for i in rhs.iter().skip(min_len) {
            lhs.push(-*i);
        }
    }

    for (i, item) in rhs[..min_len].iter().enumerate() {
        lhs[i] -= item;
    }
}

fn mul_poly<F: PrimeField>(lhs: &mut Vec<F>, rhs: &[F]) {
    if lhs.is_empty() || rhs.is_empty() {
        lhs.clear();
    } else {
        let orig = lhs.clone();
        for i in &mut *lhs {
            *i = F::ZERO;
        }
        // M + N + 1
        lhs.resize_with(lhs.len() + rhs.len(), || F::ZERO);

        // Calculate product
        for (i, item) in orig.iter().enumerate() {
            for (j, jitem) in rhs.iter().enumerate() {
                lhs[i + j] += *jitem * *item;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blsful::inner_types::{Field, Scalar};
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    #[test]
    fn poly_mod() {
        let mut rng = ChaChaRng::from_seed([7u8; 32]);

        let a = DensePolyPrimeField((0..63).map(|_| Scalar::random(&mut rng)).collect());
        let b = DensePolyPrimeField((0..33).map(|_| Scalar::random(&mut rng)).collect());

        let (div, rem) = a.poly_mod(&b);
        let div_b = &div * &b;
        let mut div_b_pr = &div_b + &rem;
        div_b_pr.trim();
        assert_eq!(a, div_b_pr);
    }

    #[test]
    fn poly_mod_ng() {
        let my_num = DensePolyPrimeField(vec![-Scalar::ONE, Scalar::ZERO, Scalar::ONE]);
        // let my_num =
        //     DensePolyPrimeField(vec![-Scalar::ONE, -Scalar::ONE, Scalar::ONE, Scalar::ONE]);
        let my_den = DensePolyPrimeField(vec![-Scalar::ONE, Scalar::ONE]);
        let (my_quo, my_rem) = my_num.poly_mod(&my_den);
        let mut my_rem_trim = my_rem.clone();
        my_rem_trim.trim();
        assert!(my_rem_trim.is_zero());
    }

    #[test]
    fn poly_mod_cyclotomic() {
        const DEGREE: usize = 320;
        let mut rng = ChaChaRng::from_seed([11u8; 32]);
        let a = DensePolyPrimeField(
            (0..2 * DEGREE - 1)
                .map(|_| Scalar::random(&mut rng))
                .collect(),
        );
        let mut b = DensePolyPrimeField((0..DEGREE + 1).map(|_| Scalar::ZERO).collect());
        b.0[0] = -Scalar::ONE;
        b.0[DEGREE] = Scalar::ONE;
        let (div, rem) = a.poly_mod(&b);
        let div_b = &div * &b;
        let mut div_b_pr = &div_b + &rem;
        div_b_pr.trim();
        assert_eq!(a, div_b_pr);
    }

    #[test]
    fn serialize() {
        let mut rng = ChaChaRng::from_seed([11u8; 32]);
        let a = DensePolyPrimeField((0..10).map(|_| Scalar::random(&mut rng)).collect());
        let res = serde_json::to_string(&a);
        assert!(res.is_ok());
        let serialized = res.unwrap();
        let res = serde_json::from_str::<DensePolyPrimeField<Scalar>>(&serialized);
        assert!(res.is_ok());
        let deserialized = res.unwrap();
        assert_eq!(a, deserialized);

        let res = serde_bare::to_vec(&a);
        assert!(res.is_ok());
        let serialized = res.unwrap();
        let res = serde_bare::from_slice::<DensePolyPrimeField<Scalar>>(&serialized);
        assert!(res.is_ok());
        let deserialized = res.unwrap();
        assert_eq!(a, deserialized);
    }

    #[test]
    fn add() {
        let mut rng = ChaChaRng::from_seed([5u8; 32]);
        // Same length
        let a = DensePolyPrimeField::<Scalar>::random(5, &mut rng);
        let b = DensePolyPrimeField::<Scalar>::random(5, &mut rng);

        let c = &a + &b;
        for i in 0..6 {
            assert_eq!(c.0[i], a.0[i] + b.0[i]);
        }

        // Different lengths
        let a = DensePolyPrimeField::<Scalar>::random(4, &mut rng);
        let b = DensePolyPrimeField::<Scalar>::random(7, &mut rng);
        let c = &a + &b;
        assert_eq!(c.0.len(), 8);
        for i in 0..5 {
            assert_eq!(c.0[i], a.0[i] + b.0[i]);
        }
        for i in 5..8 {
            assert_eq!(c.0[i], b.0[i]);
        }
    }

    #[test]
    fn sub() {
        let mut rng = ChaChaRng::from_seed([4u8; 32]);
        // Same length
        let a = DensePolyPrimeField::<Scalar>::random(5, &mut rng);
        let b = DensePolyPrimeField::<Scalar>::random(5, &mut rng);

        let c = &a - &b;
        for i in 0..6 {
            assert_eq!(c.0[i], a.0[i] - b.0[i]);
        }

        // Different lengths
        let a = DensePolyPrimeField::<Scalar>::random(4, &mut rng);
        let b = DensePolyPrimeField::<Scalar>::random(7, &mut rng);
        let c = &a - &b;
        assert_eq!(c.0.len(), 8);
        for i in 0..5 {
            assert_eq!(c.0[i], a.0[i] - b.0[i]);
        }
        for i in 5..8 {
            assert_eq!(c.0[i], -b.0[i]);
        }
    }

    #[test]
    fn dot_product() {
        let a = DensePolyPrimeField(vec![
            Scalar::from(5u64),
            Scalar::from(10u64),
            Scalar::from(20u64),
        ]);
        let b = DensePolyPrimeField(vec![
            Scalar::from(2u64),
            Scalar::from(4u64),
            Scalar::from(8u64),
        ]);

        let c = a.dot_product(&b);
        let expected = Scalar::from(5u64) * Scalar::from(2u64)
            + Scalar::from(10u64) * Scalar::from(4u64)
            + Scalar::from(20u64) * Scalar::from(8u64);
        assert_eq!(c, expected);
    }
}
