/*
    Copyright Hyperledger. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use blsful::inner_types::*;
use crypto_bigint::{
    impl_modulus,
    modular::constant_mod::{Residue, ResidueParams},
    NonZero, Zero, U256,
};
use vsss_rs::elliptic_curve::scalar::FromUintUnchecked;

pub const SUPERSCRIPT_DIGITS: [&str; 10] = ["⁰", "¹", "²", "³", "⁴", "⁵", "⁶", "⁷", "⁸", "⁹"];

pub fn to_super_script_digits(n: usize) -> String {
    n.to_string()
        .chars()
        .map(|c| SUPERSCRIPT_DIGITS[c.to_digit(10).expect("a base 10 digit") as usize])
        .collect()
}

pub fn roots_of_unity(n: usize) -> Vec<Scalar> {
    let mut roots = Vec::with_capacity(n);
    let omega = get_omega(n);
    let mut current = Scalar::ONE;
    for _ in 0..n {
        roots.push(current);
        current *= omega;
    }
    roots
}

pub fn get_omega(n: usize) -> Scalar {
    impl_modulus!(
        BLS12381ScalarModulus,
        U256,
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
    );
    type FieldElement = Residue<BLS12381ScalarModulus, { BLS12381ScalarModulus::LIMBS }>;

    const ORDER: U256 =
        U256::from_be_hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    const ORDER_M1: U256 = ORDER.wrapping_sub(&U256::ONE);
    const PRIMITIVE_ROOT: FieldElement = FieldElement::new(&U256::from_u64(7));

    let (n, _) = NonZero::<U256>::const_new(U256::from_u64(n as u64));

    let (exponent, rem) = ORDER_M1.div_rem(&n);

    if rem.is_zero().into() {
        panic!("n must divide (r - 1)");
    }

    let omega = PRIMITIVE_ROOT.pow(&exponent).retrieve();

    Scalar::from_uint_unchecked(omega.resize())
}
