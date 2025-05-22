use crate::{utils::get_omega, DensePolyPrimeField, KeyShareProofError, KeyShareProofResult};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use blsful::inner_types::PrimeCurveAffine;
use blsful::inner_types::*;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Common Reference String for a Universal Setup
pub struct KZG10CommonReferenceParams {
    /// The powers of tau in the G1 group
    pub powers_of_g: Vec<G1Projective>,
    /// The powers of tau in the G2 group
    pub powers_of_h: [G2Projective; 2],
}

impl KZG10CommonReferenceParams {
    /// Generate a common reference string for the KZG10 scheme
    pub fn setup(max_degree: NonZeroUsize, rng: impl RngCore + CryptoRng) -> Self {
        let max_degree = max_degree.get();
        let tau = Scalar::random(rng);

        let mut powers_of_g = Vec::with_capacity(max_degree + 1);

        let mut powers_of_tau = Vec::with_capacity(max_degree + 1);
        powers_of_tau.push(Scalar::ONE);
        powers_of_tau.push(tau);

        powers_of_g.push(G1Projective::GENERATOR);
        powers_of_g.push(G1Projective::GENERATOR * tau);

        let powers_of_h = [G2Projective::GENERATOR, G2Projective::GENERATOR * tau];

        for i in 2..max_degree + 1 {
            let power_beta = powers_of_tau[i - 1] * tau;
            powers_of_tau.push(power_beta);
            powers_of_g.push(G1Projective::GENERATOR * power_beta);
        }

        Self {
            powers_of_g,
            powers_of_h,
        }
    }

    /// Commit to a polynomial in the G1 group
    pub fn commit_g1(&self, polynomial: &DensePolyPrimeField<Scalar>) -> G1Projective {
        if polynomial.degree() > self.powers_of_g.len() {
            panic!("Polynomial degree is too high for the CRS");
        }
        // Allow for smaller polynomials
        G1Projective::sum_of_products(
            &self.powers_of_g[..polynomial.degree() + 1],
            &polynomial.0[..polynomial.degree() + 1],
        )
    }

    /// Open a polynomial evaluation in the G1 group
    pub fn open(&self, fx: &DensePolyPrimeField<Scalar>, challenge: Scalar) -> G1Projective {
        // f(i)
        let eval = fx.evaluate(&challenge);
        // -f(i)
        let eval_poly = DensePolyPrimeField(vec![eval]);
        // f(x) - f(i)
        let num = fx - &eval_poly;
        // x - i
        let den = DensePolyPrimeField(vec![-challenge, Scalar::ONE]);
        // (f(x) - f(i)) / (x - i)
        let (quo, _) = num.poly_mod(&den);
        // π = Com(crs, q_i(x))
        self.commit_g1(&quo)
    }

    /// Get all commitments to the H_i(X) polynomials in Feist-Khovratovich
    /// code based on https://github.com/alinush/libpolycrypto/blob/fk/libpolycrypto/src/KatePublicParameters.cpp#L199
    pub fn get_fk_hcoms(&self, fx: &DensePolyPrimeField<Scalar>) -> Vec<G1Projective> {
        let m = fx.degree();
        let big_m = m.next_power_of_two();

        // vector for circulant matrix embedding of the Topelitz matrix of fx coefficients
        // c = [ fm   vec![0;m-1]   fm   f1   f2   ...   fm-1 ]
        // if m is not a power of two then we pad to the next power of two M and
        // c = [ vec![0;M]   f1   f2   ...   fm   vec![0;M-m] ]
        let mut c_vec = vec![Scalar::ZERO; 2 * big_m];
        if m == big_m {
            c_vec[0] = fx.0[m];
            c_vec[m] = fx.0[m];
        }
        for i in 1..=m - 1 {
            c_vec[big_m + i] = fx.0[i];
        }
        if m != big_m {
            c_vec[big_m + m] = fx.0[m];
        }

        // vector of the powers of tau
        // t = [ vec![0;M-m]   t^{m-1}G   t^{m-2}G   ...   tG   G   vec![0;M] ]
        let mut t_vec = vec![G1Projective::IDENTITY; 2 * big_m];
        for i in 0..m {
            t_vec[big_m - 1 - i] = self.powers_of_g[i];
        }

        let domain =
            GeneralEvaluationDomain::<Scalar>::new(big_m * 2).expect("Failed to create domain");
        let c_evals = domain.fft(&c_vec.as_slice());
        // sanity check:
        // FFT(c(X)) is the evaluations at powers of omega: c(w^i) for each i
        let c_poly = DensePolyPrimeField(c_vec);
        let omega = get_omega(big_m * 2);
        assert_eq!(domain.group_gen(), omega);
        assert_eq!(omega.pow([(big_m * 2) as u64]), Scalar::ONE);
        for i in 0..big_m * 2 {
            assert_eq!(c_evals[i], c_poly.evaluate(&omega.pow_vartime([i as u64])));
        }

        let t_evals = domain.fft(&t_vec.as_slice());
        // sanity check:
        // FFT(t) is evaluation in the exponent at powers of omega
        // (additive notation: \sum_j (w^i)^j t^{m-1-j} G )
        for i in 0..big_m * 2 {
            let mut sum = G1Projective::IDENTITY;
            let eval_point = &omega.pow_vartime([i as u64]);
            for j in 0..t_vec.len() {
                sum += t_vec[j] * eval_point.pow_vartime([j as u64]);
            }
            // passes
            assert_eq!(t_evals[i], sum);
        }

        let ct_evals = t_evals
            .iter()
            .zip(c_evals.iter())
            .map(|(t, c)| t * c)
            .collect::<Vec<_>>();

        let h_commitments = domain.ifft(&ct_evals);
        h_commitments[..m].to_vec()
    }

    /// Batch open polynomial evaluations in the G1 group using Feist-Khovratovich
    pub fn batch_open(&self, fx: &DensePolyPrimeField<Scalar>, n: usize) -> Vec<G1Projective> {
        let domain_size = n.next_power_of_two();
        let m = fx.degree();
        let mut h_coms = self.get_fk_hcoms(fx);
        h_coms.resize(domain_size, G1Projective::IDENTITY);

        let mut h_polys = Vec::with_capacity(m);
        let mut h_evals = Vec::with_capacity(m);
        for i in 1..=m {
            // H_1 should equal f1 + f2 X +       ...        + fm X^{m-1}
            // H_2            = f2 + f3 X + ... + fm X^{m-2}
            // ...             ...
            // H_m            = fm
            let h_i = DensePolyPrimeField(fx.0[i..].to_vec());
            assert_eq!(h_i.degree(), m - i);
            let mut sum = G1Projective::IDENTITY;
            for j in 0..=m - i {
                sum += self.powers_of_g[j] * h_i.0[j];
            }
            h_polys.push(h_i);
            h_evals.push(sum);
        }

        let domain =
            GeneralEvaluationDomain::<Scalar>::new(domain_size).expect("Failed to create domain");
        let proofs = domain.fft(&h_coms);
        // sanity check 1
        let omega = get_omega(domain_size);
        assert_eq!(domain.group_gen(), omega);
        // sanity check 2
        // FFT(h_coms) is evaluation in the exponent at powers of omega
        // (additive notation: \sum_j (w^i)^j h_{j+1} )
        // for i in 0..domain_size {
        //     let mut sum = G1Projective::IDENTITY;
        //     let eval_point = &omega.pow_vartime([i as u64]);
        //     for j in 0..h_coms.len() - 1 {
        //         sum += h_coms[j + 1] * eval_point.pow_vartime([j as u64]);
        //     }
        //     dbg!(i);
        //     // TODO fails
        //     // assert_eq!(proofs[i], sum);
        // }
        proofs
    }

    /// Get quotient polynomials
    pub fn batch_get_quotients(
        fx: &DensePolyPrimeField<Scalar>,
        challenges: &[Scalar],
    ) -> Vec<DensePolyPrimeField<Scalar>> {
        let mut quotient_polys = Vec::with_capacity(challenges.len());

        for challenge in challenges.iter() {
            let num = fx - DensePolyPrimeField(vec![fx.evaluate(challenge)]);
            let den = DensePolyPrimeField(vec![-challenge, Scalar::ONE]);
            let (quo, _) = num.poly_mod(&den);
            quotient_polys.push(quo);
        }
        quotient_polys
    }

    /// Confirm y = f(i)
    pub fn verify(
        &self,
        commitment: &G1Projective,
        i: Scalar,
        y: Scalar,
        proof: &G1Projective,
    ) -> KeyShareProofResult<()> {
        // g1^Y
        let comm = G1Projective::GENERATOR * y;
        // com_f / g1^Y
        let lhs = commitment - comm;

        // g2^𝜏 / g2^i
        let rhs = self.powers_of_h[1] - G2Projective::GENERATOR * i;

        // e(com_f / g1^Y, -g2) . e(π, g2^𝜏 / g2^i) == 1
        let res = multi_miller_loop(&[
            (&lhs.to_affine(), &G2Prepared::from(-G2Affine::generator())),
            (&proof.to_affine(), &G2Prepared::from(rhs.to_affine())),
        ])
        .final_exponentiation()
        .is_identity();

        if bool::from(res) {
            Ok(())
        } else {
            Err(KeyShareProofError::General("invalid proof".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::roots_of_unity;

    use super::*;
    use rand::SeedableRng;

    #[test]
    fn test_kzg10() {
        let mut rng = rand_chacha::ChaCha12Rng::from_seed([0u8; 32]);
        let crs = KZG10CommonReferenceParams::setup(NonZeroUsize::new(10).unwrap(), &mut rng);
        let poly = DensePolyPrimeField((0..10).map(|_| Scalar::random(&mut rng)).collect());
        let commitment = crs.commit_g1(&poly);
        let i = Scalar::random(&mut rng);
        let proof = crs.open(&poly, i);
        let y = poly.evaluate(&i);
        assert!(crs.verify(&commitment, i, y, &proof).is_ok());
    }

    #[test]
    fn test_fk_hcoms() {
        let mut rng = rand_chacha::ChaCha12Rng::from_seed([0u8; 32]);
        let crs = KZG10CommonReferenceParams::setup(NonZeroUsize::new(10).unwrap(), &mut rng);
        let fx = DensePolyPrimeField((0..10).map(|_| Scalar::random(&mut rng)).collect());
        let m = fx.degree();

        let mut h_coms = crs.get_fk_hcoms(&fx);
        let mut h_polys = Vec::with_capacity(m);
        let mut h_evals = Vec::with_capacity(m);
        for i in 1..=m {
            // H_1 should equal f1 + f2 X +       ...        + fm X^{m-1}
            // H_2            = f2 + f3 X + ... + fm X^{m-2}
            // ...             ...
            // H_m            = fm
            let h_i = DensePolyPrimeField(fx.0[i..].to_vec());
            assert_eq!(h_i.degree(), m - i);
            let mut sum = G1Projective::IDENTITY;
            for j in 0..=m - i {
                sum += crs.powers_of_g[j] * h_i.0[j];
            }
            h_polys.push(h_i);
            h_evals.push(sum);
        }
        for (h_com, h_eval) in h_coms.iter().zip(h_evals.iter()) {
            assert_eq!(*h_com, *h_eval);
        }
        for (h_com, hx) in h_coms.iter().zip(h_polys.iter()) {
            assert_eq!(*h_com, crs.commit_g1(hx));
        }
    }

    #[test]
    fn test_zero_open() {
        let mut rng = rand_chacha::ChaCha12Rng::from_seed([0u8; 32]);
        let crs = KZG10CommonReferenceParams::setup(NonZeroUsize::new(10).unwrap(), &mut rng);
        let poly = DensePolyPrimeField((0..10).map(|_| Scalar::random(&mut rng)).collect());
        let commitment = crs.commit_g1(&poly);

        // challenge is omega^0 (aka 1)
        let challenge = Scalar::ONE;
        let proof = crs.open(&poly, challenge);
        let y = poly.evaluate(&challenge);
        assert!(crs.verify(&commitment, challenge, y, &proof).is_ok());
    }

    #[test]
    fn test_batch_open() {
        let mut rng = rand_chacha::ChaCha12Rng::from_seed([0u8; 32]);
        let num_parties = 10;
        let degree = num_parties - 1;

        let crs = KZG10CommonReferenceParams::setup(NonZeroUsize::new(degree).unwrap(), &mut rng);
        let poly = DensePolyPrimeField((0..degree + 1).map(|_| Scalar::random(&mut rng)).collect());
        assert_eq!(poly.degree(), degree);
        let commitment = crs.commit_g1(&poly);

        // note these start with the zero opening (at omega^0)
        let opening_proofs = crs.batch_open(&poly, num_parties + 1);
        let challenges = roots_of_unity((num_parties + 1).next_power_of_two());
        for (challenge, proof) in challenges.iter().zip(opening_proofs.iter()) {
            // check that all the batch-opened proofs verify
            assert!(crs
                .verify(&commitment, *challenge, poly.evaluate(challenge), proof)
                .is_ok());
            // and that each batch-opened proof equals an individually-opened proof
            assert_eq!(*proof, crs.open(&poly, *challenge));
        }
    }
}
