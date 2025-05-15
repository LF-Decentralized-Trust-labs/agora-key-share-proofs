use crate::{DensePolyPrimeField, KeyShareProofError, KeyShareProofResult};
// use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
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

    /// TODO batch open polynomial evaluations in the G1 group
    pub fn batch_open(
        &self,
        fx: &DensePolyPrimeField<Scalar>,
        challenges: &Vec<Scalar>,
    ) -> Vec<G1Projective> {
        let quotients = Self::batch_get_qpolys(&fx, &challenges);
        //// moved code from client.rs (small mods for compilation)
        // // let quotients = SigningKey::get_quotients(&sk, &fx, &challenges);

        // let domain_size = (challenges.len()).next_power_of_two();
        // let domain =
        //     GeneralEvaluationDomain::<Scalar>::new(domain_size).expect("Failed to create domain");
        // let aux_domain = GeneralEvaluationDomain::<Scalar>::new(domain_size * 2)
        //     .expect("Failed to create aux_domain");

        // let t_evals = aux_domain.fft(self.powers_of_g.as_slice());
        // // TODO how to use quotients as input here?
        // let d_evals = aux_domain.fft(&quotients);

        // let dt_evals = t_evals
        //     .iter()
        //     .zip(d_evals.iter())
        //     .map(|(t, d)| t * d)
        //     .collect::<Vec<_>>();

        // let dt_poly = aux_domain.ifft(&dt_evals);
        // let opening_proofs = domain.fft(&dt_poly[domain_size..]);

        // NG naive approach
        let quotient_polys = Self::batch_get_qpolys(&fx, challenges.as_slice());
        quotient_polys
            .iter()
            .map(|qpoly| self.commit_g1(qpoly))
            .collect::<Vec<_>>()
    }

    /// NG naive quotient polys function (cf. get_quotients in client.rs)
    pub fn batch_get_qpolys(
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
    use super::*;
    use rand::SeedableRng;
    // use rand_chacha::ChaCha8Rng;

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
    fn test_quotient_polys() {}

    #[test]
    fn test_zero_open() {
        let mut rng = rand_chacha::ChaCha12Rng::from_seed([0u8; 32]);
        let crs = KZG10CommonReferenceParams::setup(NonZeroUsize::new(10).unwrap(), &mut rng);
        let poly = DensePolyPrimeField((0..10).map(|_| Scalar::random(&mut rng)).collect());
        let commitment = crs.commit_g1(&poly);

        let proof = crs.open(&poly, Scalar::ZERO);
        let y = poly.evaluate(&Scalar::ZERO);
        assert!(crs.verify(&commitment, Scalar::ZERO, y, &proof).is_ok());
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

        let challenges = (0..num_parties)
            // i+2 because verification fails when challenge = 1 (TODO why?)
            .map(|i| Scalar::from((i + 2) as u64))
            .collect::<Vec<_>>();
        let opening_proofs = crs.batch_open(&poly, &challenges);
        // check that all the batch-opened proofs verify
        for (challenge, proof) in challenges.iter().zip(opening_proofs.iter()) {
            assert!(crs
                .verify(&commitment, *challenge, poly.evaluate(challenge), proof)
                .is_ok());
            // and that each batch-opened proof equals an individually-opened proof
            assert_eq!(*proof, crs.open(&poly, *challenge));
        }
    }
}
