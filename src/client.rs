use crate::{
    ClientRegisterPayload, DensePolyPrimeField, EncryptionKeys, KZG10CommonReferenceParams,
    KeyShareProofError, KeyShareProofResult, Universal,
};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use blsful::inner_types::{Field, G2Projective, Scalar};
use itertools::*;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::DefaultIsZeroes;

/// The verification key for the client
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct VerificationKey(pub G2Projective);

impl From<&SigningKey> for VerificationKey {
    fn from(s: &SigningKey) -> Self {
        VerificationKey(G2Projective::GENERATOR * s.0)
    }
}

/// The signing key for the client that they want to protect
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct SigningKey(pub Scalar);

impl DefaultIsZeroes for SigningKey {}

impl SigningKey {
    /// Create secret shares
    pub fn create_shares(
        &self,
        threshold: usize,
        num_shares: usize,
        mut rng: impl RngCore + CryptoRng,
    ) -> KeyShareProofResult<(Vec<SigningKeyShare>, DensePolyPrimeField<Scalar>)> {
        if threshold > num_shares {
            return Err(KeyShareProofError::General(
                "Threshold cannot be greater than the number of shares".to_string(),
            ));
        }
        if threshold < 2 {
            return Err(KeyShareProofError::General(
                "Threshold must be at least 2".to_string(),
            ));
        }
        let mut shares = vec![SigningKeyShare::default(); num_shares];
        let mut polynomial = DensePolyPrimeField::random(threshold - 1, &mut rng);
        polynomial.0[0] = self.0;
        for (i, share) in shares.iter_mut().enumerate() {
            let sc = polynomial.evaluate(&Scalar::from((i + 1) as u64));
            share.id = Scalar::from((i + 1) as u64);
            share.share = sc;
            share.threshold = threshold as u16;
        }

        Ok((shares, polynomial))
    }

    /// Reconstruct the signing key from the shares
    pub fn from_shares(shares: &[SigningKeyShare]) -> KeyShareProofResult<Self> {
        if shares.len() < 2 {
            return Err(KeyShareProofError::General(
                "At least 2 shares are required".to_string(),
            ));
        }
        if shares.len() < shares[0].threshold as usize {
            return Err(KeyShareProofError::General(
                "Not enough shares to reconstruct the key".to_string(),
            ));
        }
        if !shares.iter().map(|s| s.id).all_unique() {
            return Err(KeyShareProofError::General(
                "Shares must have unique indices".to_string(),
            ));
        }
        if shares.iter().any(|s| s.id.is_zero().unwrap_u8() == 1) {
            return Err(KeyShareProofError::General(
                "Shares must have indices greater than 0".to_string(),
            ));
        }
        let shares = shares.iter().map(|s| (s.id, s.share)).collect_vec();
        let identifiers = shares.iter().map(|&s| s.0).collect_vec();
        let key = shares
            .iter()
            .map(|&(i, s)| lagrange(i, identifiers.as_slice()) * s)
            .sum();

        Ok(Self(key))
    }

    /// Generate encrypted shares for hot storage wallets
    pub fn generate_register_payloads<W: AsRef<[EncryptionKeys]>>(
        &self,
        threshold: usize,
        crs: &KZG10CommonReferenceParams,
        mut rng: impl RngCore + CryptoRng,
        hot_wallet_encryption_keys: W,
    ) -> KeyShareProofResult<Vec<ClientRegisterPayload>> {
        let encryption_keys = hot_wallet_encryption_keys.as_ref();
        let (shares, poly) = self.create_shares(threshold, encryption_keys.len(), &mut rng)?;
        let mut register_payloads = vec![ClientRegisterPayload::default(); shares.len()];

        let encrypted_shares = shares
            .iter()
            .zip(encryption_keys)
            .map(|(share, encryption_key)| {
                share.share
                    + Universal::hash_g2(&[
                        encryption_key.0[0].0 * self.0,
                        encryption_key.0[1].0 * self.0,
                    ])
            })
            .collect::<Vec<_>>();

        let quotients = self.get_quotients(&poly, &encrypted_shares);

        let domain_size = (encryption_keys.len()).next_power_of_two();
        let domain =
            GeneralEvaluationDomain::<Scalar>::new(domain_size).expect("Failed to create domain");
        let aux_domain = GeneralEvaluationDomain::<Scalar>::new(domain_size * 2)
            .expect("Failed to create aux_domain");

        let t_evals = aux_domain.fft(&crs.powers_of_g);
        let d_evals = aux_domain.fft(&quotients.0);

        let dt_evals = t_evals
            .iter()
            .zip(d_evals.iter())
            .map(|(t, d)| t * d)
            .collect::<Vec<_>>();

        let dt_poly = aux_domain.ifft(&dt_evals);
        let opening_proofs = domain.fft(&dt_poly[domain_size..]);

        for (i, payload) in register_payloads.iter_mut().enumerate() {
            payload.encrypted_share = encrypted_shares[i];
            payload.verification_share = G2Projective::GENERATOR * shares[i].share;
            payload.proof = opening_proofs[i];
            payload.commitment = crs.commit_g1(&DensePolyPrimeField(vec![
                -encrypted_shares[i],
                Scalar::ONE,
            ]));
        }

        Ok(register_payloads)
    }

    fn get_quotients(
        &self,
        fx: &DensePolyPrimeField<Scalar>,
        challenges: &[Scalar],
    ) -> DensePolyPrimeField<Scalar> {
        let mut zero_poly = DensePolyPrimeField(vec![-challenges[0], Scalar::ONE]);
        for i in 1..challenges.len() {
            zero_poly *= DensePolyPrimeField(vec![-challenges[i], Scalar::ONE]);
        }
        let mut values = vec![Scalar::ZERO; challenges.len()];
        for (value, challenge) in values.iter_mut().zip(challenges) {
            *value = fx.evaluate(challenge);
        }
        let mut lagrange_poly = Self::interpolate_poly(challenges, &values);
        lagrange_poly.0.resize(fx.0.len(), Scalar::ZERO); //pad with zeros

        let mut numerator = DensePolyPrimeField(vec![Scalar::ZERO; challenges.len()]);
        for (num, (c1, c2)) in numerator
            .0
            .iter_mut()
            .zip(fx.0.iter().zip(lagrange_poly.0.iter()))
        {
            *num = *c1 - *c2;
        }

        numerator.poly_mod(&zero_poly).0
    }

    fn interpolate_poly(challenges: &[Scalar], values: &[Scalar]) -> DensePolyPrimeField<Scalar> {
        debug_assert_eq!(challenges.len(), values.len());

        let mut result = DensePolyPrimeField(vec![Scalar::ZERO; challenges.len()]);

        for i in 0..challenges.len() {
            let mut num = DensePolyPrimeField::one();
            let mut den = Scalar::ONE;

            for j in 0..challenges.len() {
                if i == j {
                    continue;
                }
                debug_assert_ne!(challenges[i], challenges[j]);
                num *= DensePolyPrimeField(vec![-challenges[j], Scalar::ONE]);
                den *= challenges[i] - challenges[j];
            }
            let den_inv = den.invert().expect("denominator to not be zero");
            let term = DensePolyPrimeField(
                num.0
                    .iter()
                    .map(|x| x * values[i] * den_inv)
                    .collect::<Vec<_>>(),
            );
            result += term;
        }
        result
    }
}

/// A share of the signing key
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct SigningKeyShare {
    pub(crate) id: Scalar,
    pub(crate) share: Scalar,
    pub(crate) threshold: u16,
}

fn lagrange(id: Scalar, others: &[Scalar]) -> Scalar {
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for &j in others {
        if id == j {
            continue;
        }
        num *= j;
        den *= j - id;
    }
    num * den.invert().expect("denominator is zero")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DecryptionKeys;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use std::num::NonZeroUsize;

    #[test]
    fn test_register_proofs() {
        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let sk = SigningKey(Scalar::random(&mut rng));
        let threshold = 2;
        let num_shares = 3;
        let shares = sk.create_shares(threshold, num_shares, &mut rng).unwrap();
        let reconstructed = SigningKey::from_shares(&shares.0).unwrap();
        assert_eq!(sk, reconstructed);

        let crs = KZG10CommonReferenceParams::setup(NonZeroUsize::new(4).unwrap(), &mut rng);

        let dks_set = (0..3)
            .map(|_| DecryptionKeys::random(&mut rng))
            .collect::<Vec<_>>();
        let eks_set = dks_set
            .iter()
            .map(|dk| EncryptionKeys::from(dk))
            .collect::<Vec<_>>();

        let payloads_res = sk.generate_register_payloads(threshold, &crs, &mut rng, &eks_set);
        assert!(payloads_res.is_ok());
    }

    #[test]
    fn test_proofs_of_remembrance() {
        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let sk = SigningKey(Scalar::random(&mut rng));
        let threshold = 2;
        let num_shares = 3;
        let shares = sk.create_shares(threshold, num_shares, &mut rng).unwrap();
        let reconstructed = SigningKey::from_shares(&shares.0).unwrap();
        assert_eq!(sk, reconstructed);

        let crs = KZG10CommonReferenceParams::setup(NonZeroUsize::new(4).unwrap(), &mut rng);

        let dks_set = (0..3)
            .map(|_| DecryptionKeys::random(&mut rng))
            .collect::<Vec<_>>();
        let eks_set = dks_set
            .iter()
            .map(|dk| EncryptionKeys::from(dk))
            .collect::<Vec<_>>();

        let payloads_res = sk.generate_register_payloads(threshold, &crs, &mut rng, &eks_set);
        assert!(payloads_res.is_ok());

        let payloads = payloads_res.unwrap();

        for (payload, eks) in payloads.iter().zip(eks_set.iter()) {
            let hot_proof = eks.prove(&crs, payload.encrypted_share, payload.commitment, 0);
            let _ = hot_proof.verify(&crs, 0);
        }
    }
}
