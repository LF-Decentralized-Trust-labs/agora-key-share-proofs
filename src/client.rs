use crate::{
    ClientRegisterPayload, DensePolyPrimeField, EncryptionKeys, KZG10CommonReferenceParams,
    KeyShareProofError, KeyShareProofResult, Universal,
};
// use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use blsful::inner_types::{Field, G2Projective, Scalar};
// use blstrs_plus::G1Projective;
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
        omega: Scalar,
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
            share.id = i + 1;
            let challenge = omega.pow_vartime([share.id as u64]);
            let sc = polynomial.evaluate(&challenge);
            share.share = sc;
            share.threshold = threshold as u16;
        }

        Ok((shares, polynomial))
    }

    /// Reconstruct the signing key from the shares
    pub fn from_shares(shares: &[SigningKeyShare], omega: Scalar) -> KeyShareProofResult<Self> {
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
        if shares.iter().any(|s| s.id == 0) {
            return Err(KeyShareProofError::General(
                "Shares must have indices greater than 0".to_string(),
            ));
        }
        let challenges = shares
            .iter()
            .map(|&s| omega.pow_vartime([s.id as u64]))
            .collect_vec();
        let key = challenges
            .iter()
            .zip(shares.iter())
            .map(|(x, s)| lagrange(*x, challenges.as_slice()) * s.share)
            .sum();

        Ok(Self(key))
    }

    /// Generate encrypted shares for hot storage wallets
    pub fn generate_register_payloads<W: AsRef<[EncryptionKeys]>>(
        &self,
        threshold: usize,
        omega: Scalar,
        crs: &KZG10CommonReferenceParams,
        mut rng: impl RngCore + CryptoRng,
        hot_wallet_encryption_keys: W,
    ) -> KeyShareProofResult<Vec<ClientRegisterPayload>> {
        let encryption_keys = hot_wallet_encryption_keys.as_ref();
        let (shares, _) = self.create_shares(threshold, encryption_keys.len(), omega, &mut rng)?;
        let share_ids = shares.iter().map(|share| share.id).collect::<Vec<_>>();
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

        let challenges = share_ids
            .iter()
            .map(|i| omega.pow_vartime([*i as u64]))
            .collect::<Vec<_>>();
        let interpolated_poly = Self::interpolate_poly(&challenges.as_slice(), &encrypted_shares);
        // Interpolated polynomial degree should be low enough for kzg
        assert!(interpolated_poly.degree() + 1 <= crs.powers_of_g.len());
        let commitment = crs.commit_g1(&interpolated_poly);

        let mut opening_proofs = crs.batch_open(&interpolated_poly, share_ids.len());

        for (i, payload) in register_payloads.iter_mut().enumerate() {
            payload.share_id = share_ids[i];
            payload.encrypted_share = encrypted_shares[i];
            payload.verification_share = G2Projective::GENERATOR * shares[i].share;
            payload.proof = opening_proofs[i];
            payload.commitment = commitment;
        }

        Ok(register_payloads)
    }

    /// Interpolate a polynomial given some evaluations
    pub fn interpolate_poly(
        challenges: &[Scalar],
        values: &[Scalar],
    ) -> DensePolyPrimeField<Scalar> {
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
        // interpolated polynomial's degree should be <= n-1 (for n input points)
        debug_assert!(result.degree() <= challenges.len() - 1);

        result
    }
}

/// A share of the signing key
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct SigningKeyShare {
    pub(crate) id: usize,
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
    use crate::{utils::get_omega, DecryptionKeys};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use std::num::NonZeroUsize;

    #[test]
    fn test_register_proofs() {
        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let sk = SigningKey(Scalar::random(&mut rng));
        let threshold = 2;
        let num_shares = 3;
        let root_degree: usize = num_shares + 1;
        let omega = get_omega(root_degree.next_power_of_two());
        let shares = sk
            .create_shares(threshold, num_shares, omega, &mut rng)
            .unwrap();
        let reconstructed = SigningKey::from_shares(&shares.0, omega).unwrap();
        assert_eq!(sk, reconstructed);

        let crs =
            KZG10CommonReferenceParams::setup(NonZeroUsize::new(num_shares - 1).unwrap(), &mut rng);

        let dks_set = (0..num_shares)
            .map(|_| DecryptionKeys::random(&mut rng))
            .collect::<Vec<_>>();
        let eks_set = dks_set
            .iter()
            .map(|dk| EncryptionKeys::from(dk))
            .collect::<Vec<_>>();

        let payloads_res =
            sk.generate_register_payloads(threshold, omega, &crs, &mut rng, &eks_set);
        assert!(payloads_res.is_ok());

        let payloads = payloads_res.unwrap();
        for payload in payloads.iter() {
            let eval_point = omega.pow_vartime([payload.share_id as u64]);
            assert!(crs
                .verify(
                    &payload.commitment,
                    eval_point,
                    payload.encrypted_share,
                    &payload.proof
                )
                .is_ok());
        }
    }

    #[test]
    fn test_proofs_of_remembrance() {
        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let sk = SigningKey(Scalar::random(&mut rng));
        let threshold = 2;
        let num_shares = 3;
        let crs =
            KZG10CommonReferenceParams::setup(NonZeroUsize::new(num_shares - 1).unwrap(), &mut rng);
        let omega = get_omega((num_shares + 1).next_power_of_two());

        let dks_set = (0..3)
            .map(|_| DecryptionKeys::random(&mut rng))
            .collect::<Vec<_>>();
        let eks_set = dks_set
            .iter()
            .map(|dk| EncryptionKeys::from(dk))
            .collect::<Vec<_>>();

        let payloads_res =
            sk.generate_register_payloads(threshold, omega, &crs, &mut rng, &eks_set);
        let payloads = payloads_res.unwrap();

        for (payload, eks) in payloads.iter().zip(eks_set.iter()) {
            let hot_proof = eks.prove(
                &crs,
                omega.pow_vartime([payload.share_id as u64]),
                payload.encrypted_share,
                payload.proof,
                0,
            );
            assert!(hot_proof
                .verify(
                    &crs,
                    &payload.commitment,
                    omega.pow_vartime([payload.share_id as u64]),
                    0
                )
                .is_ok());
        }
    }
}
