use crate::{
    ClientRegisterPayload, DensePolyPrimeField, EncryptionKeys, KZG10CommonReferenceParams,
    KeyShareProofError, KeyShareProofResult, Universal,
};
use blsful::inner_types::*;
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
        crs: &KZG10CommonReferenceParams,
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
            let challenge = crs.omega.pow_vartime([share.id as u64]);
            let sc = polynomial.evaluate(&challenge);
            share.share = sc;
            share.threshold = threshold as u16;
        }

        Ok((shares, polynomial))
    }

    /// Reconstruct the signing key from the shares
    pub fn from_shares(
        shares: &[SigningKeyShare],
        crs: &KZG10CommonReferenceParams,
    ) -> KeyShareProofResult<Self> {
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
            .map(|&s| crs.omega.pow_vartime([s.id as u64]))
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
        crs: &KZG10CommonReferenceParams,
        mut rng: impl RngCore + CryptoRng,
        hot_wallet_encryption_keys: W,
    ) -> KeyShareProofResult<Vec<ClientRegisterPayload>> {
        let encryption_keys = hot_wallet_encryption_keys.as_ref();
        let (shares, _) = self.create_shares(threshold, encryption_keys.len(), &crs, &mut rng)?;
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
            .map(|i| crs.omega.pow_vartime([*i as u64]))
            .collect::<Vec<_>>();
        let interpolated_poly = Self::interpolate_poly(&challenges.as_slice(), &encrypted_shares);
        // Interpolated polynomial degree should be low enough for kzg
        assert!(interpolated_poly.degree() + 1 <= crs.powers_of_g.len());
        let commitment = crs.commit_g1(&interpolated_poly);

        let opening_proofs = crs.batch_open(&interpolated_poly, share_ids.len());

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

/// The payload for the share refresh when refreshing encrypted shares
#[derive(Debug, Copy, Clone, Deserialize, Serialize, Default)]
pub struct ClientRefreshPayload {
    /// The share index
    pub share_id: usize,
    /// The party's share of zero
    pub share: Scalar,
    /// The opening proof
    pub proof: G1Projective,
}
/// Generate shares of zero to refresh hot key shares
/// Returns refresh payload for each client, plus commitment to refresh polynomial
pub fn generate_refresh_payloads(
    threshold: usize,
    num_shares: usize,
    crs: &KZG10CommonReferenceParams,
    mut rng: impl RngCore + CryptoRng,
) -> KeyShareProofResult<(Vec<ClientRefreshPayload>, G1Projective)> {
    let zero = SigningKey(Scalar::ZERO);
    let (ref_shares, zero_poly) = zero.create_shares(threshold, num_shares, &crs, &mut rng)?;
    let commitment = crs.commit_g1(&zero_poly);
    let opening_proofs = crs.batch_open(&zero_poly, ref_shares.len());

    let mut refresh_payloads = vec![ClientRefreshPayload::default(); ref_shares.len()];
    for (i, payload) in refresh_payloads.iter_mut().enumerate() {
        payload.share_id = ref_shares[i].id;
        payload.share = ref_shares[i].share;
        payload.proof = opening_proofs[i];
        // payload.verification_share = G2Projective::GENERATOR * shares[i].share;
    }

    Ok((refresh_payloads, commitment))
}
/// Generate shares of zero to refresh hot key shares with additional components
/// to independently verify correctness
/// Additionally returns commitment, dcom, and opening at zero
pub fn generate_refresh_payloads_untrusted(
    threshold: usize,
    num_shares: usize,
    crs: &KZG10CommonReferenceParams,
    mut rng: impl RngCore + CryptoRng,
) -> KeyShareProofResult<(
    Vec<ClientRefreshPayload>,
    (G1Projective, G1Projective, G1Projective),
)> {
    let zero = SigningKey(Scalar::ZERO);
    let (ref_shares, zero_poly) = zero.create_shares(threshold, num_shares, &crs, &mut rng)?;
    let commitment = crs.commit_g1(&zero_poly);
    let opening_proofs = crs.batch_open(&zero_poly, ref_shares.len());
    // open at zero
    let zero_opening = crs.open(&zero_poly, Scalar::ZERO);
    // degree commitment to ensure zero_poly has correct degree
    let d = crs.powers_of_g.len() - 1;
    let mut degree_shift = vec![Scalar::ZERO; d - threshold + 2];
    degree_shift[d - threshold + 1] = Scalar::ONE;
    let degree_poly = &zero_poly * DensePolyPrimeField(degree_shift);
    let dcom = crs.commit_g1(&degree_poly);

    let mut refresh_payloads = vec![ClientRefreshPayload::default(); ref_shares.len()];
    for (i, payload) in refresh_payloads.iter_mut().enumerate() {
        payload.share_id = ref_shares[i].id;
        payload.share = ref_shares[i].share;
        payload.proof = opening_proofs[i];
        // payload.verification_share = G2Projective::GENERATOR * shares[i].share;
    }

    Ok((refresh_payloads, (commitment, dcom, zero_opening)))
}

/// Verify the public/global refresh information in the case of an untrusted refresh.
/// Checks the opening at zero and the degree of the refresh commitment
pub fn verify_update_global(
    crs: &KZG10CommonReferenceParams,
    threshold: usize,
    refresh_commitment: &G1Projective,
    dcom: G1Projective,
    zero_opening: G1Projective,
) -> KeyShareProofResult<()> {
    let challenge = Scalar::ZERO;
    let d = crs.powers_of_g.len() - 1;
    // check opening at zero
    if crs.verify(&refresh_commitment, challenge, Scalar::ZERO, &zero_opening).is_ok()
        // check dcom
        & bool::from(multi_miller_loop(&[
            (
                &dcom.to_affine(),
                &G2Prepared::from(-G2Projective::GENERATOR.to_affine()),
            ),
            (
                &refresh_commitment.to_affine(),
                &G2Prepared::from(crs.powers_of_h[d - threshold + 1].to_affine()),
            ),
        ])
        .final_exponentiation()
        .is_identity()
    ) {
        Ok(())
    } else {
        Err(KeyShareProofError::InvalidRefresh)
    }
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
        let crs =
            KZG10CommonReferenceParams::setup(NonZeroUsize::new(num_shares - 1).unwrap(), &mut rng);

        let shares = sk
            .create_shares(threshold, num_shares, &crs, &mut rng)
            .unwrap();
        let reconstructed = SigningKey::from_shares(&shares.0, &crs).unwrap();
        assert_eq!(sk, reconstructed);

        let dks_set = (0..num_shares)
            .map(|_| DecryptionKeys::random(&mut rng))
            .collect::<Vec<_>>();
        let eks_set = dks_set
            .iter()
            .map(|dk| EncryptionKeys::from(dk))
            .collect::<Vec<_>>();

        let payloads_res = sk.generate_register_payloads(threshold, &crs, &mut rng, &eks_set);
        assert!(payloads_res.is_ok());

        let payloads = payloads_res.unwrap();
        for payload in payloads.iter() {
            let eval_point = crs.omega.pow_vartime([payload.share_id as u64]);
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
    fn test_refresh() {
        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let threshold = 3;
        let num_parties = 5;
        let crs = KZG10CommonReferenceParams::setup(
            NonZeroUsize::new(num_parties - 1).unwrap(),
            &mut rng,
        );

        let sk = SigningKey(Scalar::random(&mut rng));
        let dks_set = (0..num_parties)
            .map(|_| DecryptionKeys::random(&mut rng))
            .collect::<Vec<_>>();
        let eks_set = dks_set
            .iter()
            .map(|dk| EncryptionKeys::from(dk))
            .collect::<Vec<_>>();
        let payloads_res = sk.generate_register_payloads(threshold, &crs, &mut rng, &eks_set);
        let payloads = payloads_res.unwrap();

        // get refresh information
        let refresh_payloads_res = generate_refresh_payloads(threshold, num_parties, &crs, rng);
        assert!(refresh_payloads_res.is_ok());
        let (refresh_payloads, refresh_commitment) = refresh_payloads_res.unwrap();

        // refresh the shares
        for (payload, refresh_payload) in payloads.iter().zip(refresh_payloads.iter()) {
            assert!(payload
                .refresh(&refresh_commitment, refresh_payload)
                .is_ok());
        }
    }

    #[test]
    fn test_refresh_untrusted() {
        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let threshold = 2;
        let num_parties = 3;
        let crs = KZG10CommonReferenceParams::setup_extended(
            NonZeroUsize::new(num_parties - 1).unwrap(),
            &mut rng,
        );

        let sk = SigningKey(Scalar::random(&mut rng));
        let dks_set = (0..num_parties)
            .map(|_| DecryptionKeys::random(&mut rng))
            .collect::<Vec<_>>();
        let eks_set = dks_set
            .iter()
            .map(|dk| EncryptionKeys::from(dk))
            .collect::<Vec<_>>();
        let payloads_res = sk.generate_register_payloads(threshold, &crs, &mut rng, &eks_set);
        let payloads = payloads_res.unwrap();

        // get refresh information
        let refresh_payloads_res =
            generate_refresh_payloads_untrusted(threshold, num_parties, &crs, rng);
        assert!(refresh_payloads_res.is_ok());
        let (refresh_payloads, (refresh_commitment, dcom, zero_opening)) =
            refresh_payloads_res.unwrap();

        assert!(
            verify_update_global(&crs, threshold, &refresh_commitment, dcom, zero_opening).is_ok()
        );

        // refresh the shares
        for (payload, refresh_payload) in payloads.iter().zip(refresh_payloads.iter()) {
            assert!(payload
                .refresh_untrusted(&refresh_commitment, refresh_payload, &crs)
                .is_ok());
        }
    }
}
