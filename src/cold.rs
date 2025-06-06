use crate::client::VerificationKey;
use crate::{encrypt::*, SigningKey};
use crate::{
    // DensePolyPrimeField,
    KZG10CommonReferenceParams,
    KeyShareProofError,
    KeyShareProofResult,
    PedersenCommitmentParams,
    Universal,
};
use blsful::inner_types::*;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};
use zeroize::DefaultIsZeroes;

/// The decryption keys for the cold storage wallet
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default)]
pub struct DecryptionKeys(pub [DecryptionKey; 2]);

impl DefaultIsZeroes for DecryptionKeys {}

impl DecryptionKeys {
    /// Generate new random decryption keys
    pub fn random(mut rng: impl RngCore + CryptoRng) -> Self {
        DecryptionKeys([
            DecryptionKey::random(&mut rng),
            DecryptionKey::random(&mut rng),
        ])
    }

    /// Sign the message using the cold keys
    pub fn sign(&self, verification_key: VerificationKey, message: &[u8]) -> ColdSignature {
        let components = [
            verification_key.0 * self.0[0].0,
            verification_key.0 * self.0[1].0,
        ];
        let sk = Universal::hash_g2(&components);
        let pt = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(
            message,
            b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_",
        );
        ColdSignature(pt * sk)
    }

    /// Create a cold storage proof
    pub fn prove(&self, block_id: u64) -> ColdStorageProof {
        let r1 = Scalar::random(&mut rand::rngs::OsRng);
        let r2 = Scalar::random(&mut rand::rngs::OsRng);
        let a1 = G2Projective::GENERATOR * r1;
        let a2 = G2Projective::GENERATOR * r2;
        let mut bytes = [0u8; 192 + 8];
        bytes[..96].copy_from_slice(a1.to_compressed().as_ref());
        bytes[96..192].copy_from_slice(a2.to_compressed().as_ref());
        bytes[192..].copy_from_slice(&block_id.to_be_bytes());
        let c = Scalar::hash::<ExpandMsgXmd<sha2::Sha256>>(&bytes, b"BLS12381_XMD:SHA-256_RO_NUL_");
        let z1 = r1 + c * self.0[0].0;
        let z2 = r2 + c * self.0[1].0;
        ColdStorageProof { a1, a2, z1, z2 }
    }
}

impl From<&DecryptionKeys> for EncryptionKeys {
    fn from(value: &DecryptionKeys) -> Self {
        EncryptionKeys([
            EncryptionKey::from(&value.0[0]),
            EncryptionKey::from(&value.0[1]),
        ])
    }
}

/// The encryption keys for the hot storage wallet
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default)]
pub struct EncryptionKeys(pub [EncryptionKey; 2]);

impl EncryptionKeys {
    /// Encrypted share is of the form x_i + Universal::hash_g2(&[ek_1 ^ x, ek_2 ^ x, ek_3 ^ x])
    pub fn sign(&self, encrypted_share: Scalar, message: &[u8]) -> HotSignature {
        let pt = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(
            message,
            b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_",
        );
        HotSignature(pt * encrypted_share)
    }

    /// Generate a hot storage proof
    pub fn prove(
        &self,
        crs: &KZG10CommonReferenceParams,
        share_eval_pt: Scalar,
        encrypted_share: Scalar,
        current_opening: G1Projective,
        block_id: u64,
    ) -> HotStorageProof {
        let params = PedersenCommitmentParams::default();
        // hot proof correctness relies on KZG and Pedersen generator to be the same
        assert_eq!(params.g, crs.powers_of_g[0]);
        let (comm_ped, r) = params.commit_random(encrypted_share, rand::rngs::OsRng);
        let s1 = Scalar::random(&mut rand::rngs::OsRng);
        let s2 = Scalar::random(&mut rand::rngs::OsRng);
        let a_comm_ped = params.commit(s1, s2);
        let mut bytes = [0u8; 48 + 8];
        bytes[..48].copy_from_slice(a_comm_ped.to_compressed().as_ref());
        bytes[48..].copy_from_slice(&block_id.to_be_bytes());
        let c = Scalar::hash::<ExpandMsgXmd<sha2::Sha256>>(&bytes, b"BLS12381_XMD:SHA-256_RO_NUL_");
        let t1 = s1 + c * encrypted_share;
        let t2 = s2 + c * r;
        let si = Scalar::random(&mut rand::rngs::OsRng);
        let blinded_proof = current_opening + params.h * si;
        let shift_proof = G2Projective::GENERATOR * -r
            + (crs.powers_of_h[1] - (crs.powers_of_h[0] * share_eval_pt)) * -si;
        HotStorageProof {
            comm_ped,
            a_comm_ped,
            t1,
            t2,
            blinded_proof,
            shift_proof,
        }
    }
}

/// The signature for the wallet
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default)]
pub struct Signature(pub G1Projective);

impl Signature {
    /// Reconstruct a signature from a list of signatures without checking
    /// whether the signatures are valid
    pub fn reconstruct_unchecked(signatures: &[(HotSignature, ColdSignature)]) -> Self {
        Signature(
            signatures
                .iter()
                .fold(G1Projective::IDENTITY, |acc, &(hot, cold)| {
                    acc + (hot.0 - cold.0)
                }),
        )
    }

    /// Verify the signature
    pub fn verify(&self, verification_key: VerificationKey, message: &[u8]) -> Choice {
        let pt = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(
            message,
            b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_",
        );
        multi_miller_loop(&[
            (
                &pt.to_affine(),
                &G2Prepared::from(verification_key.0.to_affine()),
            ),
            (
                &self.0.to_affine(),
                &G2Prepared::from(-G2Projective::GENERATOR.to_affine()),
            ),
        ])
        .final_exponentiation()
        .is_identity()
    }
}

/// A cold storage signature
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default)]
pub struct ColdSignature(pub G1Projective);

/// A hot storage signature
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default)]
pub struct HotSignature(pub G1Projective);

/// The proof for the cold storage wallet
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default)]
pub struct ColdStorageProof {
    /// The first commitment
    pub a1: G2Projective,
    /// The second commitment
    pub a2: G2Projective,
    /// The first proof
    pub z1: Scalar,
    /// The second proof
    pub z2: Scalar,
}

impl ColdStorageProof {
    /// Verify the cold storage proof
    pub fn verify(
        &self,
        encryption_keys: &EncryptionKeys,
        block_id: u64,
    ) -> KeyShareProofResult<()> {
        let mut bytes = [0u8; 192 + 8];
        bytes[..96].copy_from_slice(self.a1.to_compressed().as_ref());
        bytes[96..192].copy_from_slice(self.a2.to_compressed().as_ref());
        bytes[192..].copy_from_slice(&block_id.to_be_bytes());
        let c = Scalar::hash::<ExpandMsgXmd<sha2::Sha256>>(&bytes, b"BLS12381_XMD:SHA-256_RO_NUL_");
        // let lhs = G2Projective::GENERATOR * self.z1 + self.a1 * c;
        // let rhs = encryption_keys.0[0].0 * self.z1 + encryption_keys.0[1].0 * self.z2;
        let lhs1 = G2Projective::GENERATOR * self.z1;
        let rhs1 = self.a1 + encryption_keys.0[0].0 * c;
        let result1 = lhs1 - rhs1;
        let lhs2 = G2Projective::GENERATOR * self.z2;
        let rhs2 = self.a2 + encryption_keys.0[1].0 * c;
        let result2 = lhs2 - rhs2;
        if (result1.is_identity() & result2.is_identity()).into() {
            Ok(())
        } else {
            Err(KeyShareProofError::General(
                "invalid cold storage proof".to_string(),
            ))
        }
    }
}

/// The proof for the hot storage wallet
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default)]
pub struct HotStorageProof {
    /// The commitment to the encrypted share
    pub comm_ped: G1Projective,
    /// The proof to the encrypted share
    pub a_comm_ped: G1Projective,
    /// The first proof
    pub t1: Scalar,
    /// The second proof
    pub t2: Scalar,
    /// The blinded proof
    pub blinded_proof: G1Projective,
    /// The shift proof
    pub shift_proof: G2Projective,
}

impl HotStorageProof {
    /// Verify the hot storage proof
    pub fn verify(
        &self,
        crs: &KZG10CommonReferenceParams,
        current_commitment: &G1Projective,
        share_eval_pt: Scalar,
        block_id: u64,
    ) -> KeyShareProofResult<()> {
        let params = PedersenCommitmentParams::default();
        let args = [
            (
                (current_commitment - self.comm_ped).to_affine(),
                G2Prepared::from(-crs.powers_of_h[0].to_affine()),
            ),
            (
                self.blinded_proof.to_affine(),
                G2Prepared::from(
                    (crs.powers_of_h[1] - (crs.powers_of_h[0] * share_eval_pt)).to_affine(),
                ),
            ),
            (
                params.h.to_affine(),
                G2Prepared::from(self.shift_proof.to_affine()),
            ),
        ];
        let ref_args = args.iter().map(|(a, b)| (a, b)).collect::<Vec<_>>();

        let mut bytes = [0u8; 48 + 8];
        bytes[..48].copy_from_slice(self.a_comm_ped.to_compressed().as_ref());
        bytes[48..].copy_from_slice(&block_id.to_be_bytes());
        let c = Scalar::hash::<ExpandMsgXmd<sha2::Sha256>>(&bytes, b"BLS12381_XMD:SHA-256_RO_NUL_");
        let lhs = self.a_comm_ped + self.comm_ped * c;
        let rhs = params.commit(self.t1, self.t2);

        if bool::from(
            lhs.ct_eq(&rhs)
                & multi_miller_loop(&ref_args)
                    .final_exponentiation()
                    .is_identity(),
        ) {
            Ok(())
        } else {
            Err(KeyShareProofError::General(
                "invalid hot storage proof".to_string(),
            ))
        }
    }
}

/// The payload for the client registration when submitting new encrypted shares
#[derive(Debug, Copy, Clone, Deserialize, Serialize, Default)]
pub struct ClientRegisterPayload {
    /// The share index
    pub share_id: usize,
    /// The encrypted share
    pub encrypted_share: Scalar,
    /// The verification share
    pub verification_share: G2Projective,
    /// The KZG commitment to the polynomial
    pub commitment: G1Projective,
    /// The opening proof
    pub proof: G1Projective,
}
impl ClientRegisterPayload {
    /// Use refresh value to update hot key share (without verifying it first)
    pub fn refresh(
        &self,
        refresh_commitment: &G1Projective,
        refresh_payload: &ClientRefreshPayload,
    ) -> KeyShareProofResult<ClientRegisterPayload> {
        Ok(ClientRegisterPayload {
            share_id: self.share_id,
            encrypted_share: self.encrypted_share + refresh_payload.share,
            verification_share: self.verification_share * refresh_payload.share,
            commitment: self.commitment + refresh_commitment,
            proof: self.proof + refresh_payload.proof,
        })
    }
    /// Verify refresh value before using it to update hot key share
    pub fn refresh_untrusted(
        &self,
        refresh_commitment: &G1Projective,
        refresh_payload: &ClientRefreshPayload,
        crs: &KZG10CommonReferenceParams,
    ) -> KeyShareProofResult<ClientRegisterPayload> {
        // use *current* share to determine eval point
        let eval_point = crs.omega.pow_vartime([self.share_id as u64]);
        // verify the refresh share
        crs.verify(
            &refresh_commitment,
            eval_point,
            refresh_payload.share,
            &refresh_payload.proof,
        )?;
        self.refresh(refresh_commitment, refresh_payload)
    }
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
    let degree_poly = &zero_poly * crate::DensePolyPrimeField(degree_shift);
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
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use std::num::NonZeroUsize;

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

    #[test]
    fn test_cold_proof() {
        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let dks = DecryptionKeys::random(&mut rng);
        let eks = EncryptionKeys::from(&dks);

        let cold_proof = dks.prove(0);
        assert!(cold_proof.verify(&eks, 0).is_ok());
    }
}
