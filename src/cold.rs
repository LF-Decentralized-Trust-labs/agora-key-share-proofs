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
        encrypted_share: Scalar,
        current_opening: G1Projective,
        block_id: u64,
    ) -> HotStorageProof {
        let params = PedersenCommitmentParams::default();
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
        let shift_proof =
            G2Projective::GENERATOR * -r + (crs.powers_of_h[1] - crs.powers_of_h[0]) * -si; // TODO crs.powers_of_h[0] should be multiplied by party index i
        HotStorageProof {
            comm_ped,
            a_comm_ped,
            t1,
            t2,
            blinded_proof,
            shift_proof,
            current_opening,
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
    pub fn verify(&self, encryption_keys: &EncryptionKeys) -> KeyShareProofResult<()> {
        let mut bytes = [0u8; 192 + 8];
        bytes[..96].copy_from_slice(self.a1.to_compressed().as_ref());
        bytes[96..192].copy_from_slice(self.a2.to_compressed().as_ref());
        bytes[192..].copy_from_slice(&1000u64.to_be_bytes());
        let c = Scalar::hash::<ExpandMsgXmd<sha2::Sha256>>(&bytes, b"BLS12381_XMD:SHA-256_RO_NUL_");
        let lhs = G2Projective::GENERATOR * self.z1 + self.a1 * c;
        let rhs = encryption_keys.0[0].0 * self.z1 + encryption_keys.0[1].0 * self.z2;
        let result = lhs - rhs;
        if result.is_identity().into() {
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
    /// The current opening proof
    pub current_opening: G1Projective,
}

impl HotStorageProof {
    /// Verify the hot storage proof
    pub fn verify(
        &self,
        crs: &KZG10CommonReferenceParams,
        block_id: u64,
    ) -> KeyShareProofResult<()> {
        let params = PedersenCommitmentParams::default();
        let args = [
            (
                (self.current_opening - self.comm_ped).to_affine(),
                G2Prepared::from(-crs.powers_of_h[0].to_affine()),
            ),
            (
                self.blinded_proof.to_affine(),
                G2Prepared::from((crs.powers_of_h[1] - crs.powers_of_h[0]).to_affine()),
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
    pub share_id: Scalar,
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
    /// Use refresh value to update hot key share
    pub fn refresh(
        &self,
        refresh_payload: &ClientRefreshPayload,
        share_id: Scalar,
        crs: &KZG10CommonReferenceParams,
    ) -> KeyShareProofResult<ClientRegisterPayload> {
        crs.verify(
            &refresh_payload.commitment,
            share_id,
            refresh_payload.zero_share,
            &refresh_payload.proof,
        )?;

        Ok(ClientRegisterPayload {
            share_id,
            encrypted_share: self.encrypted_share + refresh_payload.zero_share,
            verification_share: self.verification_share * refresh_payload.zero_share,
            commitment: self.commitment + refresh_payload.commitment,
            proof: self.proof + refresh_payload.proof,
        })
    }
}

/// The payload for the share refresh when refreshing encrypted shares
#[derive(Debug, Copy, Clone, Deserialize, Serialize, Default)]
pub struct ClientRefreshPayload {
    /// The share index
    pub share_id: Scalar,
    /// The zero share
    pub zero_share: Scalar,
    /// The KZG commitment to the zero polynomial
    pub commitment: G1Projective,
    /// The opening proof
    pub proof: G1Projective,
}
/// Generate shares of zero to refresh hot key shares
pub fn generate_refresh_payloads(
    threshold: usize,
    num_shares: usize,
    crs: &KZG10CommonReferenceParams,
    mut rng: impl RngCore + CryptoRng,
) -> KeyShareProofResult<Vec<ClientRefreshPayload>> {
    let zero = SigningKey(Scalar::ZERO);
    let (zero_shares, zero_poly) = zero.create_shares(threshold, num_shares, &mut rng)?;
    let challenges = zero_shares
        .iter()
        // i+2 because verification fails when challenge = 1 (TODO why?)
        .map(|share| share.id)
        .collect::<Vec<_>>();
    let opening_proofs = crs.batch_open(&zero_poly, &challenges);
    let zero_proof = crs.open(&zero_poly, Scalar::ZERO);

    let mut refresh_payloads = vec![ClientRefreshPayload::default(); zero_shares.len()];

    // TODO also return opening proof at 0 and dcom
    for (i, payload) in refresh_payloads.iter_mut().enumerate() {
        payload.share_id = challenges[i];
        payload.zero_share = zero_shares[i].share;
        // payload.verification_share = G2Projective::GENERATOR * shares[i].share;
        payload.proof = opening_proofs[i];
        payload.commitment = crs.commit_g1(&zero_poly)
    }

    Ok(refresh_payloads)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use std::num::NonZeroUsize;

    #[test]
    fn test_refresh() {
        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        let sk = SigningKey(Scalar::random(&mut rng));
        let threshold = 2;
        let num_parties = 3;
        let crs = KZG10CommonReferenceParams::setup(
            NonZeroUsize::new(num_parties - 1).unwrap(),
            &mut rng,
        );
        let domain_size = num_parties.next_power_of_two();
        let share_ids =
            GeneralEvaluationDomain::<Scalar>::new(domain_size).expect("Failed to create domain");

        // get refresh information
        let refresh_payloads_res = generate_refresh_payloads(threshold, num_parties, &crs, rng);
        assert!(refresh_payloads_res.is_ok());

        let refresh_payloads = refresh_payloads_res.unwrap();

        // every party verifies its zero share
        for (i, payload) in refresh_payloads.iter().enumerate() {
            assert!(crs
                .verify(
                    &payload.commitment,
                    // share_ids.element(i + 1),
                    // Scalar::from((i + 1) as u64),
                    payload.share_id,
                    payload.zero_share,
                    &payload.proof
                )
                .is_ok());
        }
    }
}
