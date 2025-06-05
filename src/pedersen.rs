use crate::*;
use blsful::inner_types::*;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// The Pedersen commitment parameters, the g and h generators
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PedersenCommitmentParams {
    /// The g generator
    pub g: G1Projective,
    /// The h generator
    pub h: G1Projective,
}

impl Default for PedersenCommitmentParams {
    fn default() -> Self {
        let h = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(
            &G1Projective::GENERATOR.to_compressed(),
            b"BLS12381G1_XMD:SHA-256_SSWU_RO_",
        );
        Self {
            g: G1Projective::GENERATOR,
            h,
        }
    }
}

impl PedersenCommitmentParams {
    /// Create a new Pedersen commitment to `x` with a random blinder
    pub fn commit_random(
        &self,
        x: Scalar,
        rng: impl RngCore + CryptoRng,
    ) -> (G1Projective, Scalar) {
        let r = Scalar::random(rng);
        (self.commit(x, r), r)
    }

    /// Create a new Pedersen commitment to `x` with a given blinder
    pub fn commit(&self, x: Scalar, r: Scalar) -> G1Projective {
        self.g * x + self.h * r
    }

    /// Open the commitment to `x` with blinder `r`
    pub fn open(&self, x: Scalar, r: Scalar, c: G1Projective) -> bool {
        c == self.commit(x, r)
    }

    /// Commit to an `x` and random blinder `r` that can be used in a ZK proof
    pub fn commit_zk(
        &self,
        x: Scalar,
        r: Option<Scalar>,
        mut rng: impl RngCore + CryptoRng,
    ) -> ZKPedersenCommitting {
        let r = r.unwrap_or_else(|| Scalar::random(&mut rng));
        let s1 = Scalar::random(&mut rng);
        let s2 = Scalar::random(&mut rng);

        let commitment = self.commit(x, r);
        let proof_commitment = self.commit(s1, s2);
        ZKPedersenCommitting {
            params: *self,
            commitment,
            proof_commitment,
            x,
            r,
            s1,
            s2,
        }
    }
}

/// A Pedersen commitment to `x` with a blinder `r` that can be used in a ZK proof
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZKPedersenCommitting {
    pub(crate) params: PedersenCommitmentParams,
    pub(crate) commitment: G1Projective,
    pub(crate) proof_commitment: G1Projective,
    pub(crate) x: Scalar,
    pub(crate) r: Scalar,
    pub(crate) s1: Scalar,
    pub(crate) s2: Scalar,
}

impl Zeroize for ZKPedersenCommitting {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.r.zeroize();
        self.s1.zeroize();
        self.s2.zeroize();
    }
}

impl ZKPedersenCommitting {
    /// Add the values to the fiat-shamir transcript for the ZK proof
    pub fn add_challenge_contribution(&self, transcript: &mut Transcript) {
        transcript.append_message(b"pedersen_g", &self.params.g.to_compressed());
        transcript.append_message(b"pedersen_h", &self.params.h.to_compressed());
        transcript.append_message(
            b"pedersen_commitment",
            &self.commitment.to_affine().to_compressed(),
        );
        transcript.append_message(
            b"pedersen_proof_commitment",
            &self.proof_commitment.to_affine().to_compressed(),
        );
    }

    /// Finish the ZK proof and create a `ZKPedersenCommitment`
    pub fn finish(self, challenge: Scalar) -> ZKPedersenCommitment {
        ZKPedersenCommitment {
            commitment: self.commitment,
            challenge,
            proof_s1: self.s1 + challenge * self.x,
            proof_s2: self.s2 + challenge * self.r,
        }
    }
}

/// A Pedersen commitment to `x` with a blinder `r` as a ZK proof
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZKPedersenCommitment {
    pub(crate) commitment: G1Projective,
    pub(crate) challenge: Scalar,
    pub(crate) proof_s1: Scalar,
    pub(crate) proof_s2: Scalar,
}

impl ZKPedersenCommitment {
    /// Add the values to the fiat-shamir transcript for the ZK proof
    pub fn add_challenge_contribution(
        &self,
        params: PedersenCommitmentParams,
        transcript: &mut Transcript,
    ) {
        let proof_commitment =
            params.commit(self.proof_s1, self.proof_s2) - self.commitment * self.challenge;
        transcript.append_message(b"pedersen_g", &params.g.to_compressed());
        transcript.append_message(b"pedersen_h", &params.h.to_compressed());
        transcript.append_message(
            b"pedersen_commitment",
            &self.commitment.to_affine().to_compressed(),
        );
        transcript.append_message(
            b"pedersen_proof_commitment",
            &proof_commitment.to_affine().to_compressed(),
        );
    }

    /// Verify the ZK proof
    pub fn verify(&self, params: PedersenCommitmentParams) -> KeyShareProofResult<()> {
        let proof_commitment =
            params.commit(self.proof_s1, self.proof_s2) - self.commitment * self.challenge;
        if proof_commitment == G1Projective::identity() {
            Ok(())
        } else {
            Err(KeyShareProofError::InvalidPedersenProof)
        }
    }
}
