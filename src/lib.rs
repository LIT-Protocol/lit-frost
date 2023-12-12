mod error;
mod identifier;
mod key_package;
mod signature;
mod signature_share;
mod signing_commitments;
mod signing_nonces;
mod signing_share;
mod verifying_key;
mod verifying_share;

pub use error::*;
pub use identifier::ParticipantIdentifier;
pub use key_package::KeyPackage;
pub use signature::Signature;
pub use signature_share::SignatureShare;
pub use signing_commitments::SigningCommitments;
pub use signing_nonces::SigningNonces;
pub use signing_share::SigningShare;
pub use verifying_key::VerifyingKey;
pub use verifying_share::VerifyingShare;

use core::num::NonZeroU8;
use frost_core::Ciphersuite;
use rand_core::{CryptoRng, RngCore};
use std::collections::BTreeMap;

/// The FROST supported signature schemes
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Copy)]
pub enum FrostScheme {
    /// Compute the Ed25519 signature using the SHA-512 hash function
    Ed25519Sha512,
    /// Compute the Ed448 signature using the SHAKE-256 hash function
    Ed448Shake256,
    /// Compute the Ristretto25519 signature using the SHA-512 hash function
    Ristretto25519Sha512,
    /// Compute the Secp256k1 schnorr signature using the SHA-256 hash function
    K256Sha256,
    /// Compute the NistP256 schnorr signature using the SHA-256 hash function
    P256Sha256,
    /// Compute the NistP384 schnorr signature using the SHA-384 hash function
    P384Sha384,
}

impl FrostScheme {
    /// Pregenerate a `count` of signing nonces and commitments that can be used
    /// later to sign a message. These nonce MUST only be used once, otherwise
    /// the long-lived signing key will be leaked.
    pub fn pregenerate_signing_nonces<R: CryptoRng + RngCore>(
        &self,
        count: NonZeroU8,
        secret_share: &SigningShare,
        rng: &mut R,
    ) -> FrostResult<(Vec<SigningNonces>, Vec<SigningCommitments>)> {
        match self {
            Self::Ed25519Sha512 => {
                preprocess::<frost_ed25519::Ed25519Sha512, R>(count, secret_share, rng)
            }
            Self::Ed448Shake256 => {
                preprocess::<frost_ed448::Ed448Shake256, R>(count, secret_share, rng)
            }
            Self::Ristretto25519Sha512 => {
                preprocess::<frost_ristretto255::Ristretto255Sha512, R>(count, secret_share, rng)
            }
            Self::K256Sha256 => {
                preprocess::<frost_secp256k1::Secp256K1Sha256, R>(count, secret_share, rng)
            }
            Self::P256Sha256 => preprocess::<frost_p256::P256Sha256, R>(count, secret_share, rng),
            Self::P384Sha384 => preprocess::<frost_p384::P384Sha384, R>(count, secret_share, rng),
        }
    }

    /// Compute the first round of the signing protocol if no pregenerated nonces and commitments are available.
    pub fn round1<R: CryptoRng + RngCore>(
        &self,
        secret_share: &SigningShare,
        rng: &mut R,
    ) -> FrostResult<(SigningNonces, SigningCommitments)> {
        match self {
            Self::Ed25519Sha512 => round1::<frost_ed25519::Ed25519Sha512, R>(secret_share, rng),
            Self::Ed448Shake256 => round1::<frost_ed448::Ed448Shake256, R>(secret_share, rng),
            Self::Ristretto25519Sha512 => {
                round1::<frost_ristretto255::Ristretto255Sha512, R>(secret_share, rng)
            }
            Self::K256Sha256 => round1::<frost_secp256k1::Secp256K1Sha256, R>(secret_share, rng),
            Self::P256Sha256 => round1::<frost_p256::P256Sha256, R>(secret_share, rng),
            Self::P384Sha384 => round1::<frost_p384::P384Sha384, R>(secret_share, rng),
        }
    }

    /// Compute the second round of the signing protocol and generate a signature.
    pub fn sign(
        &self,
        message: &[u8],
        signing_commitments: &[(ParticipantIdentifier, SigningCommitments)],
        signing_nonce: &SigningNonces,
        key_package: &KeyPackage,
    ) -> FrostResult<SignatureShare> {
        match self {
            Self::Ed25519Sha512 => round2::<frost_ed25519::Ed25519Sha512>(
                message,
                signing_commitments,
                signing_nonce,
                key_package,
            ),
            Self::Ed448Shake256 => round2::<frost_ed448::Ed448Shake256>(
                message,
                signing_commitments,
                signing_nonce,
                key_package,
            ),
            Self::Ristretto25519Sha512 => round2::<frost_ristretto255::Ristretto255Sha512>(
                message,
                signing_commitments,
                signing_nonce,
                key_package,
            ),
            Self::K256Sha256 => round2::<frost_secp256k1::Secp256K1Sha256>(
                message,
                signing_commitments,
                signing_nonce,
                key_package,
            ),
            Self::P256Sha256 => round2::<frost_p256::P256Sha256>(
                message,
                signing_commitments,
                signing_nonce,
                key_package,
            ),
            Self::P384Sha384 => round2::<frost_p384::P384Sha384>(
                message,
                signing_commitments,
                signing_nonce,
                key_package,
            ),
        }
    }

    /// Combine the signature shares into a single signature.
    pub fn aggregate(
        &self,
        message: &[u8],
        signing_commitments: &[(ParticipantIdentifier, SigningCommitments)],
        signature_shares: &[(ParticipantIdentifier, SignatureShare)],
        signer_pubkeys: &[(ParticipantIdentifier, VerifyingShare)],
        verifying_key: &VerifyingKey,
    ) -> FrostResult<Signature> {
        match self {
            Self::Ed25519Sha512 => aggregate::<frost_ed25519::Ed25519Sha512>(
                message,
                signing_commitments,
                signature_shares,
                signer_pubkeys,
                verifying_key,
            ),
            Self::Ed448Shake256 => aggregate::<frost_ed448::Ed448Shake256>(
                message,
                signing_commitments,
                signature_shares,
                signer_pubkeys,
                verifying_key,
            ),
            Self::Ristretto25519Sha512 => aggregate::<frost_ristretto255::Ristretto255Sha512>(
                message,
                signing_commitments,
                signature_shares,
                signer_pubkeys,
                verifying_key,
            ),
            Self::K256Sha256 => aggregate::<frost_secp256k1::Secp256K1Sha256>(
                message,
                signing_commitments,
                signature_shares,
                signer_pubkeys,
                verifying_key,
            ),
            Self::P256Sha256 => aggregate::<frost_p256::P256Sha256>(
                message,
                signing_commitments,
                signature_shares,
                signer_pubkeys,
                verifying_key,
            ),
            Self::P384Sha384 => aggregate::<frost_p384::P384Sha384>(
                message,
                signing_commitments,
                signature_shares,
                signer_pubkeys,
                verifying_key,
            ),
        }
    }

    /// Verify a purported signature over message made by this verification key.
    pub fn verify(
        &self,
        message: &[u8],
        verifying_key: &VerifyingKey,
        signature: &Signature,
    ) -> FrostResult<()> {
        match self {
            Self::Ed25519Sha512 => {
                verify::<frost_ed25519::Ed25519Sha512>(message, verifying_key, signature)
            }
            Self::Ed448Shake256 => {
                verify::<frost_ed448::Ed448Shake256>(message, verifying_key, signature)
            }
            Self::Ristretto25519Sha512 => {
                verify::<frost_ristretto255::Ristretto255Sha512>(message, verifying_key, signature)
            }
            Self::K256Sha256 => {
                verify::<frost_secp256k1::Secp256K1Sha256>(message, verifying_key, signature)
            }
            Self::P256Sha256 => verify::<frost_p256::P256Sha256>(message, verifying_key, signature),
            Self::P384Sha384 => verify::<frost_p384::P384Sha384>(message, verifying_key, signature),
        }
    }
}

fn verify<C: Ciphersuite>(
    message: &[u8],
    verifying_key: &VerifyingKey,
    signature: &Signature,
) -> FrostResult<()> {
    let verifying_key: frost_core::VerifyingKey<C> = verifying_key.try_into()?;
    let signature = signature.try_into()?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| Error::General("Error verifying signature".to_string()))
}

fn aggregate<C: Ciphersuite>(
    message: &[u8],
    signing_commitments: &[(ParticipantIdentifier, SigningCommitments)],
    signature_shares: &[(ParticipantIdentifier, SignatureShare)],
    signer_pubkeys: &[(ParticipantIdentifier, VerifyingShare)],
    verifying_key: &VerifyingKey,
) -> FrostResult<Signature> {
    let signing_commitment_map =
        create_frost_signing_commitments_from_bytes::<C>(signing_commitments)?;
    let signature_shares_map = create_frost_signing_shares_from_bytes::<C>(signature_shares)?;
    let mut signer_pubkeys_map = BTreeMap::new();
    for (index, pubkey) in signer_pubkeys {
        signer_pubkeys_map.insert(index.into(), pubkey.try_into()?);
    }
    let verifying_key = verifying_key.try_into()?;
    let pubkey_package =
        frost_core::keys::PublicKeyPackage::<C>::new(signer_pubkeys_map, verifying_key);
    let signing_package = frost_core::SigningPackage::<C>::new(signing_commitment_map, message);
    let res = frost_core::aggregate::<C>(&signing_package, &signature_shares_map, &pubkey_package);
    let signature = match res {
        Ok(s) => s,
        Err(_) => return Err(Error::General("Error aggregating signature".to_string())),
    };
    Ok(signature.into())
}

fn round2<C: Ciphersuite>(
    message: &[u8],
    signing_commitments: &[(ParticipantIdentifier, SigningCommitments)],
    signing_nonce: &SigningNonces,
    key_package: &KeyPackage,
) -> FrostResult<SignatureShare> {
    let key_package = key_package.try_into()?;
    let signing_nonces = signing_nonce.try_into()?;
    let signing_commitments_map =
        create_frost_signing_commitments_from_bytes::<C>(signing_commitments)?;
    let signing_package = frost_core::SigningPackage::<C>::new(signing_commitments_map, message);
    let signature = frost_core::round2::sign::<C>(&signing_package, &signing_nonces, &key_package)
        .map_err(|_| Error::General("Error signing".to_string()))?;
    Ok(signature.into())
}

fn round1<C: Ciphersuite, R: CryptoRng + RngCore>(
    secret: &SigningShare,
    rng: &mut R,
) -> FrostResult<(SigningNonces, SigningCommitments)> {
    let signing_share = secret.try_into()?;
    let (signing_nonces, signing_commitments) =
        frost_core::round1::commit::<C, R>(&signing_share, rng);
    Ok((signing_nonces.into(), signing_commitments.into()))
}

fn preprocess<C: Ciphersuite, R: CryptoRng + RngCore>(
    count: NonZeroU8,
    secret: &SigningShare,
    rng: &mut R,
) -> FrostResult<(Vec<SigningNonces>, Vec<SigningCommitments>)> {
    let signing_share = secret.try_into()?;
    let (signing_nonces, signing_commitments) =
        frost_core::round1::preprocess::<C, R>(count.get(), &signing_share, rng);
    Ok((
        signing_nonces.iter().map(SigningNonces::from).collect(),
        signing_commitments
            .iter()
            .map(SigningCommitments::from)
            .collect(),
    ))
}

fn create_frost_signing_commitments_from_bytes<C: Ciphersuite>(
    signing_commitments: &[(ParticipantIdentifier, SigningCommitments)],
) -> FrostResult<BTreeMap<frost_core::Identifier<C>, frost_core::round1::SigningCommitments<C>>> {
    let mut signing_commitments_map = BTreeMap::new();
    for (index, commitment) in signing_commitments {
        signing_commitments_map.insert(index.into(), commitment.try_into()?);
    }
    Ok(signing_commitments_map)
}

fn create_frost_signing_shares_from_bytes<C: Ciphersuite>(
    signing_shares: &[(ParticipantIdentifier, SignatureShare)],
) -> FrostResult<BTreeMap<frost_core::Identifier<C>, frost_core::round2::SignatureShare<C>>> {
    let mut signing_commitments_map = BTreeMap::new();
    for (index, share) in signing_shares {
        signing_commitments_map.insert(index.into(), share.try_into()?);
    }
    Ok(signing_commitments_map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case(FrostScheme::Ed25519Sha512, 32)]
    #[case(FrostScheme::Ristretto25519Sha512, 32)]
    #[case(FrostScheme::Ed448Shake256, 56)]
    #[case(FrostScheme::P256Sha256, 32)]
    #[case(FrostScheme::K256Sha256, 32)]
    #[case(FrostScheme::P384Sha384, 48)]
    fn test_pregenerate(#[case] scheme: FrostScheme, #[case] length: usize) {
        let mut rng = rand::rngs::OsRng;
        let secret = SigningShare(vec![1u8; length]);
        let (signing_nonces, signing_commitments) = scheme
            .pregenerate_signing_nonces(NonZeroU8::new(200).unwrap(), &secret, &mut rng)
            .unwrap();
        assert_eq!(signing_nonces.len(), 200);
        assert_eq!(signing_commitments.len(), 200);
    }
}
