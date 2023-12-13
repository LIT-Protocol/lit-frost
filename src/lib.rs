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
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Display, Formatter},
    str::FromStr,
};

/// The FROST supported signature schemes
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Copy)]
#[repr(u8)]
pub enum Scheme {
    /// Unknown scheme
    Unknown = 0,
    /// Compute the Ed25519 signature using the SHA-512 hash function
    Ed25519Sha512 = 1,
    /// Compute the Ed448 signature using the SHAKE-256 hash function
    Ed448Shake256 = 2,
    /// Compute the Ristretto25519 signature using the SHA-512 hash function
    Ristretto25519Sha512 = 3,
    /// Compute the Secp256k1 schnorr signature using the SHA-256 hash function
    K256Sha256 = 4,
    /// Compute the NistP256 schnorr signature using the SHA-256 hash function
    P256Sha256 = 5,
    /// Compute the NistP384 schnorr signature using the SHA-384 hash function
    P384Sha384 = 6,
}

impl Display for Scheme {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519Sha512 => write!(f, "Ed25519Sha512"),
            Self::Ed448Shake256 => write!(f, "Ed448Shake256"),
            Self::Ristretto25519Sha512 => write!(f, "Ristretto25519Sha512"),
            Self::K256Sha256 => write!(f, "K256Sha256"),
            Self::P256Sha256 => write!(f, "P256Sha256"),
            Self::P384Sha384 => write!(f, "P384Sha384"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl FromStr for Scheme {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Ed25519Sha512" | "FROST-ED25519-SHA512-v1" => Ok(Self::Ed25519Sha512),
            "Ed448Shake256" | "FROST-ED448-SHAKE256-v1" => Ok(Self::Ed448Shake256),
            "Ristretto25519Sha512" | "FROST-RISTRETTO255-SHA512-v1" => {
                Ok(Self::Ristretto25519Sha512)
            }
            "K256Sha256" | "FROST-secp256k1-SHA256-v1" => Ok(Self::K256Sha256),
            "P256Sha256" | "FROST-P256-SHA256-v1" => Ok(Self::P256Sha256),
            "P384Sha384" | "FROST-P384-SHA384-v1" => Ok(Self::P384Sha384),
            _ => Err(Error::General(format!("Unknown scheme: {}", s))),
        }
    }
}

impl From<u8> for Scheme {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Ed25519Sha512,
            2 => Self::Ed448Shake256,
            3 => Self::Ristretto25519Sha512,
            4 => Self::K256Sha256,
            5 => Self::P256Sha256,
            6 => Self::P384Sha384,
            _ => Self::Unknown,
        }
    }
}

impl Serialize for Scheme {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_string())
        } else {
            s.serialize_u8(*self as u8)
        }
    }
}

impl<'de> Deserialize<'de> for Scheme {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            Self::from_str(&s).map_err(serde::de::Error::custom)
        } else {
            let u = u8::deserialize(d)?;
            Ok(Self::from(u))
        }
    }
}

impl Scheme {
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
            Self::Unknown => Err(Error::General("Unknown scheme".to_string())),
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
            Self::Unknown => Err(Error::General("Unknown scheme".to_string())),
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
            Self::Unknown => Err(Error::General("Unknown scheme".to_string())),
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
            Self::Unknown => Err(Error::General("Unknown scheme".to_string())),
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
            Self::Unknown => Err(Error::General("Unknown scheme".to_string())),
        }
    }

    pub fn verifying_share(&self, signing_share: &SigningShare) -> FrostResult<VerifyingShare> {
        match self {
            Self::Ed25519Sha512 => verifying_share::<frost_ed25519::Ed25519Sha512>(signing_share),
            Self::Ed448Shake256 => verifying_share::<frost_ed448::Ed448Shake256>(signing_share),
            Self::Ristretto25519Sha512 => {
                verifying_share::<frost_ristretto255::Ristretto255Sha512>(signing_share)
            }
            Self::K256Sha256 => verifying_share::<frost_secp256k1::Secp256K1Sha256>(signing_share),
            Self::P256Sha256 => verifying_share::<frost_p256::P256Sha256>(signing_share),
            Self::P384Sha384 => verifying_share::<frost_p384::P384Sha384>(signing_share),
            Self::Unknown => Err(Error::General("Unknown scheme".to_string())),
        }
    }

    #[cfg(test)]
    pub fn generate_with_trusted_dealer<R: CryptoRng + RngCore>(
        &self,
        min_signers: u8,
        max_signers: u8,
        rng: &mut R,
    ) -> FrostResult<(BTreeMap<ParticipantIdentifier, SigningShare>, VerifyingKey)> {
        match self {
            Self::Ed25519Sha512 => generate_with_trusted_dealer::<frost_ed25519::Ed25519Sha512, R>(
                min_signers,
                max_signers,
                rng,
            ),
            Self::Ed448Shake256 => generate_with_trusted_dealer::<frost_ed448::Ed448Shake256, R>(
                min_signers,
                max_signers,
                rng,
            ),
            Self::Ristretto25519Sha512 => generate_with_trusted_dealer::<
                frost_ristretto255::Ristretto255Sha512,
                R,
            >(min_signers, max_signers, rng),
            Self::K256Sha256 => {
                generate_with_trusted_dealer::<frost_secp256k1::Secp256K1Sha256, R>(
                    min_signers,
                    max_signers,
                    rng,
                )
            }
            Self::P256Sha256 => generate_with_trusted_dealer::<frost_p256::P256Sha256, R>(
                min_signers,
                max_signers,
                rng,
            ),
            Self::P384Sha384 => generate_with_trusted_dealer::<frost_p384::P384Sha384, R>(
                min_signers,
                max_signers,
                rng,
            ),
            Self::Unknown => Err(Error::General("Unknown scheme".to_string())),
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

fn verifying_share<C: Ciphersuite>(signing_share: &SigningShare) -> FrostResult<VerifyingShare> {
    let signing_share: frost_core::keys::SigningShare<C> = signing_share.try_into()?;
    let verifying_share = frost_core::keys::VerifyingShare::<C>::from(signing_share);
    Ok(verifying_share.into())
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
        signer_pubkeys_map.insert(index.try_into()?, pubkey.try_into()?);
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

#[cfg(test)]
fn generate_with_trusted_dealer<C: Ciphersuite, R: CryptoRng + RngCore>(
    min_signers: u8,
    max_signers: u8,
    rng: &mut R,
) -> FrostResult<(BTreeMap<ParticipantIdentifier, SigningShare>, VerifyingKey)> {
    let (shares, public_package) = frost_core::keys::generate_with_dealer::<C, R>(
        max_signers as u16,
        min_signers as u16,
        frost_core::keys::IdentifierList::<C>::Default,
        rng,
    )
    .map_err(|_| Error::General("Error generating keys".to_string()))?;
    let shares = shares
        .iter()
        .map(|(id, share)| (id.into(), share.signing_share().into()))
        .collect();
    Ok((shares, public_package.verifying_key().into()))
}

fn create_frost_signing_commitments_from_bytes<C: Ciphersuite>(
    signing_commitments: &[(ParticipantIdentifier, SigningCommitments)],
) -> FrostResult<BTreeMap<frost_core::Identifier<C>, frost_core::round1::SigningCommitments<C>>> {
    let mut signing_commitments_map = BTreeMap::new();
    for (index, commitment) in signing_commitments {
        signing_commitments_map.insert(index.try_into()?, commitment.try_into()?);
    }
    Ok(signing_commitments_map)
}

fn create_frost_signing_shares_from_bytes<C: Ciphersuite>(
    signing_shares: &[(ParticipantIdentifier, SignatureShare)],
) -> FrostResult<BTreeMap<frost_core::Identifier<C>, frost_core::round2::SignatureShare<C>>> {
    let mut signing_commitments_map = BTreeMap::new();
    for (index, share) in signing_shares {
        signing_commitments_map.insert(index.try_into()?, share.try_into()?);
    }
    Ok(signing_commitments_map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case(Scheme::Ed25519Sha512, 32)]
    #[case(Scheme::Ristretto25519Sha512, 32)]
    #[case(Scheme::P256Sha256, 32)]
    #[case(Scheme::K256Sha256, 32)]
    #[case(Scheme::P384Sha384, 48)]
    #[case(Scheme::Ed448Shake256, 57)]
    fn pregenerate(#[case] scheme: Scheme, #[case] length: usize) {
        let mut rng = rand::rngs::OsRng;
        let mut secret = SigningShare {
            scheme,
            value: vec![1u8; length]
        };
        // Clear the high bits
        secret.value[length - 1] = 0;
        secret.value[length - 2] = 0;
        let (signing_nonces, signing_commitments) = scheme
            .pregenerate_signing_nonces(NonZeroU8::new(200).unwrap(), &secret, &mut rng)
            .unwrap();
        assert_eq!(signing_nonces.len(), 200);
        assert_eq!(signing_commitments.len(), 200);
    }

    #[rstest]
    #[case(Scheme::Ed25519Sha512)]
    #[case(Scheme::Ristretto25519Sha512)]
    #[case(Scheme::P256Sha256)]
    #[case(Scheme::K256Sha256)]
    #[case(Scheme::P384Sha384)]
    #[case(Scheme::Ed448Shake256)]
    fn rounds(#[case] scheme: Scheme) {
        const MSG: &[u8] = b"test";
        const THRESHOLD: u8 = 3;
        let mut rng = rand::rngs::OsRng;
        let (secret_shares, verifying_key) = scheme
            .generate_with_trusted_dealer(THRESHOLD, 5, &mut rng)
            .unwrap();

        let mut signing_pacakge = BTreeMap::new();
        let mut signing_commitments = Vec::new();

        for (id, secret_share) in secret_shares {
            let res = scheme.round1(&secret_share, &mut rng);
            assert!(res.is_ok());
            let (nonces, commitments) = res.unwrap();
            signing_pacakge.insert(id, (nonces, secret_share));
            signing_commitments.push((id, commitments));
        }

        let mut verifying_shares = Vec::new();
        let mut signature_shares = Vec::new();
        for (id, (nonces, secret_share)) in signing_pacakge {
            let res = scheme.sign(
                MSG,
                &signing_commitments,
                &nonces,
                &KeyPackage {
                    identifier: id.clone(),
                    secret_share: secret_share.clone(),
                    verifying_key: verifying_key.clone(),
                    threshold: NonZeroU8::new(THRESHOLD).unwrap(),
                },
            );
            let signature = res.unwrap();
            signature_shares.push((id.clone(), signature));
            verifying_shares.push((id.clone(), scheme.verifying_share(&secret_share).unwrap()));
        }

        let res = scheme.aggregate(
            MSG,
            &signing_commitments,
            &signature_shares,
            &verifying_shares,
            &verifying_key,
        );
        let signature = res.unwrap();
        assert!(scheme.verify(MSG, &verifying_key, &signature).is_ok());
    }

    #[rstest]
    #[case(Scheme::Ed25519Sha512)]
    #[case(Scheme::Ristretto25519Sha512)]
    #[case(Scheme::P256Sha256)]
    #[case(Scheme::K256Sha256)]
    #[case(Scheme::P384Sha384)]
    #[case(Scheme::Ed448Shake256)]
    fn full(#[case] scheme: Scheme) {
        const MSG: &[u8] = b"test";
        const THRESHOLD: u8 = 3;
        let mut rng = rand::rngs::OsRng;
        let (secret_shares, verifying_key) = scheme
            .generate_with_trusted_dealer(THRESHOLD, 5, &mut rng)
            .unwrap();

        let mut signing_package = Vec::new();
        for (id, secret_share) in secret_shares {
            let res = scheme.pregenerate_signing_nonces(
                NonZeroU8::new(20).unwrap(),
                &secret_share,
                &mut rng,
            );
            assert!(res.is_ok());
            let (nonces, commitments) = res.unwrap();
            signing_package.push((id, secret_share, nonces, commitments));
        }

        while signing_package[0].2.len() > 0 {
            let mut signing_commitments = Vec::new();
            let mut new_signing_package = Vec::new();
            for i in 0..signing_package.len() {
                signing_commitments.push((
                    signing_package[i].0.clone(),
                    signing_package[i].3.pop().unwrap(),
                ));
                new_signing_package.push((
                    signing_package[i].0.clone(),
                    signing_package[i].2.pop().unwrap(),
                    signing_package[i].1.clone(),
                ));
            }

            let mut verifying_shares = Vec::new();
            let mut signature_shares = Vec::new();
            for (id, nonces, secret_share) in new_signing_package {
                let res = scheme.sign(
                    MSG,
                    &signing_commitments,
                    &nonces,
                    &KeyPackage {
                        identifier: id.clone(),
                        secret_share: secret_share.clone(),
                        verifying_key: verifying_key.clone(),
                        threshold: NonZeroU8::new(THRESHOLD).unwrap(),
                    },
                );
                assert!(res.is_ok());
                let signature = res.unwrap();
                signature_shares.push((id.clone(), signature));
                verifying_shares.push((id.clone(), scheme.verifying_share(&secret_share).unwrap()));
            }

            let res = scheme.aggregate(
                MSG,
                &signing_commitments,
                &signature_shares,
                &verifying_shares,
                &verifying_key,
            );
            assert!(res.is_ok());
            let signature = res.unwrap();
            assert!(scheme.verify(MSG, &verifying_key, &signature).is_ok());
        }
    }
}
