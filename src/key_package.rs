use crate::{Error, ParticipantIdentifier, SigningShare, VerifyingKey};
use frost_core::Ciphersuite;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU8;

/// The frost keys used for signing generated during the DKG.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Deserialize, Serialize)]
pub struct KeyPackage {
    pub identifier: ParticipantIdentifier,
    pub secret_share: SigningShare,
    pub verifying_key: VerifyingKey,
    pub threshold: NonZeroU8,
}

impl<C: Ciphersuite> From<frost_core::keys::KeyPackage<C>> for KeyPackage {
    fn from(s: frost_core::keys::KeyPackage<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::keys::KeyPackage<C>> for KeyPackage {
    fn from(s: &frost_core::keys::KeyPackage<C>) -> Self {
        Self {
            identifier: s.identifier().into(),
            secret_share: s.signing_share().into(),
            verifying_key: s.verifying_key().into(),
            threshold: NonZeroU8::new(*s.min_signers() as u8).unwrap(),
        }
    }
}

impl<C: Ciphersuite> TryFrom<&KeyPackage> for frost_core::keys::KeyPackage<C> {
    type Error = Error;

    fn try_from(value: &KeyPackage) -> Result<Self, Self::Error> {
        let identifier = value.identifier.try_into()?;
        let secret_share: frost_core::keys::SigningShare<C> = (&value.secret_share).try_into()?;
        let verifying_share = frost_core::keys::VerifyingShare::<C>::from(secret_share);
        let group_public = (&value.verifying_key).try_into()?;
        let threshold = value.threshold.get();
        let key_package = frost_core::keys::KeyPackage::<C>::new(
            identifier,
            secret_share,
            verifying_share,
            group_public,
            threshold as u16,
        );
        Ok(key_package)
    }
}

impl KeyPackage {
    pub fn new(
        identifier: ParticipantIdentifier,
        secret_share: SigningShare,
        group_public: VerifyingKey,
        threshold: NonZeroU8,
    ) -> Self {
        Self {
            identifier,
            secret_share,
            verifying_key: group_public,
            threshold,
        }
    }
}
