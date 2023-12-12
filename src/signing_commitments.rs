use crate::Error;
use frost_core::Ciphersuite;
use serde::{Deserialize, Serialize};

/// Published by each participant in the first round of the signing protocol.
///
/// This step can be batched using FrostScheme::pregenerate_signing_nonces.
/// Each [`SigningCommitment`] can be used for exactly one signature.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Deserialize, Serialize)]
#[repr(transparent)]
pub struct SigningCommitments(pub Vec<u8>);

impl<C: Ciphersuite> From<frost_core::round1::SigningCommitments<C>> for SigningCommitments {
    fn from(s: frost_core::round1::SigningCommitments<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::round1::SigningCommitments<C>> for SigningCommitments {
    fn from(s: &frost_core::round1::SigningCommitments<C>) -> Self {
        Self(s.serialize().unwrap())
    }
}

impl<C: Ciphersuite> TryFrom<&SigningCommitments> for frost_core::round1::SigningCommitments<C> {
    type Error = Error;

    fn try_from(value: &SigningCommitments) -> Result<Self, Self::Error> {
        frost_core::round1::SigningCommitments::<C>::deserialize(value.0.as_slice())
            .map_err(|_| Error::General("Error deserializing signing commitment".to_string()))
    }
}
