use crate::{Error, Scheme};
use frost_core::Ciphersuite;

/// Published by each participant in the first round of the signing protocol.
///
/// This step can be batched using Scheme::pregenerate_signing_nonces.
/// Each [`SigningCommitments`] can be used for exactly one signature.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub struct SigningCommitments {
    /// The ciphersuite used for this signing commitment.
    pub scheme: Scheme,
    /// The serialized signing commitment.
    pub value: Vec<u8>,
}

impl<C: Ciphersuite> From<frost_core::round1::SigningCommitments<C>> for SigningCommitments {
    fn from(s: frost_core::round1::SigningCommitments<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::round1::SigningCommitments<C>> for SigningCommitments {
    fn from(s: &frost_core::round1::SigningCommitments<C>) -> Self {
        let scheme = C::ID.parse().unwrap();
        Self {
            scheme,
            value: s.serialize().unwrap(),
        }
    }
}

impl<C: Ciphersuite> TryFrom<&SigningCommitments> for frost_core::round1::SigningCommitments<C> {
    type Error = Error;

    fn try_from(value: &SigningCommitments) -> Result<Self, Self::Error> {
        if value.scheme != C::ID.parse().unwrap() {
            return Err(Error::General(
                "Signing commitment scheme does not match ciphersuite".to_string(),
            ));
        }
        frost_core::round1::SigningCommitments::<C>::deserialize(value.value.as_slice())
            .map_err(|_| Error::General("Error deserializing signing commitment".to_string()))
    }
}

serde_impl!(SigningCommitments, commitment_len, 120);
display_impl!(SigningCommitments);
