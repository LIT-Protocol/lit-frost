use crate::Error;
use frost_core::{Ciphersuite, Group};
use serde::{Deserialize, Serialize};

/// A public group element that represents a single signer’s public verification share.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Deserialize, Serialize)]
#[repr(transparent)]
pub struct VerifyingShare(pub Vec<u8>);

impl<C: Ciphersuite> From<frost_core::keys::VerifyingShare<C>> for VerifyingShare {
    fn from(s: frost_core::keys::VerifyingShare<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::keys::VerifyingShare<C>> for VerifyingShare {
    fn from(s: &frost_core::keys::VerifyingShare<C>) -> Self {
        Self(s.serialize().as_ref().to_vec())
    }
}

impl<C: Ciphersuite> TryFrom<&VerifyingShare> for frost_core::keys::VerifyingShare<C> {
    type Error = Error;

    fn try_from(value: &VerifyingShare) -> Result<Self, Self::Error> {
        let bytes =
            <C::Group as Group>::Serialization::try_from(value.0.clone()).map_err(|_| {
                Error::General("Error converting verifying share from bytes".to_string())
            })?;
        frost_core::keys::VerifyingShare::<C>::deserialize(bytes)
            .map_err(|_| Error::General("Error deserializing verifying share".to_string()))
    }
}
