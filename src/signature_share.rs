use crate::Error;
use frost_core::{Ciphersuite, Field, Group};
use serde::{Deserialize, Serialize};

/// A participant’s signature share, which is aggregated with all other signer’s shares into the joint signature.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Deserialize, Serialize)]
#[repr(transparent)]
pub struct SignatureShare(pub Vec<u8>);

impl<C: Ciphersuite> From<frost_core::round2::SignatureShare<C>> for SignatureShare {
    fn from(s: frost_core::round2::SignatureShare<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::round2::SignatureShare<C>> for SignatureShare {
    fn from(s: &frost_core::round2::SignatureShare<C>) -> Self {
        Self(s.serialize().as_ref().to_vec())
    }
}

impl<C: Ciphersuite> TryFrom<&SignatureShare> for frost_core::round2::SignatureShare<C> {
    type Error = Error;

    fn try_from(value: &SignatureShare) -> Result<Self, Self::Error> {
        let bytes = <<C::Group as Group>::Field as Field>::Serialization::try_from(value.0.clone())
            .map_err(|_| {
                Error::General("Error converting signature share from bytes".to_string())
            })?;
        frost_core::round2::SignatureShare::<C>::deserialize(bytes)
            .map_err(|_| Error::General("Error deserializing signature share".to_string()))
    }
}
