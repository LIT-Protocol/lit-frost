use crate::Error;
use frost_core::Ciphersuite;
use serde::{Deserialize, Serialize};

/// A Schnorr signature
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Deserialize, Serialize)]
#[repr(transparent)]
pub struct Signature(pub Vec<u8>);

impl<C: Ciphersuite> From<frost_core::Signature<C>> for Signature {
    fn from(s: frost_core::Signature<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::Signature<C>> for Signature {
    fn from(s: &frost_core::Signature<C>) -> Self {
        Self(s.serialize().as_ref().to_vec())
    }
}

impl<C: Ciphersuite> TryFrom<&Signature> for frost_core::Signature<C> {
    type Error = Error;

    fn try_from(value: &Signature) -> Result<Self, Self::Error> {
        let bytes = C::SignatureSerialization::try_from(value.0.clone())
            .map_err(|_| Error::General("Error converting signature from bytes".to_string()))?;
        frost_core::Signature::<C>::deserialize(bytes)
            .map_err(|_| Error::General("Error deserializing signature".to_string()))
    }
}
