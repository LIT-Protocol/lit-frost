use crate::Error;
use frost_core::{Ciphersuite, Field, Group};
use serde::{Deserialize, Serialize};

/// Comprised of hiding and binding nonces
///
/// Note that [`SigningNonces`] must be used only once for a signing operation;
/// re-using nonces will result in leakage of a signer’s long-lived signing key.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Deserialize, Serialize)]
pub struct SigningNonces {
    pub hiding: Vec<u8>,
    pub binding: Vec<u8>,
}

impl<C: Ciphersuite> From<frost_core::round1::SigningNonces<C>> for SigningNonces {
    fn from(s: frost_core::round1::SigningNonces<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::round1::SigningNonces<C>> for SigningNonces {
    fn from(s: &frost_core::round1::SigningNonces<C>) -> Self {
        Self {
            hiding: s.hiding().serialize().as_ref().to_vec(),
            binding: s.binding().serialize().as_ref().to_vec(),
        }
    }
}

impl<C: Ciphersuite> TryFrom<&SigningNonces> for frost_core::round1::SigningNonces<C> {
    type Error = Error;

    fn try_from(value: &SigningNonces) -> Result<Self, Self::Error> {
        let hiding_bytes =
            <<C::Group as Group>::Field as Field>::Serialization::try_from(value.hiding.to_vec())
                .map_err(|_| Error::General("Error converting hiding nonce to bytes".to_string()))?;
        let binding_bytes =
            <<C::Group as Group>::Field as Field>::Serialization::try_from(value.binding.to_vec())
                .map_err(|_| {
                    Error::General("Error converting binding nonce to bytes".to_string())
                })?;
        let hiding = frost_core::round1::Nonce::<C>::deserialize(hiding_bytes)
            .map_err(|_| Error::General("Error deserializing hiding nonce".to_string()))?;
        let binding = frost_core::round1::Nonce::<C>::deserialize(binding_bytes)
            .map_err(|_| Error::General("Error deserializing binding nonce".to_string()))?;
        let signing_nonces = frost_core::round1::SigningNonces::<C>::from_nonces(hiding, binding);
        Ok(signing_nonces)
    }
}
