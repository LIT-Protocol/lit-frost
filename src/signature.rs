use crate::{Error, Scheme};
use frost_core::Ciphersuite;

/// A Schnorr signature
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub struct Signature {
    /// The signature scheme
    pub scheme: Scheme,
    /// The signature value
    pub value: Vec<u8>,
}

impl<C: Ciphersuite> From<frost_core::Signature<C>> for Signature {
    fn from(s: frost_core::Signature<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::Signature<C>> for Signature {
    fn from(s: &frost_core::Signature<C>) -> Self {
        let scheme = C::ID.parse().unwrap();
        Self {
            scheme,
            value: s.serialize().as_ref().to_vec(),
        }
    }
}

impl<C: Ciphersuite> TryFrom<&Signature> for frost_core::Signature<C> {
    type Error = Error;

    fn try_from(value: &Signature) -> Result<Self, Self::Error> {
        let scheme = C::ID
            .parse::<Scheme>()
            .map_err(|_| Error::General("Unknown ciphersuite".to_string()))?;
        if scheme != value.scheme {
            return Err(Error::General(
                "Ciphersuite does not match signature".to_string(),
            ));
        }
        let bytes = C::SignatureSerialization::try_from(value.value.clone())
            .map_err(|_| Error::General("Error converting signature from bytes".to_string()))?;
        frost_core::Signature::<C>::deserialize(bytes)
            .map_err(|_| Error::General("Error deserializing signature".to_string()))
    }
}

serde_impl!(Signature, signature_len, 115);
display_impl!(Signature);
