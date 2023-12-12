use crate::Error;
use frost_core::{Ciphersuite, Field, Group};
use serde::{Deserialize, Serialize};

/// A secret scalar value representing a signer’s share of the group secret.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Deserialize, Serialize)]
#[repr(transparent)]
pub struct SigningShare(pub Vec<u8>);

impl<C: Ciphersuite> From<frost_core::keys::SigningShare<C>> for SigningShare {
    fn from(s: frost_core::keys::SigningShare<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::keys::SigningShare<C>> for SigningShare {
    fn from(s: &frost_core::keys::SigningShare<C>) -> Self {
        Self(s.serialize().as_ref().to_vec())
    }
}

impl<C: Ciphersuite> TryFrom<&SigningShare> for frost_core::keys::SigningShare<C> {
    type Error = Error;

    fn try_from(value: &SigningShare) -> Result<Self, Self::Error> {
        let bytes = <<C::Group as Group>::Field as Field>::Serialization::try_from(value.0.clone())
            .map_err(|_| Error::General("Error converting signing share from bytes".to_string()))?;
        frost_core::keys::SigningShare::<C>::deserialize(bytes)
            .map_err(|_| Error::General("Error deserializing signing share".to_string()))
    }
}

impl From<k256::Scalar> for SigningShare {
    fn from(s: k256::Scalar) -> Self {
        Self::from(&s)
    }
}

impl From<&k256::Scalar> for SigningShare {
    fn from(s: &k256::Scalar) -> Self {
        Self(s.to_bytes().to_vec())
    }
}

impl From<p256::Scalar> for SigningShare {
    fn from(s: p256::Scalar) -> Self {
        Self::from(&s)
    }
}

impl From<&p256::Scalar> for SigningShare {
    fn from(s: &p256::Scalar) -> Self {
        Self(s.to_bytes().to_vec())
    }
}

impl From<p384::Scalar> for SigningShare {
    fn from(s: p384::Scalar) -> Self {
        Self::from(&s)
    }
}

impl From<&p384::Scalar> for SigningShare {
    fn from(s: &p384::Scalar) -> Self {
        Self(s.to_bytes().to_vec())
    }
}

impl From<curve25519_dalek::Scalar> for SigningShare {
    fn from(s: curve25519_dalek::Scalar) -> Self {
        Self::from(&s)
    }
}

impl From<&curve25519_dalek::Scalar> for SigningShare {
    fn from(s: &curve25519_dalek::Scalar) -> Self {
        Self(s.to_bytes().to_vec())
    }
}

impl From<ed448_goldilocks::Scalar> for SigningShare {
    fn from(s: ed448_goldilocks::Scalar) -> Self {
        Self::from(&s)
    }
}

impl From<&ed448_goldilocks::Scalar> for SigningShare {
    fn from(s: &ed448_goldilocks::Scalar) -> Self {
        Self(s.to_bytes().to_vec())
    }
}

impl From<vsss_rs::curve25519::WrappedScalar> for SigningShare {
    fn from(s: vsss_rs::curve25519::WrappedScalar) -> Self {
        Self::from(&s)
    }
}

impl From<&vsss_rs::curve25519::WrappedScalar> for SigningShare {
    fn from(s: &vsss_rs::curve25519::WrappedScalar) -> Self {
        Self::from(&s.0)
    }
}