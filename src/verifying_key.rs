use crate::Error;
use frost_core::{Ciphersuite, Group};
use serde::{Deserialize, Serialize};

/// A valid verifying key for Schnorr signatures
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Deserialize, Serialize)]
#[repr(transparent)]
pub struct VerifyingKey(pub Vec<u8>);

impl<C: Ciphersuite> From<frost_core::VerifyingKey<C>> for VerifyingKey {
    fn from(s: frost_core::VerifyingKey<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::VerifyingKey<C>> for VerifyingKey {
    fn from(s: &frost_core::VerifyingKey<C>) -> Self {
        Self(s.serialize().as_ref().to_vec())
    }
}

impl<C: Ciphersuite> TryFrom<&VerifyingKey> for frost_core::VerifyingKey<C> {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        let bytes = <C::Group as Group>::Serialization::try_from(value.0.clone())
            .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))?;
        frost_core::VerifyingKey::<C>::deserialize(bytes)
            .map_err(|_| Error::General("Error deserializing verifying key".to_string()))
    }
}

impl From<curve25519_dalek::edwards::CompressedEdwardsY> for VerifyingKey {
    fn from(s: curve25519_dalek::edwards::CompressedEdwardsY) -> Self {
        Self::from(&s)
    }
}

impl From<&curve25519_dalek::edwards::CompressedEdwardsY> for VerifyingKey {
    fn from(s: &curve25519_dalek::edwards::CompressedEdwardsY) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl From<curve25519_dalek::edwards::EdwardsPoint> for VerifyingKey {
    fn from(s: curve25519_dalek::edwards::EdwardsPoint) -> Self {
        Self::from(&s)
    }
}

impl From<&curve25519_dalek::edwards::EdwardsPoint> for VerifyingKey {
    fn from(s: &curve25519_dalek::edwards::EdwardsPoint) -> Self {
        Self(s.compress().as_bytes().to_vec())
    }
}

impl From<curve25519_dalek::ristretto::CompressedRistretto> for VerifyingKey {
    fn from(s: curve25519_dalek::ristretto::CompressedRistretto) -> Self {
        Self::from(&s)
    }
}

impl From<&curve25519_dalek::ristretto::CompressedRistretto> for VerifyingKey {
    fn from(s: &curve25519_dalek::ristretto::CompressedRistretto) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl From<curve25519_dalek::ristretto::RistrettoPoint> for VerifyingKey {
    fn from(s: curve25519_dalek::ristretto::RistrettoPoint) -> Self {
        Self::from(&s)
    }
}

impl From<&curve25519_dalek::ristretto::RistrettoPoint> for VerifyingKey {
    fn from(s: &curve25519_dalek::ristretto::RistrettoPoint) -> Self {
        Self(s.compress().as_bytes().to_vec())
    }
}

impl From<k256::ProjectivePoint> for VerifyingKey {
    fn from(s: k256::ProjectivePoint) -> Self {
        Self::from(&s)
    }
}

impl From<&k256::ProjectivePoint> for VerifyingKey {
    fn from(s: &k256::ProjectivePoint) -> Self {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        Self(s.to_encoded_point(true).as_bytes().to_vec())
    }
}

impl From<p256::ProjectivePoint> for VerifyingKey {
    fn from(s: p256::ProjectivePoint) -> Self {
        Self::from(&s)
    }
}

impl From<&p256::ProjectivePoint> for VerifyingKey {
    fn from(s: &p256::ProjectivePoint) -> Self {
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        Self(s.to_encoded_point(true).as_bytes().to_vec())
    }
}

impl From<p384::ProjectivePoint> for VerifyingKey {
    fn from(s: p384::ProjectivePoint) -> Self {
        Self::from(&s)
    }
}

impl From<&p384::ProjectivePoint> for VerifyingKey {
    fn from(s: &p384::ProjectivePoint) -> Self {
        use p384::elliptic_curve::sec1::ToEncodedPoint;

        Self(s.to_encoded_point(true).as_bytes().to_vec())
    }
}
