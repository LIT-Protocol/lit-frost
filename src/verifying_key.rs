use crate::{Error, Scheme};
use frost_core::{Ciphersuite, Group};

/// A valid verifying key for Schnorr signatures
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Default)]
pub struct VerifyingKey {
    /// The scheme used by this verifying key
    pub scheme: Scheme,
    /// The value of the verifying key
    pub value: Vec<u8>,
}

impl<C: Ciphersuite> From<frost_core::VerifyingKey<C>> for VerifyingKey {
    fn from(s: frost_core::VerifyingKey<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::VerifyingKey<C>> for VerifyingKey {
    fn from(s: &frost_core::VerifyingKey<C>) -> Self {
        let value = s.serialize().as_ref().to_vec();
        let scheme = C::ID.parse::<Scheme>().unwrap();
        Self { scheme, value }
    }
}

impl<C: Ciphersuite> TryFrom<&VerifyingKey> for frost_core::VerifyingKey<C> {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        let scheme = C::ID
            .parse::<Scheme>()
            .map_err(|_| Error::General("Unknown ciphersuite".to_string()))?;
        if scheme != value.scheme {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        let bytes = <C::Group as Group>::Serialization::try_from(value.value.clone())
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
        Self {
            scheme: Scheme::Ed25519Sha512,
            value: s.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<VerifyingKey> for curve25519_dalek::edwards::CompressedEdwardsY {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for curve25519_dalek::edwards::CompressedEdwardsY {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        if value.scheme != Scheme::Ed25519Sha512 || value.value.len() != 32 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&value.value)
            .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))
    }
}

impl From<curve25519_dalek::edwards::EdwardsPoint> for VerifyingKey {
    fn from(s: curve25519_dalek::edwards::EdwardsPoint) -> Self {
        Self::from(&s)
    }
}

impl From<&curve25519_dalek::edwards::EdwardsPoint> for VerifyingKey {
    fn from(s: &curve25519_dalek::edwards::EdwardsPoint) -> Self {
        Self {
            scheme: Scheme::Ed25519Sha512,
            value: s.compress().as_bytes().to_vec(),
        }
    }
}

impl TryFrom<VerifyingKey> for curve25519_dalek::edwards::EdwardsPoint {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for curve25519_dalek::edwards::EdwardsPoint {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        let pt = curve25519_dalek::edwards::CompressedEdwardsY::try_from(value)?;
        pt.decompress()
            .ok_or_else(|| Error::General("Error converting verifying key from bytes".to_string()))
    }
}

impl From<curve25519_dalek::ristretto::CompressedRistretto> for VerifyingKey {
    fn from(s: curve25519_dalek::ristretto::CompressedRistretto) -> Self {
        Self::from(&s)
    }
}

impl From<&curve25519_dalek::ristretto::CompressedRistretto> for VerifyingKey {
    fn from(s: &curve25519_dalek::ristretto::CompressedRistretto) -> Self {
        Self {
            scheme: Scheme::Ristretto25519Sha512,
            value: s.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<VerifyingKey> for curve25519_dalek::ristretto::CompressedRistretto {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for curve25519_dalek::ristretto::CompressedRistretto {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        if value.scheme != Scheme::Ristretto25519Sha512 || value.value.len() != 32 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        curve25519_dalek::ristretto::CompressedRistretto::from_slice(&value.value)
            .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))
    }
}

impl From<curve25519_dalek::ristretto::RistrettoPoint> for VerifyingKey {
    fn from(s: curve25519_dalek::ristretto::RistrettoPoint) -> Self {
        Self::from(&s)
    }
}

impl From<&curve25519_dalek::ristretto::RistrettoPoint> for VerifyingKey {
    fn from(s: &curve25519_dalek::ristretto::RistrettoPoint) -> Self {
        Self {
            scheme: Scheme::Ristretto25519Sha512,
            value: s.compress().as_bytes().to_vec(),
        }
    }
}

impl TryFrom<VerifyingKey> for curve25519_dalek::ristretto::RistrettoPoint {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for curve25519_dalek::ristretto::RistrettoPoint {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        let pt = curve25519_dalek::ristretto::CompressedRistretto::try_from(value)?;
        pt.decompress()
            .ok_or_else(|| Error::General("Error converting verifying key from bytes".to_string()))
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

        Self {
            scheme: Scheme::K256Sha256,
            value: s.to_encoded_point(true).as_bytes().to_vec(),
        }
    }
}

impl TryFrom<VerifyingKey> for k256::ProjectivePoint {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for k256::ProjectivePoint {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        use k256::elliptic_curve::sec1::FromEncodedPoint;

        let scheme = value.scheme;
        if scheme != Scheme::K256Sha256 || value.value.len() != 33 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        let pt = k256::elliptic_curve::sec1::EncodedPoint::<k256::Secp256k1>::from_bytes(
            &value.value,
        )
        .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))?;
        Option::from(k256::ProjectivePoint::from_encoded_point(&pt))
            .ok_or_else(|| Error::General("Error converting verifying key from bytes".to_string()))
    }
}

impl From<k256::AffinePoint> for VerifyingKey {
    fn from(s: k256::AffinePoint) -> Self {
        Self::from(&s)
    }
}

impl From<&k256::AffinePoint> for VerifyingKey {
    fn from(s: &k256::AffinePoint) -> Self {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        Self {
            scheme: Scheme::K256Sha256,
            value: s.to_encoded_point(true).as_bytes().to_vec(),
        }
    }
}

impl TryFrom<VerifyingKey> for k256::AffinePoint {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for k256::AffinePoint {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        use k256::elliptic_curve::sec1::FromEncodedPoint;

        let scheme = value.scheme;
        if scheme != Scheme::K256Sha256 || value.value.len() != 33 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        let pt = k256::elliptic_curve::sec1::EncodedPoint::<k256::Secp256k1>::from_bytes(
            &value.value,
        )
        .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))?;
        Option::from(k256::AffinePoint::from_encoded_point(&pt))
            .ok_or_else(|| Error::General("Error converting verifying key from bytes".to_string()))
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

        Self {
            scheme: Scheme::P256Sha256,
            value: s.to_encoded_point(true).as_bytes().to_vec(),
        }
    }
}

impl TryFrom<VerifyingKey> for p256::ProjectivePoint {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for p256::ProjectivePoint {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        use p256::elliptic_curve::sec1::FromEncodedPoint;

        if value.scheme != Scheme::P256Sha256 || value.value.len() != 33 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        let pt =
            p256::elliptic_curve::sec1::EncodedPoint::<p256::NistP256>::from_bytes(&value.value)
                .map_err(|_| {
                    Error::General("Error converting verifying key from bytes".to_string())
                })?;
        Option::from(p256::ProjectivePoint::from_encoded_point(&pt))
            .ok_or_else(|| Error::General("Error converting verifying key from bytes".to_string()))
    }
}

impl From<p256::AffinePoint> for VerifyingKey {
    fn from(s: p256::AffinePoint) -> Self {
        Self::from(&s)
    }
}

impl From<&p256::AffinePoint> for VerifyingKey {
    fn from(s: &p256::AffinePoint) -> Self {
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        Self {
            scheme: Scheme::P256Sha256,
            value: s.to_encoded_point(true).as_bytes().to_vec(),
        }
    }
}

impl TryFrom<VerifyingKey> for p256::AffinePoint {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for p256::AffinePoint {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        use p256::elliptic_curve::sec1::FromEncodedPoint;

        let scheme = value.scheme;
        if scheme != Scheme::P256Sha256 || value.value.len() != 33 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        let pt =
            p256::elliptic_curve::sec1::EncodedPoint::<p256::NistP256>::from_bytes(&value.value)
                .map_err(|_| {
                    Error::General("Error converting verifying key from bytes".to_string())
                })?;
        Option::from(p256::AffinePoint::from_encoded_point(&pt))
            .ok_or_else(|| Error::General("Error converting verifying key from bytes".to_string()))
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

        Self {
            scheme: Scheme::P384Sha384,
            value: s.to_encoded_point(true).as_bytes().to_vec(),
        }
    }
}

impl TryFrom<VerifyingKey> for p384::ProjectivePoint {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for p384::ProjectivePoint {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        use p384::elliptic_curve::sec1::FromEncodedPoint;

        let scheme = value.scheme;
        if scheme != Scheme::P384Sha384 || value.value.len() != 49 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        let pt =
            p384::elliptic_curve::sec1::EncodedPoint::<p384::NistP384>::from_bytes(&value.value)
                .map_err(|_| {
                    Error::General("Error converting verifying key from bytes".to_string())
                })?;
        Option::from(p384::ProjectivePoint::from_encoded_point(&pt))
            .ok_or_else(|| Error::General("Error converting verifying key from bytes".to_string()))
    }
}

impl From<p384::AffinePoint> for VerifyingKey {
    fn from(s: p384::AffinePoint) -> Self {
        Self::from(&s)
    }
}

impl From<&p384::AffinePoint> for VerifyingKey {
    fn from(s: &p384::AffinePoint) -> Self {
        use p384::elliptic_curve::sec1::ToEncodedPoint;

        Self {
            scheme: Scheme::P384Sha384,
            value: s.to_encoded_point(true).as_bytes().to_vec(),
        }
    }
}

impl TryFrom<VerifyingKey> for p384::AffinePoint {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for p384::AffinePoint {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        use p384::elliptic_curve::sec1::FromEncodedPoint;

        let scheme = value.scheme;
        if scheme != Scheme::P384Sha384 || value.value.len() != 49 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        let pt =
            p384::elliptic_curve::sec1::EncodedPoint::<p384::NistP384>::from_bytes(&value.value)
                .map_err(|_| {
                    Error::General("Error converting verifying key from bytes".to_string())
                })?;
        Option::from(p384::AffinePoint::from_encoded_point(&pt))
            .ok_or_else(|| Error::General("Error converting verifying key from bytes".to_string()))
    }
}

impl From<ed448_goldilocks::curve::edwards::CompressedEdwardsY> for VerifyingKey {
    fn from(s: ed448_goldilocks::curve::edwards::CompressedEdwardsY) -> Self {
        Self::from(&s)
    }
}

impl From<&ed448_goldilocks::curve::edwards::CompressedEdwardsY> for VerifyingKey {
    fn from(s: &ed448_goldilocks::curve::edwards::CompressedEdwardsY) -> Self {
        Self {
            scheme: Scheme::Ed448Shake256,
            value: s.0.to_vec(),
        }
    }
}

impl TryFrom<VerifyingKey> for ed448_goldilocks::curve::edwards::CompressedEdwardsY {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for ed448_goldilocks::curve::edwards::CompressedEdwardsY {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        if value.scheme != Scheme::Ed448Shake256 || value.value.len() != 57 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        let mut bytes = [0u8; 57];
        bytes.copy_from_slice(&value.value);
        let pt = ed448_goldilocks::curve::edwards::CompressedEdwardsY(bytes);
        let _ = pt.decompress().ok_or(Error::General(
            "Error converting verifying key from bytes".to_string(),
        ))?;
        Ok(pt)
    }
}

impl From<ed448_goldilocks::curve::edwards::ExtendedPoint> for VerifyingKey {
    fn from(s: ed448_goldilocks::curve::edwards::ExtendedPoint) -> Self {
        Self::from(&s)
    }
}

impl From<&ed448_goldilocks::curve::edwards::ExtendedPoint> for VerifyingKey {
    fn from(s: &ed448_goldilocks::curve::edwards::ExtendedPoint) -> Self {
        Self {
            scheme: Scheme::Ed448Shake256,
            value: s.compress().0.to_vec(),
        }
    }
}

impl TryFrom<VerifyingKey> for ed448_goldilocks::curve::edwards::ExtendedPoint {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for ed448_goldilocks::curve::edwards::ExtendedPoint {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        if value.scheme != Scheme::Ed448Shake256 || value.value.len() != 57 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        let mut bytes = [0u8; 57];
        bytes.copy_from_slice(&value.value);
        let pt = ed448_goldilocks::curve::edwards::CompressedEdwardsY(bytes);
        pt.decompress().ok_or(Error::General(
            "Error converting verifying key from bytes".to_string(),
        ))
    }
}

impl From<jubjub::ExtendedPoint> for VerifyingKey {
    fn from(s: jubjub::ExtendedPoint) -> Self {
        Self::from(&s)
    }
}

impl From<&jubjub::ExtendedPoint> for VerifyingKey {
    fn from(s: &jubjub::ExtendedPoint) -> Self {
        use jubjub::group::GroupEncoding;

        Self {
            scheme: Scheme::RedJubjubBlake2b512,
            value: s.to_bytes().to_vec(),
        }
    }
}

impl TryFrom<VerifyingKey> for jubjub::ExtendedPoint {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for jubjub::ExtendedPoint {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        let pt = jubjub::AffinePoint::try_from(value)?;
        Ok(pt.into())
    }
}

impl From<jubjub::AffinePoint> for VerifyingKey {
    fn from(s: jubjub::AffinePoint) -> Self {
        Self::from(&s)
    }
}

impl From<&jubjub::AffinePoint> for VerifyingKey {
    fn from(s: &jubjub::AffinePoint) -> Self {
        Self {
            scheme: Scheme::RedJubjubBlake2b512,
            value: s.to_bytes().to_vec(),
        }
    }
}

impl TryFrom<VerifyingKey> for jubjub::AffinePoint {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for jubjub::AffinePoint {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        let scheme = value.scheme;
        if scheme != Scheme::RedJubjubBlake2b512 || value.value.len() != 32 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        let bytes = <[u8; 32]>::try_from(value.value.as_slice()).unwrap();
        Option::<jubjub::AffinePoint>::from(jubjub::AffinePoint::from_bytes(bytes)).ok_or(
            Error::General("Error converting verifying key from bytes".to_string()),
        )
    }
}

impl From<jubjub::SubgroupPoint> for VerifyingKey {
    fn from(s: jubjub::SubgroupPoint) -> Self {
        Self::from(&s)
    }
}

impl From<&jubjub::SubgroupPoint> for VerifyingKey {
    fn from(s: &jubjub::SubgroupPoint) -> Self {
        use jubjub::group::GroupEncoding;

        Self {
            scheme: Scheme::RedJubjubBlake2b512,
            value: s.to_bytes().to_vec(),
        }
    }
}

impl TryFrom<VerifyingKey> for jubjub::SubgroupPoint {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for jubjub::SubgroupPoint {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        use jubjub::group::GroupEncoding;

        let scheme = value.scheme;
        if scheme != Scheme::RedJubjubBlake2b512 || value.value.len() != 32 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        let bytes = <[u8; 32]>::try_from(value.value.as_slice()).unwrap();
        Option::<jubjub::SubgroupPoint>::from(jubjub::SubgroupPoint::from_bytes(&bytes)).ok_or(
            Error::General("Error converting verifying key from bytes".to_string()),
        )
    }
}

impl From<vsss_rs::curve25519::WrappedEdwards> for VerifyingKey {
    fn from(s: vsss_rs::curve25519::WrappedEdwards) -> Self {
        Self::from(&s)
    }
}

impl From<&vsss_rs::curve25519::WrappedEdwards> for VerifyingKey {
    fn from(s: &vsss_rs::curve25519::WrappedEdwards) -> Self {
        Self::from(&s.0)
    }
}

impl TryFrom<VerifyingKey> for vsss_rs::curve25519::WrappedEdwards {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for vsss_rs::curve25519::WrappedEdwards {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        let pt = curve25519_dalek::edwards::EdwardsPoint::try_from(value)?;
        Ok(Self(pt))
    }
}

impl From<vsss_rs::curve25519::WrappedRistretto> for VerifyingKey {
    fn from(s: vsss_rs::curve25519::WrappedRistretto) -> Self {
        Self::from(&s)
    }
}

impl From<&vsss_rs::curve25519::WrappedRistretto> for VerifyingKey {
    fn from(s: &vsss_rs::curve25519::WrappedRistretto) -> Self {
        Self::from(&s.0)
    }
}

impl TryFrom<VerifyingKey> for vsss_rs::curve25519::WrappedRistretto {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for vsss_rs::curve25519::WrappedRistretto {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        let pt = curve25519_dalek::ristretto::RistrettoPoint::try_from(value)?;
        Ok(Self(pt))
    }
}

serde_impl!(VerifyingKey, compressed_point_len, 58);
display_impl!(VerifyingKey);

impl VerifyingKey {
    is_identity_impl!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_redjubjub::frost;
    use rstest::*;

    #[rstest]
    #[case::ed25519(frost_ed25519::Ed25519Sha512, Scheme::Ed25519Sha512)]
    #[case::ed448(frost_ed448::Ed448Shake256, Scheme::Ed448Shake256)]
    #[case::ristretto25519(frost_ristretto255::Ristretto255Sha512, Scheme::Ristretto25519Sha512)]
    #[case::k256(frost_secp256k1::Secp256K1Sha256, Scheme::K256Sha256)]
    #[case::p256(frost_p256::P256Sha256, Scheme::P256Sha256)]
    #[case::p384(frost_p384::P384Sha384, Scheme::P384Sha384)]
    #[case::redjubjub(frost_redjubjub::JubjubBlake2b512, Scheme::RedJubjubBlake2b512)]
    fn convert_1<C: Ciphersuite>(#[case] _c: C, #[case] scheme: Scheme) {
        let value = frost_core::VerifyingKey::<C>::new(C::Group::generator());
        let vk = VerifyingKey::from(&value);
        assert_eq!(vk.scheme, scheme);
        assert_eq!(vk.value.len(), scheme.compressed_point_len().unwrap());
        let res = frost::VerifyingKey::<C>::try_from(&vk);
        assert!(res.is_ok());
        let vk2 = res.unwrap();
        assert_eq!(vk2, value);
    }

    #[test]
    fn convert_k256() {
        const SCHEME: Scheme = Scheme::K256Sha256;

        let value = k256::ProjectivePoint::GENERATOR;
        let vk = VerifyingKey::from(&value);
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = k256::ProjectivePoint::try_from(&vk);
        assert!(res.is_ok());
        let vk2 = res.unwrap();
        assert_eq!(vk2, value);

        let value = k256::AffinePoint::GENERATOR;
        let vk = VerifyingKey::from(&value);
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = k256::AffinePoint::try_from(&vk);
        assert!(res.is_ok());
    }

    #[test]
    fn convert_p256() {
        const SCHEME: Scheme = Scheme::P256Sha256;

        let value = p256::ProjectivePoint::GENERATOR;
        let vk = VerifyingKey::from(&value);
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = p256::ProjectivePoint::try_from(&vk);
        assert!(res.is_ok());
        let vk2 = res.unwrap();
        assert_eq!(vk2, value);

        let value = p256::AffinePoint::GENERATOR;
        let vk = VerifyingKey::from(&value);
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = p256::AffinePoint::try_from(&vk);
        assert!(res.is_ok());
    }

    #[test]
    fn convert_p384() {
        const SCHEME: Scheme = Scheme::P384Sha384;

        let value = p384::ProjectivePoint::GENERATOR;
        let vk = VerifyingKey::from(&value);
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = p384::ProjectivePoint::try_from(&vk);
        assert!(res.is_ok());
        let vk2 = res.unwrap();
        assert_eq!(vk2, value);

        let value = p384::AffinePoint::GENERATOR;
        let vk = VerifyingKey::from(&value);
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = p384::AffinePoint::try_from(&vk);
        assert!(res.is_ok());
    }

    #[test]
    fn convert_ed25519() {
        const SCHEME: Scheme = Scheme::Ed25519Sha512;

        let value = curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        let vk = VerifyingKey::from(&value);
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = curve25519_dalek::EdwardsPoint::try_from(&vk);
        assert!(res.is_ok());
        let vk2 = res.unwrap();
        assert_eq!(vk2, value);

        let value = curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED;
        let vk = VerifyingKey::from(&value);
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = curve25519_dalek::edwards::CompressedEdwardsY::try_from(&vk);
        assert!(res.is_ok());
    }

    #[test]
    fn convert_ristretto25519() {
        const SCHEME: Scheme = Scheme::Ristretto25519Sha512;

        let value = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        let vk = VerifyingKey::from(&value);
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = curve25519_dalek::RistrettoPoint::try_from(&vk);
        assert!(res.is_ok());
        let vk2 = res.unwrap();
        assert_eq!(vk2, value);

        let value = curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
        let vk = VerifyingKey::from(&value);
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = curve25519_dalek::ristretto::CompressedRistretto::try_from(&vk);
        assert!(res.is_ok());
    }

    #[test]
    fn convert_ed448() {
        const SCHEME: Scheme = Scheme::Ed448Shake256;

        let value = ed448_goldilocks::constants::GOLDILOCKS_BASE_POINT;
        let vk = VerifyingKey::from(&value);
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = ed448_goldilocks::curve::edwards::ExtendedPoint::try_from(&vk);
        assert!(res.is_ok());
        let vk2 = res.unwrap();
        assert_eq!(vk2, value);

        let value = ed448_goldilocks::constants::GOLDILOCKS_BASE_POINT.compress();
        let vk = VerifyingKey::from(&value);
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = ed448_goldilocks::curve::edwards::CompressedEdwardsY::try_from(&vk);
        assert!(res.is_ok());
    }

    #[test]
    fn convert_redjubjub() {
        use group::{cofactor::CofactorCurveAffine, Group};

        const SCHEME: Scheme = Scheme::RedJubjubBlake2b512;

        let value = jubjub::ExtendedPoint::generator();
        let vk = VerifyingKey::from(&value);
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = jubjub::ExtendedPoint::try_from(&vk);
        assert!(res.is_ok());
        let vk2 = res.unwrap();
        assert_eq!(vk2, value);

        let value = jubjub::AffinePoint::generator();
        let vk = VerifyingKey::from(&value);
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = jubjub::AffinePoint::try_from(&vk);
        assert!(res.is_ok());

        let value = jubjub::SubgroupPoint::generator();
        let vk = VerifyingKey::from(&value);
        assert_eq!(vk.scheme, SCHEME);
        assert_eq!(vk.value.len(), SCHEME.compressed_point_len().unwrap());
        let res = jubjub::SubgroupPoint::try_from(&vk);
        assert!(res.is_ok());
    }

    #[rstest]
    #[case::ed25519(frost_ed25519::Ed25519Sha512, Scheme::Ed25519Sha512)]
    #[case::ed448(frost_ed448::Ed448Shake256, Scheme::Ed448Shake256)]
    #[case::ristretto25519(frost_ristretto255::Ristretto255Sha512, Scheme::Ristretto25519Sha512)]
    #[case::k256(frost_secp256k1::Secp256K1Sha256, Scheme::K256Sha256)]
    #[case::p256(frost_p256::P256Sha256, Scheme::P256Sha256)]
    #[case::p384(frost_p384::P384Sha384, Scheme::P384Sha384)]
    #[case::redjubjub(frost_redjubjub::JubjubBlake2b512, Scheme::RedJubjubBlake2b512)]
    fn serialize<C: Ciphersuite>(#[case] _c: C, #[case] scheme: Scheme) {
        use frost_core::Field;

        const ITER: usize = 25;

        let mut rng = rand::rngs::OsRng;

        for _ in 0..ITER {
            let pt = C::Group::generator()
                * <<<C as Ciphersuite>::Group as Group>::Field as Field>::random(&mut rng);
            let vk = frost_core::VerifyingKey::<C>::new(pt);
            let vk2 = VerifyingKey::from(&vk);
            assert_eq!(vk2.scheme, scheme);
            assert_eq!(vk2.value.len(), scheme.compressed_point_len().unwrap());
            let res = serde_json::to_string(&vk2);
            assert!(res.is_ok());
            let serialized = res.unwrap();
            let res = serde_json::from_str::<VerifyingKey>(&serialized);
            assert!(res.is_ok());
            let vk3 = res.unwrap();
            assert_eq!(vk2, vk3);

            let res = serde_bare::to_vec(&vk2);
            assert!(res.is_ok());
            let serialized = res.unwrap();
            assert_eq!(serialized.len(), scheme.compressed_point_len().unwrap() + 1);
            let res = serde_bare::from_slice::<VerifyingKey>(&serialized);
            assert!(res.is_ok());
            let vk3 = res.unwrap();
            assert_eq!(vk2, vk3);
        }
    }
}
