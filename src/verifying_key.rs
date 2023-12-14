use crate::{Error, Scheme};
use frost_core::{Ciphersuite, Group};
use serde::{
    de::{SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserialize, Deserializer, Serialize, Serializer,
};

/// A valid verifying key for Schnorr signatures
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
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

impl Serialize for VerifyingKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            (self.scheme, &self.value[..]).serialize(s)
        } else {
            let mut seq = s.serialize_tuple(self.value.len() + 1)?;
            seq.serialize_element(&(self.scheme as u8))?;
            for b in &self.value {
                seq.serialize_element(b)?;
            }

            seq.end()
        }
    }
}

impl<'de> Deserialize<'de> for VerifyingKey {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if d.is_human_readable() {
            let (ty, value) = <(String, Vec<u8>)>::deserialize(d)?;
            let scheme: Scheme = ty
                .parse()
                .map_err(|e: Error| serde::de::Error::custom(e.to_string()))?;
            Ok(Self { scheme, value })
        } else {
            struct VerifyingKeyVisitor;

            impl<'de> Visitor<'de> for VerifyingKeyVisitor {
                type Value = VerifyingKey;

                fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                    formatter.write_str("a tuple of (u8, Vec<u8>)")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>,
                {
                    let scheme = seq
                        .next_element::<u8>()?
                        .ok_or_else(|| serde::de::Error::custom("Missing scheme"))?;
                    let scheme = Scheme::from(scheme);
                    let length = match scheme {
                        Scheme::Unknown => {
                            return Err(serde::de::Error::custom("Unknown ciphersuite"))
                        }
                        Scheme::Ed25519Sha512 => 32,
                        Scheme::Ed448Shake256 => 57,
                        Scheme::Ristretto25519Sha512 => 32,
                        Scheme::K256Sha256 => 33,
                        Scheme::P256Sha256 => 33,
                        Scheme::P384Sha384 => 49,
                        Scheme::RedJubjubBlake2b512 => 32,
                    };
                    let mut value = Vec::new();
                    while let Some(b) = seq.next_element::<u8>()? {
                        value.push(b);
                        if value.len() == length {
                            break;
                        }
                    }
                    if value.len() != length {
                        return Err(serde::de::Error::custom("Invalid length"));
                    }
                    Ok(VerifyingKey { scheme, value })
                }
            }

            d.deserialize_seq(VerifyingKeyVisitor)
        }
    }
}
