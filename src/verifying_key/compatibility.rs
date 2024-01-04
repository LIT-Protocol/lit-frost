use super::*;

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

impl From<(Scheme, k256::ProjectivePoint)> for VerifyingKey {
    fn from(s: (Scheme, k256::ProjectivePoint)) -> Self {
        Self::from((s.0, &s.1))
    }
}

impl From<(Scheme, &k256::ProjectivePoint)> for VerifyingKey {
    fn from(s: (Scheme, &k256::ProjectivePoint)) -> Self {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        Self {
            scheme: s.0,
            value: s.1.to_encoded_point(true).as_bytes().to_vec(),
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
        if (scheme != Scheme::K256Sha256 && scheme != Scheme::K256Taproot) || value.value.len() != 33 {
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

impl From<(Scheme, k256::AffinePoint)> for VerifyingKey {
    fn from(s: (Scheme, k256::AffinePoint)) -> Self {
        Self::from((s.0, &s.1))
    }
}

impl From<(Scheme, &k256::AffinePoint)> for VerifyingKey {
    fn from(s: (Scheme, &k256::AffinePoint)) -> Self {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        Self {
            scheme: s.0,
            value: s.1.to_encoded_point(true).as_bytes().to_vec(),
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
        if (scheme != Scheme::K256Sha256 && scheme != Scheme::K256Taproot) || value.value.len() != 33 {
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

impl From<k256::schnorr::VerifyingKey> for VerifyingKey {
    fn from(s: k256::schnorr::VerifyingKey) -> Self {
        Self::from(&s)
    }
}

impl From<&k256::schnorr::VerifyingKey> for VerifyingKey {
    fn from(s: &k256::schnorr::VerifyingKey) -> Self {
        Self {
            scheme: Scheme::K256Taproot,
            value: s.to_bytes().to_vec(),
        }
    }
}

impl TryFrom<VerifyingKey> for k256::schnorr::VerifyingKey {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for k256::schnorr::VerifyingKey {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        let scheme = value.scheme;
        if scheme != Scheme::K256Taproot {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        match value.value.len() {
            32 => {
                k256::schnorr::VerifyingKey::from_bytes(value.value.as_slice())
                    .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))
            },
            33 => {
                k256::schnorr::VerifyingKey::from_bytes(&value.value[1..])
                    .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))
            },
            _ => {
                Err(Error::General(
                    "Error converting verifying key from bytes".to_string(),
                ))
            }
        }
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

impl From<ed448_goldilocks::CompressedEdwardsY> for VerifyingKey {
    fn from(s: ed448_goldilocks::CompressedEdwardsY) -> Self {
        Self::from(&s)
    }
}

impl From<&ed448_goldilocks::CompressedEdwardsY> for VerifyingKey {
    fn from(s: &ed448_goldilocks::CompressedEdwardsY) -> Self {
        Self {
            scheme: Scheme::Ed448Shake256,
            value: s.0.to_vec(),
        }
    }
}

impl TryFrom<VerifyingKey> for ed448_goldilocks::CompressedEdwardsY {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for ed448_goldilocks::CompressedEdwardsY {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        if value.scheme != Scheme::Ed448Shake256 || value.value.len() != 57 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Self::try_from(&value.value[..])
            .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))
    }
}

impl From<ed448_goldilocks::EdwardsPoint> for VerifyingKey {
    fn from(s: ed448_goldilocks::EdwardsPoint) -> Self {
        Self::from(&s)
    }
}

impl From<&ed448_goldilocks::EdwardsPoint> for VerifyingKey {
    fn from(s: &ed448_goldilocks::EdwardsPoint) -> Self {
        Self {
            scheme: Scheme::Ed448Shake256,
            value: s.compress().0.to_vec(),
        }
    }
}

impl TryFrom<VerifyingKey> for ed448_goldilocks::EdwardsPoint {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&VerifyingKey> for ed448_goldilocks::EdwardsPoint {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        if value.scheme != Scheme::Ed448Shake256 || value.value.len() != 57 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        Self::try_from(&value.value[..])
            .map_err(|_| Error::General("Error converting verifying key from bytes".to_string()))
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

impl<S: reddsa::SigType> From<&reddsa::VerificationKey<S>> for VerifyingKey {
    fn from(s: &reddsa::VerificationKey<S>) -> Self {
        Self::from(*s)
    }
}

impl<S: reddsa::SigType> From<reddsa::VerificationKey<S>> for VerifyingKey {
    fn from(s: reddsa::VerificationKey<S>) -> Self {
        let bytes: [u8; 32] = s.into();
        Self {
            scheme: Scheme::RedJubjubBlake2b512,
            value: bytes.to_vec()
        }
    }
}

impl<S: reddsa::SigType> TryFrom<VerifyingKey> for reddsa::VerificationKey<S> {
    type Error = Error;

    fn try_from(value: VerifyingKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl<S: reddsa::SigType> TryFrom<&VerifyingKey> for reddsa::VerificationKey<S> {
    type Error = Error;

    fn try_from(value: &VerifyingKey) -> Result<Self, Self::Error> {
        let scheme = value.scheme;
        if scheme != Scheme::RedJubjubBlake2b512 || value.value.len() != 32 {
            return Err(Error::General(
                "Ciphersuite does not match verifying key".to_string(),
            ));
        }
        let bytes = <[u8; 32]>::try_from(value.value.as_slice()).unwrap();
        Ok(bytes.try_into()?)
    }
}