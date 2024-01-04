use super::*;

impl From<k256::Scalar> for SigningShare {
    fn from(s: k256::Scalar) -> Self {
        Self::from(&s)
    }
}

impl From<&k256::Scalar> for SigningShare {
    fn from(s: &k256::Scalar) -> Self {
        Self {
            scheme: Scheme::K256Sha256,
            value: s.to_bytes().to_vec(),
        }
    }
}

impl From<(Scheme, k256::Scalar)> for SigningShare {
    fn from((scheme, s): (Scheme, k256::Scalar)) -> Self {
        Self::from((scheme, &s))
    }
}

impl From<(Scheme, &k256::Scalar)> for SigningShare {
    fn from((scheme, s): (Scheme, &k256::Scalar)) -> Self {
        Self {
            scheme,
            value: s.to_bytes().to_vec(),
        }
    }
}

impl TryFrom<SigningShare> for k256::Scalar {
    type Error = Error;

    fn try_from(value: SigningShare) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&SigningShare> for k256::Scalar {
    type Error = Error;

    fn try_from(value: &SigningShare) -> Result<Self, Self::Error> {
        use k256::elliptic_curve::ff::PrimeField;

        if (value.scheme != Scheme::K256Sha256 && value.scheme != Scheme::K256Taproot) || value.value.len() != 32 {
            return Err(Error::General(
                "Signing share scheme does not match ciphersuite".to_string(),
            ));
        }
        let bytes = k256::FieldBytes::clone_from_slice(&value.value);
        Option::from(k256::Scalar::from_repr(bytes))
            .ok_or(Error::General("Error converting signing share".to_string()))
    }
}

impl From<p256::Scalar> for SigningShare {
    fn from(s: p256::Scalar) -> Self {
        Self::from(&s)
    }
}

impl From<&p256::Scalar> for SigningShare {
    fn from(s: &p256::Scalar) -> Self {
        Self {
            scheme: Scheme::P256Sha256,
            value: s.to_bytes().to_vec(),
        }
    }
}

impl TryFrom<SigningShare> for p256::Scalar {
    type Error = Error;

    fn try_from(value: SigningShare) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&SigningShare> for p256::Scalar {
    type Error = Error;

    fn try_from(value: &SigningShare) -> Result<Self, Self::Error> {
        use p256::elliptic_curve::ff::PrimeField;

        if value.scheme != Scheme::P256Sha256 || value.value.len() != 32 {
            return Err(Error::General(
                "Signing share scheme does not match ciphersuite".to_string(),
            ));
        }
        let bytes = p256::FieldBytes::clone_from_slice(&value.value);
        Option::from(p256::Scalar::from_repr(bytes))
            .ok_or(Error::General("Error converting signing share".to_string()))
    }
}

impl From<p384::Scalar> for SigningShare {
    fn from(s: p384::Scalar) -> Self {
        Self::from(&s)
    }
}

impl From<&p384::Scalar> for SigningShare {
    fn from(s: &p384::Scalar) -> Self {
        Self {
            scheme: Scheme::P384Sha384,
            value: s.to_bytes().to_vec(),
        }
    }
}

impl TryFrom<SigningShare> for p384::Scalar {
    type Error = Error;

    fn try_from(value: SigningShare) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&SigningShare> for p384::Scalar {
    type Error = Error;

    fn try_from(value: &SigningShare) -> Result<Self, Self::Error> {
        use p384::elliptic_curve::ff::PrimeField;

        if value.scheme != Scheme::P384Sha384 || value.value.len() != 48 {
            return Err(Error::General(
                "Signing share scheme does not match ciphersuite".to_string(),
            ));
        }
        let bytes = p384::FieldBytes::clone_from_slice(&value.value);
        Option::from(p384::Scalar::from_repr(bytes))
            .ok_or(Error::General("Error converting signing share".to_string()))
    }
}

impl From<curve25519_dalek::Scalar> for SigningShare {
    fn from(s: curve25519_dalek::Scalar) -> Self {
        Self::from(&s)
    }
}

impl From<&curve25519_dalek::Scalar> for SigningShare {
    fn from(s: &curve25519_dalek::Scalar) -> Self {
        Self {
            scheme: Scheme::Ed25519Sha512,
            value: s.to_bytes().to_vec(),
        }
    }
}

impl TryFrom<SigningShare> for curve25519_dalek::Scalar {
    type Error = Error;

    fn try_from(value: SigningShare) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&SigningShare> for curve25519_dalek::Scalar {
    type Error = Error;

    fn try_from(value: &SigningShare) -> Result<Self, Self::Error> {
        if value.scheme != Scheme::Ed25519Sha512 || value.value.len() != 32 {
            return Err(Error::General(
                "Signing share scheme does not match ciphersuite".to_string(),
            ));
        }
        let bytes = <[u8; 32]>::try_from(value.value.as_slice()).unwrap();
        Option::from(curve25519_dalek::Scalar::from_canonical_bytes(bytes))
            .ok_or(Error::General("Error converting signing share".to_string()))
    }
}

impl From<ed448_goldilocks::Scalar> for SigningShare {
    fn from(s: ed448_goldilocks::Scalar) -> Self {
        Self::from(&s)
    }
}

impl From<&ed448_goldilocks::Scalar> for SigningShare {
    fn from(s: &ed448_goldilocks::Scalar) -> Self {
        Self {
            scheme: Scheme::Ed448Shake256,
            value: s.to_bytes_rfc_8032().to_vec(),
        }
    }
}

impl TryFrom<SigningShare> for ed448_goldilocks::Scalar {
    type Error = Error;

    fn try_from(value: SigningShare) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&SigningShare> for ed448_goldilocks::Scalar {
    type Error = Error;

    fn try_from(value: &SigningShare) -> Result<Self, Self::Error> {
        if value.scheme != Scheme::Ed448Shake256 || value.value.len() != 57 {
            return Err(Error::General(
                "Signing share scheme does not match ciphersuite".to_string(),
            ));
        }
        let bytes = ed448_goldilocks::ScalarBytes::clone_from_slice(value.value.as_slice());
        Option::from(ed448_goldilocks::Scalar::from_canonical_bytes(&bytes))
            .ok_or(Error::General("Error converting signing share".to_string()))
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

impl TryFrom<SigningShare> for vsss_rs::curve25519::WrappedScalar {
    type Error = Error;

    fn try_from(value: SigningShare) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&SigningShare> for vsss_rs::curve25519::WrappedScalar {
    type Error = Error;

    fn try_from(value: &SigningShare) -> Result<Self, Self::Error> {
        let scalar: curve25519_dalek::Scalar = curve25519_dalek::Scalar::try_from(value)?;
        Ok(Self(scalar))
    }
}

impl From<jubjub::Scalar> for SigningShare {
    fn from(value: jubjub::Scalar) -> Self {
        Self::from(&value)
    }
}

impl From<&jubjub::Scalar> for SigningShare {
    fn from(value: &jubjub::Scalar) -> Self {
        Self {
            scheme: Scheme::RedJubjubBlake2b512,
            value: value.to_bytes().to_vec(),
        }
    }
}

impl TryFrom<SigningShare> for jubjub::Scalar {
    type Error = Error;

    fn try_from(value: SigningShare) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&SigningShare> for jubjub::Scalar {
    type Error = Error;

    fn try_from(value: &SigningShare) -> Result<Self, Self::Error> {
        if value.scheme != Scheme::RedJubjubBlake2b512 || value.value.len() != 32 {
            return Err(Error::General(
                "Signing share scheme does not match ciphersuite".to_string(),
            ));
        }
        let bytes = <[u8; 32]>::try_from(value.value.as_slice()).unwrap();
        Option::from(jubjub::Scalar::from_bytes(&bytes))
            .ok_or(Error::General("Error converting signing share".to_string()))
    }
}

