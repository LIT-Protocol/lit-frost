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
    pub scheme: Scheme,
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
