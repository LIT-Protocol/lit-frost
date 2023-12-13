use crate::{Error, Scheme};
use frost_core::{Ciphersuite, Field, Group};
use serde::{
    de::{SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserialize, Deserializer, Serialize, Serializer,
};

/// A secret scalar value representing a signer’s share of the group secret.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub struct SigningShare {
    /// The scheme used to generate the signing share.
    pub scheme: Scheme,
    /// The value of the signing share.
    pub value: Vec<u8>,
}

impl<C: Ciphersuite> From<frost_core::keys::SigningShare<C>> for SigningShare {
    fn from(s: frost_core::keys::SigningShare<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::keys::SigningShare<C>> for SigningShare {
    fn from(s: &frost_core::keys::SigningShare<C>) -> Self {
        let scheme = C::ID.parse().unwrap();
        Self {
            scheme,
            value: s.serialize().as_ref().to_vec(),
        }
    }
}

impl<C: Ciphersuite> TryFrom<&SigningShare> for frost_core::keys::SigningShare<C> {
    type Error = Error;

    fn try_from(value: &SigningShare) -> Result<Self, Self::Error> {
        if value.scheme != C::ID.parse().unwrap() {
            return Err(Error::General(
                "Signing share scheme does not match ciphersuite".to_string(),
            ));
        }
        let bytes =
            <<C::Group as Group>::Field as Field>::Serialization::try_from(value.value.clone())
                .map_err(|_| {
                    Error::General("Error converting signing share from bytes".to_string())
                })?;
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
        Self {
            scheme: Scheme::K256Sha256,
            value: s.to_bytes().to_vec(),
        }
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

impl From<ed448_goldilocks::Scalar> for SigningShare {
    fn from(s: ed448_goldilocks::Scalar) -> Self {
        Self::from(&s)
    }
}

impl From<&ed448_goldilocks::Scalar> for SigningShare {
    fn from(s: &ed448_goldilocks::Scalar) -> Self {
        Self {
            scheme: Scheme::Ed448Shake256,
            value: s.to_bytes().to_vec(),
        }
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

impl Serialize for SigningShare {
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

impl<'de> Deserialize<'de> for SigningShare {
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
            struct SigningShareVisitor;

            impl<'de> Visitor<'de> for SigningShareVisitor {
                type Value = SigningShare;

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
                        Scheme::K256Sha256 => 32,
                        Scheme::P256Sha256 => 32,
                        Scheme::P384Sha384 => 48,
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
                    Ok(SigningShare { scheme, value })
                }
            }

            d.deserialize_seq(SigningShareVisitor)
        }
    }
}
