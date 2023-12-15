use crate::{Error, Scheme};
use frost_core::Ciphersuite;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{self, Display, Formatter};

/// A FROST participant identifier.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Copy, Default)]
pub struct Identifier {
    /// The scheme associated with this identifier.
    pub scheme: Scheme,
    /// The identifier value.
    pub id: u8,
}

impl Display for Identifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "scheme: {}, id: {}", self.scheme, self.id)
    }
}

impl<C: Ciphersuite> From<frost_core::Identifier<C>> for Identifier {
    fn from(s: frost_core::Identifier<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::Identifier<C>> for Identifier {
    fn from(s: &frost_core::Identifier<C>) -> Self {
        match C::ID.parse().unwrap() {
            Scheme::Ed25519Sha512 => Self {
                scheme: Scheme::Ed25519Sha512,
                id: s.serialize().as_ref()[0],
            },
            Scheme::Ed448Shake256 => Self {
                scheme: Scheme::Ed448Shake256,
                id: s.serialize().as_ref()[0],
            },
            Scheme::Ristretto25519Sha512 => Self {
                scheme: Scheme::Ristretto25519Sha512,
                id: s.serialize().as_ref()[0],
            },
            Scheme::K256Sha256 => Self {
                scheme: Scheme::K256Sha256,
                id: s.serialize().as_ref()[31],
            },
            Scheme::P256Sha256 => Self {
                scheme: Scheme::P256Sha256,
                id: s.serialize().as_ref()[31],
            },
            Scheme::P384Sha384 => Self {
                scheme: Scheme::P384Sha384,
                id: s.serialize().as_ref()[47],
            },
            Scheme::RedJubjubBlake2b512 => Self {
                scheme: Scheme::RedJubjubBlake2b512,
                id: s.serialize().as_ref()[0],
            },
            Scheme::Unknown => panic!("Unknown ciphersuite"),
        }
    }
}

impl<C: Ciphersuite> TryFrom<Identifier> for frost_core::Identifier<C> {
    type Error = Error;

    fn try_from(s: Identifier) -> Result<Self, Self::Error> {
        Self::try_from(&s)
    }
}

impl<C: Ciphersuite> TryFrom<&Identifier> for frost_core::Identifier<C> {
    type Error = Error;

    fn try_from(s: &Identifier) -> Result<Self, Self::Error> {
        let scheme = C::ID
            .parse::<Scheme>()
            .map_err(|_| Error::General("Unknown ciphersuite".to_string()))?;
        if scheme == s.scheme {
            Ok(frost_core::Identifier::<C>::try_from(s.id as u16).unwrap())
        } else {
            Err(Error::General("Ciphersuite mismatch".to_string()))
        }
    }
}

impl Serialize for Identifier {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            (self.scheme.to_string(), self.id).serialize(s)
        } else {
            (self.scheme as u8, self.id).serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for Identifier {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (scheme, id) = if d.is_human_readable() {
            let (ty, id) = <(String, u8)>::deserialize(d)?;
            let scheme: Scheme = ty
                .parse()
                .map_err(|e: Error| serde::de::Error::custom(e.to_string()))?;
            (scheme, id)
        } else {
            let (ty, id) = <(u8, u8)>::deserialize(d)?;
            (ty.into(), id)
        };
        if scheme == Scheme::Unknown {
            return Err(serde::de::Error::custom("Unknown ciphersuite"));
        }
        Ok(Self { scheme, id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use rstest::*;

    #[rstest]
    #[case::ed25519(frost_ed25519::Ed25519Sha512, Scheme::Ed25519Sha512)]
    #[case::ed448(frost_ed448::Ed448Shake256, Scheme::Ed448Shake256)]
    #[case::ristretto25519(frost_ristretto255::Ristretto255Sha512, Scheme::Ristretto25519Sha512)]
    #[case::k256(frost_secp256k1::Secp256K1Sha256, Scheme::K256Sha256)]
    #[case::p256(frost_p256::P256Sha256, Scheme::P256Sha256)]
    #[case::p384(frost_p384::P384Sha384, Scheme::P384Sha384)]
    #[case::redjubjub(frost_redjubjub::JubjubBlake2b512, Scheme::RedJubjubBlake2b512)]
    fn convert<C: Ciphersuite>(#[case] _c: C, #[case] scheme: Scheme) {
        let id = Identifier { scheme, id: 1 };
        let frost_id = frost_core::Identifier::<C>::try_from(id).unwrap();
        assert_eq!(id, Identifier::from(frost_id));
    }

    #[rstest]
    #[case::ed25519(Scheme::Ed25519Sha512)]
    #[case::ed448(Scheme::Ed448Shake256)]
    #[case::ristretto25519(Scheme::Ristretto25519Sha512)]
    #[case::k256(Scheme::K256Sha256)]
    #[case::p256(Scheme::P256Sha256)]
    #[case::p384(Scheme::P384Sha384)]
    #[case::redjubjub(Scheme::RedJubjubBlake2b512)]
    fn serialize(#[case] scheme: Scheme) {
        const ITER: usize = 25;
        for _ in 0..ITER {
            let id = Identifier {
                scheme,
                id: rand::rngs::OsRng.gen::<u8>(),
            };
            let res = serde_json::to_string(&id);
            assert!(res.is_ok());
            let serialized = res.unwrap();
            let res = serde_json::from_str(&serialized);
            assert!(res.is_ok());
            let deserialized: Identifier = res.unwrap();
            assert_eq!(id, deserialized);
            let res = serde_bare::to_vec(&id);
            assert!(res.is_ok());
            let serialized = res.unwrap();
            assert_eq!(serialized.len(), 2);
            let res = serde_bare::from_slice(&serialized);
            assert!(res.is_ok());
            let deserialized: Identifier = res.unwrap();
            assert_eq!(id, deserialized);
        }
    }
}
