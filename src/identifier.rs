use crate::{Error, Scheme};
use frost_core::Ciphersuite;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A FROST participant identifier.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Copy)]
pub struct Identifier {
    /// The scheme associated with this identifier.
    pub scheme: Scheme,
    /// The identifier value.
    pub id: u8,
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

#[test]
fn test_participant_identifier() {
    let id = Identifier {
        scheme: Scheme::P384Sha384,
        id: 1,
    };
    let frost_id = frost_core::Identifier::<frost_p384::P384Sha384>::try_from(id).unwrap();
    assert_eq!(id, Identifier::from(frost_id));
}
