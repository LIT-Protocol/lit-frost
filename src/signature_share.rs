use crate::{Error, Scheme};
use frost_core::{Ciphersuite, Field, Group};
use serde::{
    de::{SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserialize, Deserializer, Serialize, Serializer,
};

/// A participant’s signature share, which is aggregated with all other signer’s shares into the joint signature.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub struct SignatureShare {
    /// The ciphersuite used to create this signature share.
    pub scheme: Scheme,
    /// The signature share value.
    pub value: Vec<u8>,
}

impl<C: Ciphersuite> From<frost_core::round2::SignatureShare<C>> for SignatureShare {
    fn from(s: frost_core::round2::SignatureShare<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::round2::SignatureShare<C>> for SignatureShare {
    fn from(s: &frost_core::round2::SignatureShare<C>) -> Self {
        let scheme = C::ID.parse().unwrap();
        Self {
            scheme,
            value: s.serialize().as_ref().to_vec(),
        }
    }
}

impl<C: Ciphersuite> TryFrom<&SignatureShare> for frost_core::round2::SignatureShare<C> {
    type Error = Error;

    fn try_from(value: &SignatureShare) -> Result<Self, Self::Error> {
        let scheme = C::ID
            .parse::<Scheme>()
            .map_err(|_| Error::General("Unknown ciphersuite".to_string()))?;
        if scheme != value.scheme {
            return Err(Error::General(
                "Ciphersuite does not match signature share".to_string(),
            ));
        }
        let bytes =
            <<C::Group as Group>::Field as Field>::Serialization::try_from(value.value.clone())
                .map_err(|_| {
                    Error::General("Error converting signature share from bytes".to_string())
                })?;
        frost_core::round2::SignatureShare::<C>::deserialize(bytes)
            .map_err(|_| Error::General("Error deserializing signature share".to_string()))
    }
}

impl Serialize for SignatureShare {
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

impl<'de> Deserialize<'de> for SignatureShare {
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
            struct SignatureShareVisitor;

            impl<'de> Visitor<'de> for SignatureShareVisitor {
                type Value = SignatureShare;

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
                    Ok(SignatureShare { scheme, value })
                }
            }

            d.deserialize_seq(SignatureShareVisitor)
        }
    }
}
