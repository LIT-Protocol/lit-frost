use crate::{Error, Scheme};
use frost_core::Ciphersuite;
use serde::{
    de::{SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserialize, Deserializer, Serialize, Serializer,
};

/// Published by each participant in the first round of the signing protocol.
///
/// This step can be batched using Scheme::pregenerate_signing_nonces.
/// Each [`SigningCommitments`] can be used for exactly one signature.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub struct SigningCommitments {
    /// The ciphersuite used for this signing commitment.
    pub scheme: Scheme,
    /// The serialized signing commitment.
    pub value: Vec<u8>,
}

impl<C: Ciphersuite> From<frost_core::round1::SigningCommitments<C>> for SigningCommitments {
    fn from(s: frost_core::round1::SigningCommitments<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::round1::SigningCommitments<C>> for SigningCommitments {
    fn from(s: &frost_core::round1::SigningCommitments<C>) -> Self {
        let scheme = C::ID.parse().unwrap();
        Self {
            scheme,
            value: s.serialize().unwrap(),
        }
    }
}

impl<C: Ciphersuite> TryFrom<&SigningCommitments> for frost_core::round1::SigningCommitments<C> {
    type Error = Error;

    fn try_from(value: &SigningCommitments) -> Result<Self, Self::Error> {
        if value.scheme != C::ID.parse().unwrap() {
            return Err(Error::General(
                "Signing commitment scheme does not match ciphersuite".to_string(),
            ));
        }
        frost_core::round1::SigningCommitments::<C>::deserialize(value.value.as_slice())
            .map_err(|_| Error::General("Error deserializing signing commitment".to_string()))
    }
}

impl Serialize for SigningCommitments {
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

impl<'de> Deserialize<'de> for SigningCommitments {
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
            struct SigningCommitmentsVisitor;

            impl<'de> Visitor<'de> for SigningCommitmentsVisitor {
                type Value = SigningCommitments;

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
                        Scheme::Ed25519Sha512 => 69,
                        Scheme::Ed448Shake256 => 119,
                        Scheme::Ristretto25519Sha512 => 69,
                        Scheme::K256Sha256 => 71,
                        Scheme::P256Sha256 => 71,
                        Scheme::P384Sha384 => 103,
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
                    Ok(SigningCommitments { scheme, value })
                }
            }

            d.deserialize_seq(SigningCommitmentsVisitor)
        }
    }
}
