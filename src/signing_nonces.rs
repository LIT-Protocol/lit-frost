use crate::{Error, Scheme};
use frost_core::{Ciphersuite, Field, Group};
use serde::{
    de::{SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserialize, Deserializer, Serialize, Serializer,
};

/// Comprised of hiding and binding nonces
///
/// Note that [`SigningNonces`] must be used only once for a signing operation;
/// re-using nonces will result in leakage of a signer’s long-lived signing key.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub struct SigningNonces {
    /// The ciphersuite used for the signing nonces
    pub scheme: Scheme,
    /// The hiding nonce
    pub hiding: Vec<u8>,
    /// The binding nonce
    pub binding: Vec<u8>,
}

impl<C: Ciphersuite> From<frost_core::round1::SigningNonces<C>> for SigningNonces {
    fn from(s: frost_core::round1::SigningNonces<C>) -> Self {
        Self::from(&s)
    }
}

impl<C: Ciphersuite> From<&frost_core::round1::SigningNonces<C>> for SigningNonces {
    fn from(s: &frost_core::round1::SigningNonces<C>) -> Self {
        let scheme = C::ID.parse().unwrap();
        Self {
            scheme,
            hiding: s.hiding().serialize().as_ref().to_vec(),
            binding: s.binding().serialize().as_ref().to_vec(),
        }
    }
}

impl<C: Ciphersuite> TryFrom<&SigningNonces> for frost_core::round1::SigningNonces<C> {
    type Error = Error;

    fn try_from(value: &SigningNonces) -> Result<Self, Self::Error> {
        let scheme = C::ID
            .parse::<Scheme>()
            .map_err(|_| Error::General("Unknown ciphersuite".to_string()))?;
        if scheme != value.scheme {
            return Err(Error::General(
                "Ciphersuite does not match signing nonces".to_string(),
            ));
        }
        let hiding_bytes =
            <<C::Group as Group>::Field as Field>::Serialization::try_from(value.hiding.to_vec())
                .map_err(|_| Error::General("Error converting hiding nonce to bytes".to_string()))?;
        let binding_bytes =
            <<C::Group as Group>::Field as Field>::Serialization::try_from(value.binding.to_vec())
                .map_err(|_| {
                    Error::General("Error converting binding nonce to bytes".to_string())
                })?;
        let hiding = frost_core::round1::Nonce::<C>::deserialize(hiding_bytes)
            .map_err(|_| Error::General("Error deserializing hiding nonce".to_string()))?;
        let binding = frost_core::round1::Nonce::<C>::deserialize(binding_bytes)
            .map_err(|_| Error::General("Error deserializing binding nonce".to_string()))?;
        let signing_nonces = frost_core::round1::SigningNonces::<C>::from_nonces(hiding, binding);
        Ok(signing_nonces)
    }
}

impl Serialize for SigningNonces {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            (self.scheme.to_string(), &self.hiding, &self.binding).serialize(s)
        } else {
            let mut seq = s.serialize_tuple(1 + self.hiding.len() + self.binding.len())?;
            seq.serialize_element(&(self.scheme as u8))?;
            for byte in &self.hiding {
                seq.serialize_element(byte)?;
            }
            for byte in &self.binding {
                seq.serialize_element(byte)?;
            }

            seq.end()
        }
    }
}

impl<'de> Deserialize<'de> for SigningNonces {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if d.is_human_readable() {
            let (ty, hiding, binding) = <(String, Vec<u8>, Vec<u8>)>::deserialize(d)?;
            let scheme: Scheme = ty
                .parse()
                .map_err(|e: Error| serde::de::Error::custom(e.to_string()))?;
            Ok(Self {
                scheme,
                hiding,
                binding,
            })
        } else {
            struct SigningNoncesVisitor;

            impl<'de> Visitor<'de> for SigningNoncesVisitor {
                type Value = SigningNonces;

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
                    let mut hiding = Vec::new();
                    while let Some(b) = seq.next_element::<u8>()? {
                        hiding.push(b);
                        if hiding.len() == length {
                            break;
                        }
                    }
                    if hiding.len() != length {
                        return Err(serde::de::Error::custom("Invalid hiding length"));
                    }
                    let mut binding = Vec::new();
                    while let Some(b) = seq.next_element::<u8>()? {
                        binding.push(b);
                        if binding.len() == length {
                            break;
                        }
                    }
                    if binding.len() != length {
                        return Err(serde::de::Error::custom("Invalid binding length"));
                    }
                    Ok(SigningNonces {
                        scheme,
                        hiding,
                        binding,
                    })
                }
            }

            d.deserialize_seq(SigningNoncesVisitor)
        }
    }
}
