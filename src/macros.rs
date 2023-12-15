macro_rules! serde_impl {
    ($name:ident, $method_length:ident, $len:expr) => {
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                if s.is_human_readable() {
                    (self.scheme, &self.value[..]).serialize(s)
                } else {
                    use serde::ser::SerializeTuple;

                    let mut seq = s.serialize_tuple(self.value.len() + 1)?;
                    seq.serialize_element(&(self.scheme as u8))?;
                    for b in &self.value {
                        seq.serialize_element(b)?;
                    }

                    seq.end()
                }
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(d: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                if d.is_human_readable() {
                    let (ty, value) = <(String, Vec<u8>)>::deserialize(d)?;
                    let scheme: Scheme = ty
                        .parse()
                        .map_err(|e: Error| serde::de::Error::custom(e.to_string()))?;
                    Ok(Self { scheme, value })
                } else {
                    struct NameVisitor;

                    impl<'de> serde::de::Visitor<'de> for NameVisitor {
                        type Value = $name;

                        fn expecting(
                            &self,
                            formatter: &mut std::fmt::Formatter,
                        ) -> std::fmt::Result {
                            formatter.write_str("a tuple of (u8, Vec<u8>)")
                        }

                        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                        where
                            A: serde::de::SeqAccess<'de>,
                        {
                            let scheme: Scheme = seq
                                .next_element::<u8>()?
                                .ok_or_else(|| serde::de::Error::custom("Missing scheme"))?
                                .into();
                            let length = scheme
                                .$method_length()
                                .map_err(|e| serde::de::Error::custom(e.to_string()))?;
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
                            Ok($name { scheme, value })
                        }
                    }

                    d.deserialize_tuple($len, NameVisitor)
                }
            }
        }
    };
}

macro_rules! display_impl {
    ($name:ident) => {
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{}: 0x", self.scheme)?;
                for b in &self.value {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
        }
    };
}
