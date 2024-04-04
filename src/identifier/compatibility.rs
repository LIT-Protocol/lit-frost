use crate::{Error, Identifier, Scheme};

try_from_scheme_ref!(Identifier, k256::Scalar, |scheme, id: &k256::Scalar| {
    match scheme {
        Scheme::K256Sha256 | Scheme::K256Taproot => {
            let bytes = id.to_bytes();
            if bytes[..31].iter().any(|b| *b != 0) {
                return Err(Error::General("Invalid identifier".to_string()));
            }
            Ok(Self {
                scheme,
                id: bytes[31],
            })
        }
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});
try_from_scheme_ref!(k256::Scalar, Identifier, |id: &Identifier| {
    match id.scheme {
        Scheme::K256Sha256 | Scheme::K256Taproot => Ok(k256::Scalar::from(id.id as u32)),
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});
try_from_scheme_ref!(Identifier, p256::Scalar, |scheme, id: &p256::Scalar| {
    match scheme {
        Scheme::P256Sha256 => {
            let bytes = id.to_bytes();
            if bytes[..31].iter().any(|b| *b != 0) {
                return Err(Error::General("Invalid identifier".to_string()));
            }
            Ok(Self {
                scheme,
                id: bytes[31],
            })
        }
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});
try_from_scheme_ref!(p256::Scalar, Identifier, |id: &Identifier| {
    match id.scheme {
        Scheme::P256Sha256 => Ok(p256::Scalar::from(id.id as u32)),
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});
try_from_scheme_ref!(Identifier, p384::Scalar, |scheme, id: &p384::Scalar| {
    match scheme {
        Scheme::P384Sha384 => {
            let bytes = id.to_bytes();
            if bytes[..47].iter().any(|b| *b != 0) {
                return Err(Error::General("Invalid identifier".to_string()));
            }
            Ok(Self {
                scheme,
                id: bytes[47],
            })
        }
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});
try_from_scheme_ref!(p384::Scalar, Identifier, |id: &Identifier| {
    match id.scheme {
        Scheme::P384Sha384 => Ok(p384::Scalar::from(id.id as u32)),
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});
try_from_scheme_ref!(
    Identifier,
    curve25519_dalek::Scalar,
    |scheme, id: &curve25519_dalek::Scalar| {
        match scheme {
            Scheme::Ed25519Sha512 | Scheme::Ristretto25519Sha512 => {
                let bytes = id.to_bytes();
                if bytes[1..].iter().any(|b| *b != 0) {
                    return Err(Error::General("Invalid identifier".to_string()));
                }
                Ok(Self {
                    scheme,
                    id: bytes[0],
                })
            }
            _ => Err(Error::General("Invalid ciphersuite".to_string())),
        }
    }
);
try_from_scheme_ref!(curve25519_dalek::Scalar, Identifier, |id: &Identifier| {
    match id.scheme {
        Scheme::Ed25519Sha512 | Scheme::Ristretto25519Sha512 => {
            Ok(curve25519_dalek::Scalar::from(id.id as u32))
        }
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});
try_from_scheme_ref!(
    Identifier,
    ed448_goldilocks::Scalar,
    |scheme, id: &ed448_goldilocks::Scalar| {
        match scheme {
            Scheme::Ed448Shake256 => {
                let bytes = id.to_bytes();
                if bytes[1..].iter().any(|b| *b != 0) {
                    return Err(Error::General("Invalid identifier".to_string()));
                }
                Ok(Self {
                    scheme,
                    id: bytes[0],
                })
            }
            _ => Err(Error::General("Invalid ciphersuite".to_string())),
        }
    }
);
try_from_scheme_ref!(ed448_goldilocks::Scalar, Identifier, |id: &Identifier| {
    match id.scheme {
        Scheme::Ed448Shake256 => Ok(ed448_goldilocks::Scalar::from(id.id as u32)),
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});
try_from_scheme_ref!(Identifier, jubjub::Scalar, |scheme, id: &jubjub::Scalar| {
    match scheme {
        Scheme::RedJubjubBlake2b512 => {
            let bytes = id.to_bytes();
            if bytes[1..].iter().any(|b| *b != 0) {
                return Err(Error::General("Invalid identifier".to_string()));
            }
            Ok(Self {
                scheme,
                id: bytes[0],
            })
        }
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});
try_from_scheme_ref!(jubjub::Scalar, Identifier, |id: &Identifier| {
    match id.scheme {
        Scheme::RedJubjubBlake2b512 => Ok(jubjub::Scalar::from(id.id as u64)),
        _ => Err(Error::General("Invalid ciphersuite".to_string())),
    }
});

try_from_scheme_ref!(
    Identifier,
    vsss_rs::curve25519_dalek::Scalar,
    |scheme, id: &vsss_rs::curve25519_dalek::Scalar| {
        match scheme {
            Scheme::Ed25519Sha512 | Scheme::Ristretto25519Sha512 => {
                let bytes = id.to_bytes();
                if bytes[1..].iter().any(|b| *b != 0) {
                    return Err(Error::General("Invalid identifier".to_string()));
                }
                Ok(Self {
                    scheme,
                    id: bytes[0],
                })
            }
            _ => Err(Error::General("Invalid ciphersuite".to_string())),
        }
    }
);
try_from_scheme_ref!(
    vsss_rs::curve25519_dalek::Scalar,
    Identifier,
    |id: &Identifier| {
        match id.scheme {
            Scheme::Ed25519Sha512 | Scheme::Ristretto25519Sha512 => {
                Ok(vsss_rs::curve25519_dalek::Scalar::from(id.id as u32))
            }
            _ => Err(Error::General("Invalid ciphersuite".to_string())),
        }
    }
);
try_from_scheme_ref!(
    Identifier,
    vsss_rs::curve25519::WrappedScalar,
    |scheme, id: &vsss_rs::curve25519::WrappedScalar| { Self::try_from((scheme, &id.0)) }
);
try_from_scheme_ref!(
    vsss_rs::curve25519::WrappedScalar,
    Identifier,
    |id: &Identifier| {
        let scalar = vsss_rs::curve25519::WrappedScalar::try_from(id)?;
        Ok(Self(scalar.0))
    }
);
