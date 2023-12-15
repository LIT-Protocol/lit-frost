use crate::{Error, Scheme};
use frost_core::{Ciphersuite, Field, Group};

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
            .map_err(|_| Error::General("Error converting signing share".to_string()))
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

        if value.scheme != Scheme::K256Sha256 || value.value.len() != 32 {
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
        let bytes = <[u8; 57]>::try_from(value.value.as_slice()).unwrap();
        ed448_goldilocks::Scalar::from_canonical_bytes(bytes)
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

serde_impl!(SigningShare, scalar_len, 58);
display_impl!(SigningShare);

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case::ed25519(
        frost_ed25519::Ed25519Sha512,
        frost_ed25519::Ed25519ScalarField,
        Scheme::Ed25519Sha512
    )]
    #[case::ed448(
        frost_ed448::Ed448Shake256,
        frost_ed448::Ed448ScalarField,
        Scheme::Ed448Shake256
    )]
    #[case::ristretto25519(
        frost_ristretto255::Ristretto255Sha512,
        frost_ristretto255::RistrettoScalarField,
        Scheme::Ristretto25519Sha512
    )]
    #[case::k256(
        frost_secp256k1::Secp256K1Sha256,
        frost_secp256k1::Secp256K1ScalarField,
        Scheme::K256Sha256
    )]
    #[case::p256(
        frost_p256::P256Sha256,
        frost_p256::P256ScalarField,
        Scheme::P256Sha256
    )]
    #[case::p384(
        frost_p384::P384Sha384,
        frost_p384::P384ScalarField,
        Scheme::P384Sha384
    )]
    #[case::redjubjub(
        frost_redjubjub::JubjubBlake2b512,
        frost_redjubjub::JubjubScalarField,
        Scheme::RedJubjubBlake2b512
    )]
    fn convert_1<C: Ciphersuite, F: Field>(#[case] _c: C, #[case] _f: F, #[case] scheme: Scheme) {
        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let share = F::random(&mut rng);
            let share = SigningShare {
                scheme,
                value: F::serialize(&share).as_ref().to_vec(),
            };
            let frost_share = frost_core::keys::SigningShare::<C>::try_from(&share);
            assert!(frost_share.is_ok());
            let frost_share = frost_share.unwrap();
            assert_eq!(share, SigningShare::from(&frost_share));
        }
    }

    #[test]
    fn convert_k256() {
        use ff::Field as FFField;

        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let share = k256::Scalar::random(&mut rng);
            let share: SigningShare = share.into();
            let frost_share = k256::Scalar::try_from(&share);
            assert!(frost_share.is_ok());
            let frost_share = frost_share.unwrap();
            assert_eq!(share, SigningShare::from(&frost_share));
        }
    }

    #[test]
    fn convert_p256() {
        use ff::Field as FFField;

        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let share = p256::Scalar::random(&mut rng);
            let share: SigningShare = share.into();
            let frost_share = p256::Scalar::try_from(&share);
            assert!(frost_share.is_ok());
            let frost_share = frost_share.unwrap();
            assert_eq!(share, SigningShare::from(&frost_share));
        }
    }

    #[test]
    fn convert_p384() {
        use ff::Field as FFField;

        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let share = p384::Scalar::random(&mut rng);
            let share: SigningShare = share.into();
            let frost_share = p384::Scalar::try_from(&share);
            assert!(frost_share.is_ok());
            let frost_share = frost_share.unwrap();
            assert_eq!(share, SigningShare::from(&frost_share));
        }
    }

    #[test]
    fn convert_ed25519_ristretto25519() {
        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let share = curve25519_dalek::Scalar::random(&mut rng);
            let share: SigningShare = share.into();
            let frost_share = curve25519_dalek::Scalar::try_from(&share);
            assert!(frost_share.is_ok());
            let frost_share = frost_share.unwrap();
            assert_eq!(share, SigningShare::from(&frost_share));
        }
    }

    #[test]
    fn convert_ed448() {
        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let share = ed448_goldilocks::Scalar::random(&mut rng);
            let share: SigningShare = share.into();
            let frost_share = ed448_goldilocks::Scalar::try_from(&share);
            assert!(frost_share.is_ok());
            let frost_share = frost_share.unwrap();
            assert_eq!(share, SigningShare::from(&frost_share));
        }
    }

    #[test]
    fn convert_redjubjub() {
        use ff::Field as FFField;

        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let share = jubjub::Scalar::random(&mut rng);
            let share: SigningShare = share.into();
            let frost_share = jubjub::Scalar::try_from(&share);
            assert!(frost_share.is_ok());
            let frost_share = frost_share.unwrap();
            assert_eq!(share, SigningShare::from(&frost_share));
        }
    }

    #[test]
    fn convert_vsss_wrapped() {
        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let share = curve25519_dalek::Scalar::random(&mut rng);
            let share: SigningShare = vsss_rs::curve25519::WrappedScalar(share).into();
            let frost_share = vsss_rs::curve25519::WrappedScalar::try_from(&share);
            assert!(frost_share.is_ok());
            let frost_share = frost_share.unwrap();
            assert_eq!(share, SigningShare::from(&frost_share));
        }
    }

    #[rstest]
    #[case::ed25519(frost_ed25519::Ed25519ScalarField, Scheme::Ed25519Sha512)]
    #[case::ed448(frost_ed448::Ed448ScalarField, Scheme::Ed448Shake256)]
    #[case::ristretto25519(frost_ristretto255::RistrettoScalarField, Scheme::Ristretto25519Sha512)]
    #[case::k256(frost_secp256k1::Secp256K1ScalarField, Scheme::K256Sha256)]
    #[case::p256(frost_p256::P256ScalarField, Scheme::P256Sha256)]
    #[case::p384(frost_p384::P384ScalarField, Scheme::P384Sha384)]
    #[case::redjubjub(frost_redjubjub::JubjubScalarField, Scheme::RedJubjubBlake2b512)]
    fn serialize<F: Field>(#[case] _f: F, #[case] scheme: Scheme) {
        const ITER: usize = 25;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..ITER {
            let share = F::random(&mut rng);
            let share = SigningShare {
                scheme,
                value: F::serialize(&share).as_ref().to_vec(),
            };
            let res = serde_json::to_string(&share);
            assert!(res.is_ok());
            let serialized = res.unwrap();
            let res = serde_json::from_str(&serialized);
            assert!(res.is_ok());
            let deserialized: SigningShare = res.unwrap();
            assert_eq!(share, deserialized);
            let res = serde_bare::to_vec(&share);
            assert!(res.is_ok());
            let serialized = res.unwrap();
            assert_eq!(serialized.len(), scheme.scalar_len().unwrap() + 1);
            let res = serde_bare::from_slice(&serialized);
            if res.is_err() {
                println!("Error: {:?}", res);
            }
            assert!(res.is_ok());
            let deserialized: SigningShare = res.unwrap();
            assert_eq!(share, deserialized);
        }
    }
}
