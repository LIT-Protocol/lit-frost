use super::*;

impl From<ed25519_dalek::Signature> for Signature {
    fn from(s: ed25519_dalek::Signature) -> Self {
        Self::from(&s)
    }
}

impl From<&ed25519_dalek::Signature> for Signature {
    fn from(s: &ed25519_dalek::Signature) -> Self {
        Self {
            scheme: Scheme::Ed25519Sha512,
            value: s.to_bytes().to_vec(),
        }
    }
}

impl TryFrom<&Signature> for ed25519_dalek::Signature {
    type Error = Error;

    fn try_from(value: &Signature) -> Result<Self, Self::Error> {
        let scheme = Scheme::Ed25519Sha512;
        if scheme != value.scheme {
            return Err(Error::General(
                "Ciphersuite does not match signature".to_string(),
            ));
        }
        let bytes: ed25519_dalek::ed25519::SignatureBytes = value.value.clone().try_into().map_err(|_| Error::General("Error converting signature from bytes".to_string()))?;
        Ok(ed25519_dalek::Signature::from_bytes(&bytes))
    }
}

impl TryFrom<Signature> for ed25519_dalek::Signature {
    type Error = Error;

    fn try_from(value: Signature) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl<S: reddsa::SigType> From<reddsa::Signature<S>> for Signature {
    fn from(s: reddsa::Signature<S>) -> Self {
        let bytes: [u8; 64] = s.into();
        Self {
            scheme: Scheme::RedJubjubBlake2b512,
            value: bytes.to_vec(),
        }
    }
}

impl<S: reddsa::SigType> From<&reddsa::Signature<S>> for Signature {
    fn from(s: &reddsa::Signature<S>) -> Self {
        Self::from(*s)
    }
}

impl<S: reddsa::SigType> TryFrom<Signature> for reddsa::Signature<S> {
    type Error = Error;

    fn try_from(value: Signature) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }

}

impl<S: reddsa::SigType> TryFrom<&Signature> for reddsa::Signature<S> {
    type Error = Error;

    fn try_from(value: &Signature) -> Result<Self, Self::Error> {
        let scheme = Scheme::RedJubjubBlake2b512;
        if scheme != value.scheme {
            return Err(Error::General(
                "Ciphersuite does not match signature".to_string(),
            ));
        }
        let bytes: [u8; 64] = value.value.as_slice().try_into().map_err(|_| Error::General("Error converting signature from bytes".to_string()))?;
        Ok(Self::from(bytes))
    }
}

impl From<k256::schnorr::Signature> for Signature {
    fn from(s: k256::schnorr::Signature) -> Self {
        Self::from(&s)
    }
}

impl From<&k256::schnorr::Signature> for Signature {
    fn from(s: &k256::schnorr::Signature) -> Self {
        Self {
            scheme: Scheme::K256Taproot,
            value: s.to_bytes().to_vec(),
        }
    }
}

impl TryFrom<Signature> for k256::schnorr::Signature {
    type Error = Error;

    fn try_from(value: Signature) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&Signature> for k256::schnorr::Signature {
    type Error = Error;

    fn try_from(value: &Signature) -> Result<Self, Self::Error> {
        let scheme = Scheme::K256Taproot;
        if scheme != value.scheme {
            return Err(Error::General(
                "Ciphersuite does not match signature".to_string(),
            ));
        }
        match value.value.len() {
            64 => {
                k256::schnorr::Signature::try_from(value.value.as_slice()).map_err(|_| Error::General("Error converting signature from bytes".to_string()))
            },
            65 => {
                k256::schnorr::Signature::try_from(&value.value[1..]).map_err(|_| Error::General("Error converting signature from bytes".to_string()))
            },
            _ => Err(Error::General("Invalid signature length".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use ed448_goldilocks::elliptic_curve::bigint::U256;
    use ed448_goldilocks::elliptic_curve::ops::Reduce;
    use ff::PrimeField;
    use group::prime::PrimeCurveAffine;
    use k256::{FieldBytes, ProjectivePoint, Scalar};
    use k256::elliptic_curve::scalar::IsHigh;
    use crate::*;
    use rand::Rng;
    use subtle::ConstantTimeEq;
    use sha2::{Digest, Sha256};
    use vsss_rs::Share;

    #[test]
    fn ed25519_signature_conversion_simple() {
        use ed25519_dalek::Signer;

        let mut rng = rand::thread_rng();
        let sk = rng.gen::<ed25519_dalek::SecretKey>();
        let sk = ed25519_dalek::SigningKey::from(sk);
        let msg = b"Hello, world!";
        let sig = sk.sign(msg);
        let sig2 = Signature::from(&sig);
        let sig3 = ed25519_dalek::Signature::try_from(sig2).unwrap();
        assert_eq!(sig, sig3);
    }

    #[test]
    fn ed25519_signature_frost_verify() {
        use ed25519_dalek::Verifier;
        const SCHEME: Scheme = Scheme::Ed25519Sha512;
        const MSG: &[u8] = b"ed25519_signature_frost_verify";

        let mut rng = rand::thread_rng();

        let (secret_shares, verifying_key) = SCHEME.generate_with_trusted_dealer(2, 3, &mut rng).unwrap();

        let mut signing_package = BTreeMap::new();
        let mut signing_commitments = Vec::new();

        for (id, secret_share) in secret_shares {
            let res = SCHEME.round1(&secret_share, &mut rng);
            assert!(res.is_ok());
            let (nonces, commitments) = res.unwrap();
            signing_package.insert(id, (nonces, secret_share));
            signing_commitments.push((id, commitments));
        }

        let mut verifying_shares = Vec::new();
        let mut signature_shares = Vec::new();
        for (id, (nonces, secret_share)) in signing_package {
            let res = SCHEME.sign(
                MSG,
                &signing_commitments,
                &nonces,
                &KeyPackage {
                    identifier: id.clone(),
                    secret_share: secret_share.clone(),
                    verifying_key: verifying_key.clone(),
                    threshold: NonZeroU8::new(2).unwrap(),
                },
            );
            let signature = res.unwrap();
            signature_shares.push((id.clone(), signature));
            verifying_shares.push((id.clone(), SCHEME.verifying_share(&secret_share).unwrap()));
        }

        let res = SCHEME.aggregate(
            MSG,
            &signing_commitments,
            &signature_shares,
            &verifying_shares,
            &verifying_key,
        );
        let signature = res.unwrap();
        assert!(SCHEME.verify(MSG, &verifying_key, &signature).is_ok());

        // Convert to concrete types and see if verify works
        let signature = ed25519_dalek::Signature::try_from(signature).unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(verifying_key.value.as_slice().try_into().unwrap()).unwrap();
        assert!(verifying_key.verify(MSG, &signature).is_ok());
    }

    #[test]
    fn redjubjub_signature_conversion_simple() {
        const MSG: &[u8] = b"redjubjub_signature_conversion_simple";
        let mut rng = rand_core::OsRng;
        let sk = reddsa::SigningKey::<reddsa::sapling::SpendAuth>::new(&mut rng);
        let sig = sk.sign(&mut rng, MSG);
        let sig2 = Signature::from(&sig);
        let sig3 = reddsa::Signature::<reddsa::sapling::SpendAuth>::try_from(sig2).unwrap();
        assert_eq!(sig, sig3);

        let sk = reddsa::SigningKey::<reddsa::orchard::SpendAuth>::new(&mut rng);
        let sig = sk.sign(&mut rng, MSG);
        let sig2 = Signature::from(&sig);
        let sig3 = reddsa::Signature::<reddsa::orchard::SpendAuth>::try_from(sig2).unwrap();
        assert_eq!(sig, sig3);
    }

    #[test]
    fn redjubjub_signature_frost_verify() {
        const SCHEME: Scheme = Scheme::RedJubjubBlake2b512;
        const MSG: &[u8] = b"redjubjub_signature_frost_verify";

        let mut rng = rand_core::OsRng;

        let (secret_shares, verifying_key) = SCHEME.generate_with_trusted_dealer(2, 3, &mut rng).unwrap();

        let mut signing_package = BTreeMap::new();
        let mut signing_commitments = Vec::new();

        for (id, secret_share) in secret_shares {
            let res = SCHEME.round1(&secret_share, &mut rng);
            assert!(res.is_ok());
            let (nonces, commitments) = res.unwrap();
            signing_package.insert(id, (nonces, secret_share));
            signing_commitments.push((id, commitments));
        }

        let mut verifying_shares = Vec::new();
        let mut signature_shares = Vec::new();
        for (id, (nonces, secret_share)) in signing_package {
            let res = SCHEME.sign(
                MSG,
                &signing_commitments,
                &nonces,
                &KeyPackage {
                    identifier: id.clone(),
                    secret_share: secret_share.clone(),
                    verifying_key: verifying_key.clone(),
                    threshold: NonZeroU8::new(2).unwrap(),
                },
            );
            let signature = res.unwrap();
            signature_shares.push((id.clone(), signature));
            verifying_shares.push((id.clone(), SCHEME.verifying_share(&secret_share).unwrap()));
        }

        let res = SCHEME.aggregate(
            MSG,
            &signing_commitments,
            &signature_shares,
            &verifying_shares,
            &verifying_key,
        );
        let signature = res.unwrap();
        assert!(SCHEME.verify(MSG, &verifying_key, &signature).is_ok());

        // Convert to concrete types and see if verify works
        let signature = reddsa::Signature::<reddsa::sapling::SpendAuth>::try_from(signature).unwrap();
        let verifying_key = reddsa::VerificationKey::try_from(verifying_key).unwrap();
        assert!(verifying_key.verify(MSG, &signature).is_ok());
    }

    #[test]
    fn taproot_signature_conversion_simple() {
        use signature_crypto::Signer;

        const MSG: &[u8] = b"k256_signature_conversion_simple";
        let mut rng = rand_core::OsRng;
        let sk = k256::schnorr::SigningKey::random(&mut rng);
        let sig = sk.sign(MSG);
        let sig2 = Signature::from(&sig);
        let sig3 = k256::schnorr::Signature::try_from(sig2).unwrap();
        assert_eq!(sig, sig3);
    }

    #[test]
    fn taproot_signature_frost_verify() {
        use k256::elliptic_curve::point::AffineCoordinates;

        const SCHEME: Scheme = Scheme::K256Taproot;
        const MSG: &[u8] = b"secp256k1_taproot_signature_frost_verify";

        let msg  = Sha256::default().chain_update(MSG).finalize();

        let mut rng = rand_core::OsRng;

        let (mut secret_shares, mut verifying_key) = SCHEME.generate_with_trusted_dealer(2, 3, &mut rng).unwrap();

        if verifying_key.value[0] == 0x2 {
            let mut shares = secret_shares.iter().map(|(i, s)| {
                <Vec<u8> as vsss_rs::Share>::with_identifier_and_value(i.id, s.value.as_slice())
            }).collect::<Vec<Vec<u8>>>();
            let mut secret = vsss_rs::combine_shares::<Scalar, u8, Vec<u8>>(shares.as_slice()).unwrap();
            secret = -secret;
            let pk = ProjectivePoint::GENERATOR * secret;
            verifying_key = (SCHEME, pk).into();
            shares = vsss_rs::shamir::split_secret(2, 3, secret, &mut rng).unwrap();
            secret_shares = shares.iter().map(|s| {
                let i: Identifier = (SCHEME, s[0]).into();
                let ss = s.as_field_element::<Scalar>().unwrap();
                let sss: SigningShare = (SCHEME, ss).into();
                (i, sss)
            }).collect();
        }

        println!("verifying key {}", hex::encode(verifying_key.value.as_slice()));
        let vk = k256::schnorr::VerifyingKey::try_from(&verifying_key).unwrap();

        let mut counts = [0; 4];
        for _ in 0..30 {
            let mut signing_package = BTreeMap::new();
            let mut signing_commitments = Vec::new();

            for (id, secret_share) in &secret_shares {
                let res = SCHEME.round1(&secret_share, &mut rng);
                assert!(res.is_ok());
                let (nonces, commitments) = res.unwrap();
                signing_package.insert(id.clone(), (nonces, secret_share));
                signing_commitments.push((id.clone(), commitments));
            }

            let mut verifying_shares = Vec::new();
            let mut signature_shares = Vec::new();
            for (id, (nonces, secret_share)) in signing_package {
                let res = SCHEME.sign(
                    &msg[..],
                    &signing_commitments[..],
                    &nonces,
                    &KeyPackage {
                        identifier: id.clone(),
                        secret_share: secret_share.clone(),
                        verifying_key: verifying_key.clone(),
                        threshold: NonZeroU8::new(2).unwrap(),
                    },
                );
                let signature = res.unwrap();
                signature_shares.push((id.clone(), signature));
                verifying_shares.push((id.clone(), SCHEME.verifying_share(&secret_share).unwrap()));
            }

            let res = SCHEME.aggregate(
                &msg[..],
                &signing_commitments,
                &signature_shares,
                &verifying_shares,
                &verifying_key,
            );
            let signature = res.unwrap();
            assert!(SCHEME.verify(&msg[..], &verifying_key, &signature).is_ok());

            // Convert to concrete types and see if verify works
            // let sig = k256::schnorr::Signature::try_from(&signature).unwrap();

            let prehash: [u8; 32] = (&msg[..]).try_into().unwrap();

            let e = <Scalar as Reduce<U256>>::reduce_bytes(
                &tagged_hash(CHALLENGE_TAG)
                    .chain_update(&signature.value[1..33])
                    .chain_update(vk.to_bytes())
                    .chain_update(prehash)
                    .finalize(),
            );
            let r = k256::FieldElement::from_bytes(FieldBytes::from_slice(&signature.value[1..33])).unwrap();
            let s = Scalar::from_repr(FieldBytes::clone_from_slice(&signature.value[33..])).unwrap();

            let mut R = (ProjectivePoint::GENERATOR * s + ProjectivePoint::from(vk.as_affine()) * -e).to_affine();
            counts[0] += (!R.is_identity() & R.y_is_odd() & R.x().ct_eq(&signature.value[1..33])).unwrap_u8() as usize;

            R = (ProjectivePoint::GENERATOR * -s + ProjectivePoint::from(vk.as_affine()) * -e).to_affine();

            counts[1] += (!R.is_identity() & R.y_is_odd() & R.x().ct_eq(&signature.value[1..33])).unwrap_u8() as usize;

            R = (ProjectivePoint::GENERATOR * -s - ProjectivePoint::from(vk.as_affine()) * -e).to_affine();

            counts[2] += (!R.is_identity() & R.y_is_odd() & R.x().ct_eq(&signature.value[1..33])).unwrap_u8() as usize;

            R = (ProjectivePoint::GENERATOR * s - ProjectivePoint::from(vk.as_affine()) * -e).to_affine();

            counts[3] += (!R.is_identity() & R.y_is_odd() & R.x().ct_eq(&signature.value[1..33])).unwrap_u8() as usize;
        }
        println!("Counts");
        println!("original {}", counts[0]);
        println!("neg s    {}", counts[1]);
        println!("neg s_vk {}", counts[2]);
        println!("neg vk   {}", counts[3]);
    }

    const CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";
    fn tagged_hash(tag: &[u8]) -> Sha256 {
        let tag_hash = Sha256::digest(tag);
        let mut digest = Sha256::new();
        digest.update(tag_hash);
        digest.update(tag_hash);
        digest
    }
}