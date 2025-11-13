use lit_frost::{KeyPackage, Scheme, Signature, VerifyingKey};
use lit_rust_crypto::*;
use signature_crypto::Verifier;
use std::collections::BTreeMap;
use std::num::NonZeroU16;

#[test]
fn k256_taproot() {
    const MSG: &[u8] = b"k256_taproot";
    let (signature, verifying_key) = generate(MSG, Scheme::K256Taproot);

    let vk: k256::schnorr::VerifyingKey =
        verifying_key.try_into().expect("to convert to schnorr key");
    let sig: k256::schnorr::Signature = signature
        .try_into()
        .expect("to convert to schnorr signature");
    assert!(vk.verify(MSG, &sig).is_ok());
}

#[test]
fn ed25519() {
    const MSG: &[u8] = b"ed25519";
    let (signature, verifying_key) = generate(MSG, Scheme::Ed25519Sha512);

    let vk: ed25519_dalek::VerifyingKey =
        verifying_key.try_into().expect("to convert to ed25519 key");
    let sig: ed25519_dalek::Signature = signature
        .try_into()
        .expect("to convert to ed25519 signature");
    assert!(vk.verify(MSG, &sig).is_ok());
}

#[test]
fn jubjub() {
    const MSG: &[u8] = b"jubjub";

    let (signature, verifying_key) = generate(MSG, Scheme::RedJubjubBlake2b512);

    let vk: reddsa::VerificationKey<reddsa::sapling::SpendAuth> =
        verifying_key.try_into().expect("to convert to jubjub key");
    let sig: reddsa::Signature<reddsa::sapling::SpendAuth> = signature
        .try_into()
        .expect("to convert to jubjub signature");
    assert!(vk.verify(MSG, &sig).is_ok());
}

fn generate(msg: &[u8], scheme: Scheme) -> (Signature, VerifyingKey) {
    const THRESHOLD: u16 = 3;
    let mut rng = rand::rngs::OsRng;
    let (secret_shares, verifying_key) = scheme
        .generate_with_trusted_dealer(THRESHOLD, 5, &mut rng)
        .unwrap();

    let mut signing_package = BTreeMap::new();
    let mut signing_commitments = Vec::new();

    for (id, secret_share) in &secret_shares {
        let res = scheme.signing_round1(&secret_share, &mut rng);
        assert!(res.is_ok());
        let (nonces, commitments) = res.unwrap();
        signing_package.insert(id, (nonces, secret_share));
        signing_commitments.push((id.clone(), commitments));
    }

    let mut verifying_shares = Vec::new();
    let mut signature_shares = Vec::new();
    for (id, (nonces, secret_share)) in signing_package {
        let res = scheme.signing_round2(
            msg,
            &signing_commitments,
            &nonces,
            &KeyPackage {
                identifier: id.clone(),
                secret_share: secret_share.clone(),
                verifying_key: verifying_key.clone(),
                threshold: NonZeroU16::new(THRESHOLD).unwrap(),
            },
        );
        let signature = res.unwrap();
        signature_shares.push((id.clone(), signature));
        verifying_shares.push((id.clone(), scheme.verifying_share(&secret_share).unwrap()));
    }

    let res = scheme.aggregate(
        msg,
        &signing_commitments,
        &signature_shares,
        &verifying_shares,
        &verifying_key,
    );
    let signature = res.unwrap();
    (signature, verifying_key)
}
