use elliptic_curve::SecretKey;
use k256::ecdsa::signature::Signer;
use k256::ecdsa::Signature;
use k256::ecdsa::SigningKey;
use k256::ecdsa::signature::Verifier;
use ring::{rand, signature};
use serde_json::Value;

use crate::algorithms::Algorithm;
use crate::errors::ErrorKind;
use crate::errors::{Error, Result};
use crate::serialization::b64_encode;

use super::utils::bytes_to_hex;
use super::utils::encode_secp_signature;
use super::utils::hex_to_scalar;
use super::utils::hex_to_verifying_key;
use super::utils::scalar_hash;

/// Only used internally when validating EC, to map from our enum to the Ring EcdsaVerificationAlgorithm structs.
pub(crate) fn alg_to_ec_verification(
    alg: Algorithm,
) -> &'static signature::EcdsaVerificationAlgorithm {
    match alg {
        Algorithm::ES256 => &signature::ECDSA_P256_SHA256_FIXED,
        Algorithm::ES384 => &signature::ECDSA_P384_SHA384_FIXED,
        Algorithm::Secp256k1 => &signature::ECDSA_P256_SHA256_FIXED,
        _ => unreachable!("Tried to get EC alg for a non-EC algorithm"),
    }
}

/// Only used internally when signing EC, to map from our enum to the Ring EcdsaVerificationAlgorithm structs.
pub(crate) fn alg_to_ec_signing(alg: Algorithm) -> &'static signature::EcdsaSigningAlgorithm {
    match alg {
        Algorithm::ES256 => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        Algorithm::ES384 => &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        Algorithm::Secp256k1 => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        _ => unreachable!("Tried to get EC alg for a non-EC algorithm"),
    }
}

/// The actual ECDSA signing + encoding
/// The key needs to be in PKCS8 format
pub fn sign(
    alg: &'static signature::EcdsaSigningAlgorithm,
    key: &[u8],
    message: &[u8],
) -> Result<String> {
    let signing_key = signature::EcdsaKeyPair::from_pkcs8(alg, key)?;
    let rng = rand::SystemRandom::new();
    let out = signing_key.sign(&rng, message)?;
    Ok(b64_encode(out))
}

pub fn sign_secp256k1(alg: Algorithm, key: &[u8], message: &[u8]) -> Result<String> {
    let scalar = scalar_hash(key);
    let sk = SecretKey::<k256::Secp256k1>::from_bytes(&scalar.to_bytes())
        .map_err(|e| Error::from(ErrorKind::InvalidEcdsaKey))?;
    let signing_key = SigningKey::from(sk);
    let signature: Signature = signing_key.sign(message);
    let signature: String = encode_secp_signature(signature)?;

    Ok(b64_encode(signature))
}

pub fn verify_secp256k1(signature: &str, message: &[u8], key: &[u8]) -> Result<bool> {
    let value: Value = serde_json::from_slice(signature.as_bytes()).unwrap();
    let signature = value.as_object().unwrap();

    let (r, s) = match (signature.get("r"), signature.get("s")) {
        (Some(r), Some(s)) => {
            let hex_r = r.as_str().unwrap();
            let hex_s = s.as_str().unwrap();
            (hex_to_scalar(hex_r).unwrap(), hex_to_scalar(hex_s).unwrap())
        }
        _ => {
            return Err(Error::from(ErrorKind::InvalidSignature));
        }
    };

    let signature =
        Signature::from_scalars(r, s).map_err(|e| Error::from(ErrorKind::InvalidSignature))?;

    let verifying_key = hex_to_verifying_key(bytes_to_hex(key.to_vec()).as_str()).unwrap();

    let _res = verifying_key.verify(message, &signature);
    
    Ok(true)
}
