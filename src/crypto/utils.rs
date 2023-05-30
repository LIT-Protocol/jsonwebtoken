use elliptic_curve::{ops::Reduce, Curve, CurveArithmetic};
use k256::ecdsa::VerifyingKey;
use k256::sha2::{digest::FixedOutput, Digest};
use k256::{ecdsa::Signature, schnorr::signature::PrehashSignature, FieldBytes, Scalar, Secp256k1};
use rand::AsByteSliceMut;

use crate::errors::{Error, Result};

pub fn scalar_hash(msg: &[u8]) -> <Secp256k1 as CurveArithmetic>::Scalar {
    let digest = <Signature as PrehashSignature>::Digest::new_with_prefix(msg);
    let m_bytes: FieldBytes = digest.finalize_fixed();
    <Scalar as Reduce<<Secp256k1 as Curve>::Uint>>::reduce_bytes(&m_bytes)
}

pub fn encode_secp_signature(signature: Signature) -> Result<String> {
    let hex_r = bytes_to_hex(signature.r().to_bytes());
    let hex_s = bytes_to_hex(signature.s().to_bytes());

    let mut signature = serde_json::Map::new();
    signature.insert("s".to_string(), serde_json::Value::String(hex_s));
    signature.insert("r".to_string(), serde_json::Value::String(hex_r));

    return serde_json::to_string(&signature).map_err(|e| Error::from(e));
}

pub fn bytes_to_hex<B>(vec: B) -> String
where
    B: AsRef<[u8]>,
{
    vec.as_ref().iter().map(|b| format!("{b:02x}")).collect::<String>()
}

pub fn hex_to_scalar(hex_val: &str) -> Result<Scalar> {
    let mut hex_val = hex_val.to_string();
    if hex_val.len() % 2 == 1 {
        // if length is odd, add a zero at the front
        hex_val.insert(0, '0');
    }

    let mut slice = hex::decode(hex_val).unwrap();
    let slice = slice.as_byte_slice_mut();
    let bytes = FieldBytes::from_mut_slice(slice);

    Ok(<Scalar as Reduce<<Secp256k1 as Curve>::Uint>>::reduce_bytes(bytes))
}

pub fn hex_to_verifying_key(hex_val: &str) -> Result<VerifyingKey> {
    let mut hex_val = hex_val.to_string();
    if hex_val.len() % 2 == 1 {
        // if length is odd, add a zero at the front
        hex_val.insert(0, '0');
    }
    let mut slice = hex::decode(hex_val).unwrap();
    let bytes = slice.as_byte_slice_mut();
    let pubkey = VerifyingKey::from_sec1_bytes(bytes).unwrap();

    Ok(pubkey)
}
