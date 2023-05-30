use elliptic_curve::{ops::Reduce, Curve, CurveArithmetic};
use k256::sha2::{digest::FixedOutput, Digest};
use k256::{ecdsa::Signature, schnorr::signature::PrehashSignature, FieldBytes, Scalar, Secp256k1};

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
