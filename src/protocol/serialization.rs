use anyhow::{Result, anyhow};
use ff::PrimeField;
use group::{Group, GroupEncoding};

/// Trait for types that can be serialized to bytes.
pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

/// Trait for types that can be deserialized from bytes.
pub trait FromBytes: Sized {
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}

/// Returns the length in bytes of a group element.
pub(super) fn element_len<G: Group + GroupEncoding>() -> usize {
    G::Repr::default().as_ref().len()
}

/// Serializes a group element to a byte vector.
pub(super) fn serialize_element<G: Group + GroupEncoding>(out: &mut Vec<u8>, elem: G) {
    out.extend_from_slice(elem.to_bytes().as_ref());
}

/// Serializes a scalar to a byte vector.
pub(super) fn serialize_scalar<F: PrimeField>(out: &mut Vec<u8>, scalar: F) {
    out.extend_from_slice(scalar.to_repr().as_ref());
}

/// Serializes a vector of group elements to a byte vector.
pub(super) fn serialize_elements<G: Group + GroupEncoding>(out: &mut Vec<u8>, elements: &[G]) {
    out.extend_from_slice(&(elements.len() as u32).to_be_bytes());
    for elem in elements {
        out.extend_from_slice(elem.to_bytes().as_ref());
    }
}

/// Serializes a vector of scalars to a byte vector.
pub(super) fn serialize_scalars<F: PrimeField>(out: &mut Vec<u8>, scalars: &[F]) {
    out.extend_from_slice(&(scalars.len() as u32).to_be_bytes());
    for scalar in scalars {
        out.extend_from_slice(scalar.to_repr().as_ref());
    }
}

/// Deserializes a length prefix from a byte buffer.
pub(super) fn deserialize_len(buf: &[u8]) -> usize {
    u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize
}

/// Deserializes a group element from a byte buffer.
pub(super) fn deserialize_element<G: Group + GroupEncoding>(buf: &[u8]) -> Result<G> {
    let mut repr = G::Repr::default();
    if buf.len() < repr.as_ref().len() {
        return Err(anyhow!("Invalid buffer size"));
    }
    repr.as_mut().copy_from_slice(buf);
    let elem: Option<G> = G::from_bytes(&repr).into();
    elem.ok_or(anyhow!("Deserialization error"))
}

/// Deserializes a scalar field element from a byte buffer.
pub(super) fn deserialize_scalar<F: PrimeField>(buf: &[u8]) -> Result<F> {
    let mut repr = F::Repr::default();
    if buf.len() < repr.as_ref().len() {
        return Err(anyhow!("Invalid buffer size"));
    }
    repr.as_mut().copy_from_slice(buf);
    let elem: Option<F> = F::from_repr(repr).into();
    elem.ok_or(anyhow!("Deserialization error"))
}

/// Deserializes a vector of group elements from a byte buffer.
pub(super) fn deserialize_elements<G: Group + GroupEncoding>(
    buf: &[u8],
    count: usize,
) -> Result<Vec<G>> {
    let mut repr = G::Repr::default();
    let elem_size = repr.as_ref().len();
    if buf.len() < count * elem_size {
        return Err(anyhow!("Invalid buffer size"));
    }

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        repr.as_mut()
            .copy_from_slice(&buf[i * elem_size..(i + 1) * elem_size]);
        let elem: Option<G> = G::from_bytes(&repr).into();
        out.push(elem.ok_or(anyhow!("Deserialization error"))?);
    }
    Ok(out)
}

/// Deserializes a vector of scalars from a byte buffer.
pub(super) fn deserialize_scalars<F: PrimeField>(buf: &[u8], count: usize) -> Result<Vec<F>> {
    let mut repr = F::Repr::default();
    let elem_size = repr.as_ref().len();
    if buf.len() < count * elem_size {
        return Err(anyhow!("Invalid buffer size"));
    }

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        repr.as_mut()
            .copy_from_slice(&buf[i * elem_size..(i + 1) * elem_size]);
        let elem: Option<F> = F::from_repr(repr).into();
        out.push(elem.ok_or(anyhow!("Deserialization error"))?);
    }
    Ok(out)
}

/// Derive serde traits for struct fields that are ToBytes + FromBytes.
pub(crate) mod serde_derive {
    use super::{FromBytes, ToBytes};
    use serde::{Deserializer, Serializer};

    /// Serializes a ToBytes type for Serde.
    #[allow(dead_code)]
    pub(crate) fn serialize<T: ToBytes, S: Serializer>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let bytes = value.to_bytes();
        serializer.serialize_bytes(&bytes)
    }

    /// Deserializes a FromBytes type for Serde.
    #[allow(dead_code)]
    pub(crate) fn deserialize<'de, T: FromBytes, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        let bytes: &[u8] = serde::Deserialize::deserialize(deserializer)?;
        T::from_bytes(bytes).map_err(serde::de::Error::custom)
    }
}

/// Macro to generate ToBytes and FromBytes implementations for simple structs.
#[macro_export]
macro_rules! impl_serialization {
    (
        $struct_name:ident<$generic:ident> {
            $($field:ident: $field_type:tt),* $(,)?
        }
    ) => {
        impl<$generic: Group + GroupEncoding> ToBytes for $struct_name<$generic> {
            fn to_bytes(&self) -> Vec<u8> { let mut out = Vec::new();
                $(
                    crate::protocol::impl_serialization!(@serialize out, self.$field, $field_type);
                )*
                out
            }
        }

        #[allow(unused_assignments)]
        impl<$generic: Group + GroupEncoding> FromBytes for $struct_name<$generic> {
            fn from_bytes(bytes: &[u8]) -> Result<Self> {
                let elem_len = element_len::<$generic>();
                let _scalar_len = <<$generic as Group>::Scalar as PrimeField>::Repr::default().as_ref().len();
                let mut pos = 0;

                $(
                    let $field = crate::protocol::impl_serialization!(@deserialize bytes, pos, $field_type, elem_len, _scalar_len);
                )*

                Ok($struct_name {
                    $($field),*
                })
            }
        }
    };

    // Serialize based on field type
    (@serialize $out:expr, $field:expr, group) => {
        serialize_element(&mut $out, $field);
    };
    (@serialize $out:expr, $field:expr, scalar) => {
        serialize_scalar(&mut $out, $field);
    };
    (@serialize $out:expr, $field:expr, group_vec) => {
        serialize_elements(&mut $out, &$field);
    };
    (@serialize $out:expr, $field:expr, scalar_vec) => {
        serialize_scalars(&mut $out, &$field);
    };

    // Deserialize based on field type
    (@deserialize $bytes:expr, $pos:expr, group, $elem_len:expr, $scalar_len:expr) => {{
        let field = deserialize_element(&$bytes[$pos..$pos + $elem_len])?;
        $pos += $elem_len;
        field
    }};
    (@deserialize $bytes:expr, $pos:expr, scalar, $elem_len:expr, $scalar_len:expr) => {{
        let field = deserialize_scalar(&$bytes[$pos..$pos + $scalar_len])?;
        $pos += $scalar_len;
        field
    }};
    (@deserialize $bytes:expr, $pos:expr, group_vec, $elem_len:expr, $scalar_len:expr) => {{
        let (buf, _) = $bytes[$pos..].split_at(4);
        let len = deserialize_len(buf);
        $pos += 4;
        let field = deserialize_elements(&$bytes[$pos..$pos + $elem_len * len], len)?;
        $pos += $elem_len * len;
        field
    }};
    (@deserialize $bytes:expr, $pos:expr, scalar_vec, $elem_len:expr, $scalar_len:expr) => {{
        let (buf, _) = $bytes[$pos..].split_at(4);
        let len = deserialize_len(buf);
        $pos += 4;
        let field = deserialize_scalars(&$bytes[$pos..$pos + $elem_len * len], len)?;
        $pos += $elem_len * len;
        field
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Aggregation, dl::DiscreteLog};

    use curve25519_dalek::RistrettoPoint;
    use rand::rngs::OsRng;

    type G = RistrettoPoint;
    type Agg = DiscreteLog<G>;

    /// Tests serialization and deserialization of all protocol types.
    #[test]
    fn basic_serialization() {
        let num_clients = 1;
        let length = 1;
        let (params, sk, cks) = Agg::setup(num_clients, length, &mut OsRng);

        let params_bytes = params.to_bytes();
        let new_params = <Agg as Aggregation>::Params::from_bytes(&params_bytes).unwrap();
        assert_eq!(params, new_params);

        let ck_bytes = cks[0].to_bytes();
        let new_ck = <Agg as Aggregation>::ClientKey::from_bytes(&ck_bytes).unwrap();
        assert_eq!(cks[0], new_ck);

        let (encoding, proof) = Agg::encode(&cks[0], &[1], &mut OsRng).unwrap();

        let enc_bytes = encoding.to_bytes();
        let new_enc = <Agg as Aggregation>::Encoding::from_bytes(&enc_bytes).unwrap();
        assert_eq!(encoding, new_enc);

        let proof_bytes = proof.to_bytes();
        let new_proof = <Agg as Aggregation>::Proof::from_bytes(&proof_bytes).unwrap();
        assert_eq!(proof, new_proof);

        let enc = &[encoding];
        Agg::verify_encodings(&params, None, enc, &[proof]).unwrap();
        let agg = Agg::aggregate(&params, enc).unwrap();
        let partial_results = Agg::decode(&sk, agg).unwrap();

        let partial_result_bytes = partial_results.to_bytes();
        let new_partial_results =
            <Agg as Aggregation>::PartialOutput::from_bytes(&partial_result_bytes).unwrap();
        assert_eq!(partial_results, new_partial_results);

        let results = Agg::post_process(&params, partial_results).unwrap();
        assert_eq!(results[0], 1);
    }
}
