// TODO: Credit library
use ff::PrimeField;
use group::{Group, GroupEncoding};

pub trait ToBytes {
    fn to_bytes(self) -> Vec<u8>;
}

pub trait FromBytes: Sized {
    fn from_bytes(bytes: &[u8]) -> Result<Self, ()>;
}

impl ToBytes for Vec<u8> {
    fn to_bytes(self) -> Vec<u8> {
        self
    }
}

impl FromBytes for Vec<u8> {
    fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        Ok(bytes.to_vec())
    }
}

pub(super) fn element_len<G: Group + GroupEncoding>() -> usize {
    G::Repr::default().as_ref().len()
}

pub(super) fn serialize_element<G: Group + GroupEncoding>(out: &mut Vec<u8>, elem: G) {
    out.extend_from_slice(elem.to_bytes().as_ref());
}

pub(super) fn serialize_scalar<F: PrimeField>(out: &mut Vec<u8>, scalar: F) {
    out.extend_from_slice(scalar.to_repr().as_ref());
}

pub(super) fn serialize_elements<G: Group + GroupEncoding>(out: &mut Vec<u8>, elements: &[G]) {
    out.extend_from_slice(&(elements.len() as u32).to_be_bytes());
    for elem in elements {
        out.extend_from_slice(elem.to_bytes().as_ref());
    }
}

pub(super) fn deserialize_len(buf: &[u8]) -> usize {
    u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize
}

pub(super) fn deserialize_element<G: Group + GroupEncoding>(buf: &[u8]) -> Result<G, ()> {
    let mut repr = G::Repr::default();
    if buf.len() < repr.as_ref().len() {
        return Err(());
    }
    repr.as_mut().copy_from_slice(buf);
    let elem: Option<G> = G::from_bytes(&repr).into();
    elem.ok_or(())
}

pub(super) fn deserialize_scalar<F: PrimeField>(buf: &[u8]) -> Result<F, ()> {
    let mut repr = F::Repr::default();
    if buf.len() < repr.as_ref().len() {
        return Err(());
    }
    repr.as_mut().copy_from_slice(buf);
    let elem: Option<F> = F::from_repr(repr).into();
    elem.ok_or(())
}

pub(super) fn deserialize_elements<G: Group + GroupEncoding>(
    buf: &[u8],
    count: usize,
) -> Result<Vec<G>, ()> {
    let mut repr = G::Repr::default();
    let elem_size = repr.as_ref().len();
    if buf.len() < count * elem_size {
        return Err(());
    }

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        repr.as_mut()
            .copy_from_slice(&buf[i * elem_size..(i + 1) * elem_size]);
        let elem: Option<G> = G::from_bytes(&repr).into();
        out.push(elem.ok_or(())?);
    }
    Ok(out)
}
