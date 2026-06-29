use crate::bertlv::primitive::decode_i64;
use crate::bertlv::{Tag, Tlv};
use crate::error::{EuiccError, Result};

pub(super) fn optional_value(parent: &Tlv, tag: Tag) -> Option<&[u8]> {
    parent.first(&tag).and_then(Tlv::value)
}

pub(super) fn required_value<'a>(
    parent: &'a Tlv,
    tag: Tag,
    name: &'static str,
) -> Result<&'a [u8]> {
    parent
        .first(&tag)
        .and_then(Tlv::value)
        .ok_or(EuiccError::MissingField(name))
}

pub(super) fn required_utf8(parent: &Tlv, tag: Tag, name: &'static str) -> Result<String> {
    let value = required_value(parent, tag, name)?;
    std::str::from_utf8(value)
        .map(str::to_owned)
        .map_err(|_| EuiccError::InvalidText(name))
}

pub(super) fn optional_string(parent: &Tlv, tag: Tag) -> Option<String> {
    optional_value(parent, tag).map(|value| String::from_utf8_lossy(value).into_owned())
}

pub(super) fn optional_int(parent: &Tlv, tag: Tag, max_bytes: usize) -> Result<Option<i64>> {
    optional_value(parent, tag)
        .map(|value| decode_i64(value, max_bytes))
        .transpose()
}
