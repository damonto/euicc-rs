use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::error::{EuiccError, Result};
use crate::identifier::decode_base64;

use super::{MAX_LENGTH, Tag, decode_length, encode_length};

/// BER-TLV body, separated by primitive and constructed forms.
///
/// # Arguments
///
/// Variants carry either primitive bytes or nested TLVs.
///
/// # Returns
///
/// A body value that prevents primitive TLVs from holding children and
/// constructed TLVs from holding raw value bytes.
///
/// # Errors
///
/// Constructing this enum does not return errors.
///
/// # Examples
///
/// ```
/// let body = euicc::bertlv::TlvBody::Primitive(vec![0x01]);
/// assert!(matches!(body, euicc::bertlv::TlvBody::Primitive(_)));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlvBody {
    /// Primitive payload bytes.
    Primitive(Vec<u8>),
    /// Constructed child TLVs.
    Constructed(Vec<Tlv>),
}

/// BER-TLV object.
///
/// # Arguments
///
/// Use [`Tlv::primitive`] or [`Tlv::constructed`] to build values with tag/body
/// consistency checked at construction time.
///
/// # Returns
///
/// A tag plus either primitive payload bytes or constructed child TLVs.
///
/// # Errors
///
/// Parsing and encoding return [`EuiccError`] when the wire representation is
/// malformed or too large.
///
/// # Examples
///
/// ```
/// let tlv = euicc::bertlv::Tlv::primitive(
///     euicc::bertlv::Class::ContextSpecific.primitive(0),
///     [0xFF],
/// )?;
/// assert_eq!(tlv.to_bytes()?, vec![0x80, 0x01, 0xFF]);
/// # Ok::<(), euicc::EuiccError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    tag: Tag,
    body: TlvBody,
}

impl Tlv {
    /// Builds a primitive TLV.
    ///
    /// # Arguments
    ///
    /// * `tag` - Primitive BER tag.
    /// * `value` - Payload bytes.
    ///
    /// # Returns
    ///
    /// A primitive TLV.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::PrimitiveExpected`] when `tag` is constructed.
    ///
    /// # Examples
    ///
    /// ```
    /// let tlv = euicc::bertlv::Tlv::primitive(
    ///     euicc::bertlv::Class::ContextSpecific.primitive(0),
    ///     [0xFF],
    /// )?;
    /// assert_eq!(tlv.value(), Some(&[0xFF][..]));
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn primitive(tag: Tag, value: impl Into<Vec<u8>>) -> Result<Self> {
        if !tag.is_primitive() {
            return Err(EuiccError::PrimitiveExpected);
        }
        Ok(Self {
            tag,
            body: TlvBody::Primitive(value.into()),
        })
    }

    /// Builds a constructed TLV.
    ///
    /// # Arguments
    ///
    /// * `tag` - Constructed BER tag.
    /// * `children` - Child TLVs.
    ///
    /// # Returns
    ///
    /// A constructed TLV.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::ConstructedExpected`] when `tag` is primitive.
    ///
    /// # Examples
    ///
    /// ```
    /// let tlv = euicc::bertlv::Tlv::constructed(
    ///     euicc::bertlv::Class::ContextSpecific.constructed(0),
    ///     Vec::new(),
    /// )?;
    /// assert_eq!(tlv.children(), Some(&[][..]));
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn constructed(tag: Tag, children: Vec<Tlv>) -> Result<Self> {
        if !tag.is_constructed() {
            return Err(EuiccError::ConstructedExpected);
        }
        Ok(Self {
            tag,
            body: TlvBody::Constructed(children),
        })
    }

    /// Parses exactly one TLV from bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - BER-TLV bytes.
    ///
    /// # Returns
    ///
    /// The decoded [`Tlv`].
    ///
    /// # Errors
    ///
    /// Returns an error when the tag, length, or child TLV encoding is malformed
    /// or when trailing bytes remain after the first TLV.
    ///
    /// # Examples
    ///
    /// ```
    /// let tlv = euicc::bertlv::Tlv::from_bytes(&[0x80, 0x01, 0xFF])?;
    /// assert_eq!(tlv.value(), Some(&[0xFF][..]));
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let (tlv, consumed) = Self::from_prefix(data)?;
        if consumed != data.len() {
            return Err(EuiccError::MalformedTlv("trailing bytes"));
        }
        Ok(tlv)
    }

    /// Parses one TLV from the front of `data`.
    ///
    /// # Arguments
    ///
    /// * `data` - Bytes beginning with a TLV.
    ///
    /// # Returns
    ///
    /// The decoded [`Tlv`] and consumed byte count.
    ///
    /// # Errors
    ///
    /// Returns an error when the tag, length, value, or children are malformed.
    ///
    /// # Examples
    ///
    /// ```
    /// let (tlv, consumed) = euicc::bertlv::Tlv::from_prefix(&[0x80, 0x01, 0xFF, 0x00])?;
    /// assert_eq!(consumed, 3);
    /// assert_eq!(tlv.value(), Some(&[0xFF][..]));
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn from_prefix(data: &[u8]) -> Result<(Self, usize)> {
        let (tag, tag_len) = Tag::from_prefix(data)?;
        let (length, length_len) = decode_length(
            data.get(tag_len..)
                .ok_or_else(|| EuiccError::LengthEncoding("missing length".to_owned()))?,
        )?;
        let content_start = tag_len + length_len;
        let content_end = content_start
            .checked_add(length)
            .ok_or(EuiccError::LengthTooLarge {
                max: MAX_LENGTH,
                got: usize::MAX,
            })?;
        let content = data
            .get(content_start..content_end)
            .ok_or_else(|| EuiccError::LengthEncoding("content is truncated".to_owned()))?;

        let body = if tag.is_primitive() {
            TlvBody::Primitive(content.to_vec())
        } else {
            let mut children = Vec::new();
            let mut offset = 0usize;
            while offset < content.len() {
                let (child, consumed) = Self::from_prefix(&content[offset..])?;
                if consumed == 0 {
                    return Err(EuiccError::MalformedTlv("zero-length child"));
                }
                offset += consumed;
                children.push(child);
            }
            TlvBody::Constructed(children)
        };

        Ok((Self { tag, body }, content_end))
    }

    /// Parses a base64-encoded TLV.
    ///
    /// # Arguments
    ///
    /// * `text` - Padded or unpadded standard base64 text.
    ///
    /// # Returns
    ///
    /// The decoded [`Tlv`].
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::Base64`] for invalid base64 or TLV parsing errors
    /// for malformed decoded bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let tlv = euicc::bertlv::Tlv::from_base64("gAH/")?;
    /// assert_eq!(tlv.value(), Some(&[0xFF][..]));
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn from_base64(text: &str) -> Result<Self> {
        Self::from_bytes(&decode_base64(text)?)
    }

    /// Encodes this TLV to bytes.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// A newly allocated BER-TLV encoding.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::LengthTooLarge`] when the content exceeds the
    /// three-byte length encoding supported by SGP.22 payloads.
    ///
    /// # Examples
    ///
    /// ```
    /// let tlv = euicc::bertlv::Tlv::primitive(
    ///     euicc::bertlv::Class::ContextSpecific.primitive(0),
    ///     [0xFF],
    /// )?;
    /// assert_eq!(tlv.to_bytes()?, vec![0x80, 0x01, 0xFF]);
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        out.extend_from_slice(&self.header_bytes()?);
        match &self.body {
            TlvBody::Primitive(value) => out.extend_from_slice(value),
            TlvBody::Constructed(children) => {
                for child in children {
                    out.extend_from_slice(&child.to_bytes()?);
                }
            }
        }
        Ok(out)
    }

    /// Encodes this TLV to standard base64 text.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Standard padded base64 text.
    ///
    /// # Errors
    ///
    /// Returns TLV encoding errors from [`Tlv::to_bytes`].
    ///
    /// # Examples
    ///
    /// ```
    /// let tlv = euicc::bertlv::Tlv::primitive(
    ///     euicc::bertlv::Class::ContextSpecific.primitive(0),
    ///     [0xFF],
    /// )?;
    /// assert_eq!(tlv.to_base64()?, "gAH/");
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn to_base64(&self) -> Result<String> {
        Ok(STANDARD.encode(self.to_bytes()?))
    }

    /// Returns this TLV's tag.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Borrowed [`Tag`].
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let tlv = euicc::bertlv::Tlv::primitive(
    ///     euicc::bertlv::Class::ContextSpecific.primitive(0),
    ///     [],
    /// )?;
    /// assert_eq!(tlv.tag().value(), 0);
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    #[must_use]
    pub fn tag(&self) -> &Tag {
        &self.tag
    }

    /// Returns primitive payload bytes when this TLV is primitive.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// `Some(&[u8])` for primitive TLVs, otherwise `None`.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let tlv = euicc::bertlv::Tlv::primitive(
    ///     euicc::bertlv::Class::ContextSpecific.primitive(0),
    ///     [0xFF],
    /// )?;
    /// assert_eq!(tlv.value(), Some(&[0xFF][..]));
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    #[must_use]
    pub fn value(&self) -> Option<&[u8]> {
        match &self.body {
            TlvBody::Primitive(value) => Some(value),
            TlvBody::Constructed(_) => None,
        }
    }

    /// Returns child TLVs when this TLV is constructed.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// `Some(&[Tlv])` for constructed TLVs, otherwise `None`.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let tlv = euicc::bertlv::Tlv::constructed(
    ///     euicc::bertlv::Class::ContextSpecific.constructed(0),
    ///     Vec::new(),
    /// )?;
    /// assert_eq!(tlv.children(), Some(&[][..]));
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    #[must_use]
    pub fn children(&self) -> Option<&[Tlv]> {
        match &self.body {
            TlvBody::Primitive(_) => None,
            TlvBody::Constructed(children) => Some(children),
        }
    }

    /// Finds the first direct child with the requested tag.
    ///
    /// # Arguments
    ///
    /// * `tag` - Tag to match among direct children.
    ///
    /// # Returns
    ///
    /// The first matching child, or `None`.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let child = euicc::bertlv::Tlv::primitive(
    ///     euicc::bertlv::Class::ContextSpecific.primitive(1),
    ///     [0xAA],
    /// )?;
    /// let parent = euicc::bertlv::Tlv::constructed(
    ///     euicc::bertlv::Class::ContextSpecific.constructed(0),
    ///     vec![child],
    /// )?;
    /// assert!(parent.first(&euicc::bertlv::Class::ContextSpecific.primitive(1)).is_some());
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    #[must_use]
    pub fn first(&self, tag: &Tag) -> Option<&Tlv> {
        self.children()?.iter().find(|child| child.tag() == tag)
    }

    /// Finds all direct children with the requested tag.
    ///
    /// # Arguments
    ///
    /// * `tag` - Tag to match among direct children.
    ///
    /// # Returns
    ///
    /// A vector of borrowed matching children.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let child = euicc::bertlv::Tlv::primitive(
    ///     euicc::bertlv::Class::ContextSpecific.primitive(1),
    ///     [0xAA],
    /// )?;
    /// let parent = euicc::bertlv::Tlv::constructed(
    ///     euicc::bertlv::Class::ContextSpecific.constructed(0),
    ///     vec![child],
    /// )?;
    /// assert_eq!(parent.find(&euicc::bertlv::Class::ContextSpecific.primitive(1)).len(), 1);
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    #[must_use]
    pub fn find(&self, tag: &Tag) -> Vec<&Tlv> {
        self.children()
            .unwrap_or_default()
            .iter()
            .filter(|child| child.tag() == tag)
            .collect()
    }

    /// Follows a direct-child tag path.
    ///
    /// # Arguments
    ///
    /// * `tags` - Ordered tag path to follow.
    ///
    /// # Returns
    ///
    /// The nested TLV at the end of the path, or `None`.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let child = euicc::bertlv::Tlv::primitive(
    ///     euicc::bertlv::Class::ContextSpecific.primitive(1),
    ///     [0xAA],
    /// )?;
    /// let parent = euicc::bertlv::Tlv::constructed(
    ///     euicc::bertlv::Class::ContextSpecific.constructed(0),
    ///     vec![child],
    /// )?;
    /// assert!(parent.select(&[euicc::bertlv::Class::ContextSpecific.primitive(1)]).is_some());
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    #[must_use]
    pub fn select(&self, tags: &[Tag]) -> Option<&Tlv> {
        let mut current = self;
        for tag in tags {
            current = current.first(tag)?;
        }
        Some(current)
    }

    /// Returns the complete encoded TLV length.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Number of bytes produced by [`Tlv::to_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::LengthTooLarge`] when nested content exceeds
    /// `0xFF_FF_FF` bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let tlv = euicc::bertlv::Tlv::primitive(
    ///     euicc::bertlv::Class::ContextSpecific.primitive(0),
    ///     vec![0; 127],
    /// )?;
    /// assert_eq!(tlv.encoded_len()?, 129);
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn encoded_len(&self) -> Result<usize> {
        Ok(self.tag.as_bytes().len()
            + encode_length(self.content_len()?)?.len()
            + self.content_len()?)
    }

    /// Returns the encoded tag and length bytes.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Header bytes without value or children.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::LengthTooLarge`] when content exceeds `0xFF_FF_FF`.
    ///
    /// # Examples
    ///
    /// ```
    /// let tlv = euicc::bertlv::Tlv::primitive(
    ///     euicc::bertlv::Class::ContextSpecific.primitive(0),
    ///     [0xFF],
    /// )?;
    /// assert_eq!(tlv.header_bytes()?, vec![0x80, 0x01]);
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn header_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.tag.as_bytes().len() + 4);
        out.extend_from_slice(self.tag.as_bytes());
        out.extend_from_slice(&encode_length(self.content_len()?)?);
        Ok(out)
    }

    /// Returns the encoded content length.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Number of bytes occupied by the value or encoded children.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::LengthTooLarge`] when nested content exceeds
    /// `0xFF_FF_FF` bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let tlv = euicc::bertlv::Tlv::primitive(
    ///     euicc::bertlv::Class::ContextSpecific.primitive(0),
    ///     [0xFF],
    /// )?;
    /// assert_eq!(tlv.content_len()?, 1);
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn content_len(&self) -> Result<usize> {
        let length = match &self.body {
            TlvBody::Primitive(value) => value.len(),
            TlvBody::Constructed(children) => children.iter().try_fold(0usize, |sum, child| {
                Ok::<usize, EuiccError>(sum + child.encoded_len()?)
            })?,
        };
        if length > MAX_LENGTH {
            return Err(EuiccError::LengthTooLarge {
                max: MAX_LENGTH,
                got: length,
            });
        }
        Ok(length)
    }
}

impl Serialize for Tlv {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_base64().map_err(serde::ser::Error::custom)?)
    }
}

impl<'de> Deserialize<'de> for Tlv {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        Self::from_base64(&text).map_err(de::Error::custom)
    }
}
