use std::fmt;

use crate::error::{EuiccError, Result};
use crate::identifier::encode_hex_upper;

const MAX_TAG_BYTES: usize = 11;

/// BER tag class.
///
/// # Arguments
///
/// Variants map directly to the top two bits of the first tag byte.
///
/// # Returns
///
/// A typed tag class used to construct or inspect [`Tag`] values.
///
/// # Errors
///
/// Constructing this enum does not return errors.
///
/// # Examples
///
/// ```
/// let tag = euicc::bertlv::Class::ContextSpecific.primitive(0);
/// assert!(tag.is_context_specific());
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Class {
    /// Universal ASN.1 tag class.
    Universal = 0,
    /// Application tag class.
    Application = 1,
    /// Context-specific tag class.
    ContextSpecific = 2,
    /// Private tag class.
    Private = 3,
}

impl Class {
    /// Builds a primitive tag in this class.
    ///
    /// # Arguments
    ///
    /// * `value` - BER tag number.
    ///
    /// # Returns
    ///
    /// A primitive [`Tag`].
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(
    ///     euicc::bertlv::Class::Application.primitive(26).as_bytes(),
    ///     &[0x5A],
    /// );
    /// ```
    #[must_use]
    pub fn primitive(self, value: u64) -> Tag {
        Tag::new(self, Form::Primitive, value)
    }

    /// Builds a constructed tag in this class.
    ///
    /// # Arguments
    ///
    /// * `value` - BER tag number.
    ///
    /// # Returns
    ///
    /// A constructed [`Tag`].
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(
    ///     euicc::bertlv::Class::ContextSpecific.constructed(60).as_bytes(),
    ///     &[0xBF, 0x3C],
    /// );
    /// ```
    #[must_use]
    pub fn constructed(self, value: u64) -> Tag {
        Tag::new(self, Form::Constructed, value)
    }
}

/// BER tag form.
///
/// # Arguments
///
/// Variants map to the constructed bit of the first tag byte.
///
/// # Returns
///
/// A typed tag form used to construct or inspect [`Tag`] values.
///
/// # Errors
///
/// Constructing this enum does not return errors.
///
/// # Examples
///
/// ```
/// let tag = euicc::bertlv::Form::Constructed.context_specific(0);
/// assert!(tag.is_constructed());
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Form {
    /// Primitive tag form.
    Primitive = 0,
    /// Constructed tag form.
    Constructed = 1,
}

impl Form {
    /// Builds a universal tag with this form.
    ///
    /// # Arguments
    ///
    /// * `value` - BER tag number.
    ///
    /// # Returns
    ///
    /// A [`Tag`] in the universal class.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(euicc::bertlv::Form::Primitive.universal(12).as_bytes(), &[0x0C]);
    /// ```
    #[must_use]
    pub fn universal(self, value: u64) -> Tag {
        Tag::new(Class::Universal, self, value)
    }

    /// Builds an application tag with this form.
    ///
    /// # Arguments
    ///
    /// * `value` - BER tag number.
    ///
    /// # Returns
    ///
    /// A [`Tag`] in the application class.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(euicc::bertlv::Form::Primitive.application(26).as_bytes(), &[0x5A]);
    /// ```
    #[must_use]
    pub fn application(self, value: u64) -> Tag {
        Tag::new(Class::Application, self, value)
    }

    /// Builds a context-specific tag with this form.
    ///
    /// # Arguments
    ///
    /// * `value` - BER tag number.
    ///
    /// # Returns
    ///
    /// A [`Tag`] in the context-specific class.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(
    ///     euicc::bertlv::Form::Constructed.context_specific(54).as_bytes(),
    ///     &[0xBF, 0x36],
    /// );
    /// ```
    #[must_use]
    pub fn context_specific(self, value: u64) -> Tag {
        Tag::new(Class::ContextSpecific, self, value)
    }

    /// Builds a private tag with this form.
    ///
    /// # Arguments
    ///
    /// * `value` - BER tag number.
    ///
    /// # Returns
    ///
    /// A [`Tag`] in the private class.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(euicc::bertlv::Form::Constructed.private(3).as_bytes(), &[0xE3]);
    /// ```
    #[must_use]
    pub fn private(self, value: u64) -> Tag {
        Tag::new(Class::Private, self, value)
    }
}

/// BER tag bytes.
///
/// # Arguments
///
/// Create tags with [`Tag::new`] or the convenience methods on [`Class`] and
/// [`Form`].
///
/// # Returns
///
/// A tag wrapper that can be compared, displayed, and used to select child TLVs.
///
/// # Errors
///
/// Parsing from bytes returns [`EuiccError::TagEncoding`] when the encoding is
/// incomplete.
///
/// # Examples
///
/// ```
/// let tag = euicc::bertlv::Tag::new(
///     euicc::bertlv::Class::ContextSpecific,
///     euicc::bertlv::Form::Constructed,
///     0x7F,
/// );
/// assert_eq!(tag.as_bytes(), &[0xBF, 0x7F]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tag(Vec<u8>);

impl Tag {
    /// Builds a BER tag.
    ///
    /// # Arguments
    ///
    /// * `class` - BER tag class.
    /// * `form` - Primitive or constructed form.
    /// * `value` - BER tag number.
    ///
    /// # Returns
    ///
    /// A BER tag encoded with short or high-tag-number form.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let tag = euicc::bertlv::Tag::new(
    ///     euicc::bertlv::Class::ContextSpecific,
    ///     euicc::bertlv::Form::Constructed,
    ///     0x80,
    /// );
    /// assert_eq!(tag.as_bytes(), &[0xBF, 0x81, 0x00]);
    /// ```
    #[must_use]
    pub fn new(class: Class, form: Form, value: u64) -> Self {
        let mask = ((class as u8) << 6) | ((form as u8) << 5);
        if value < 0x1F {
            return Self(vec![mask | value as u8]);
        }

        let mut groups = Vec::with_capacity(10);
        let mut remaining = value;
        groups.push((remaining & 0x7F) as u8);
        remaining >>= 7;
        while remaining > 0 {
            groups.push(((remaining & 0x7F) as u8) | 0x80);
            remaining >>= 7;
        }
        groups.reverse();

        let mut bytes = Vec::with_capacity(1 + groups.len());
        bytes.push(mask | 0x1F);
        bytes.extend(groups);
        Self(bytes)
    }

    /// Parses one BER tag from the front of `data`.
    ///
    /// # Arguments
    ///
    /// * `data` - Bytes starting with a BER tag.
    ///
    /// # Returns
    ///
    /// The parsed tag and number of consumed bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::TagEncoding`] when the tag is empty or high-tag
    /// continuation bytes never terminate.
    ///
    /// # Examples
    ///
    /// ```
    /// let (tag, consumed) = euicc::bertlv::Tag::from_prefix(&[0xBF, 0x81, 0x00])?;
    /// assert_eq!(tag.value(), 128);
    /// assert_eq!(consumed, 3);
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn from_prefix(data: &[u8]) -> Result<(Self, usize)> {
        let Some(&first) = data.first() else {
            return Err(EuiccError::TagEncoding(
                "encoding has less than one byte".to_owned(),
            ));
        };
        if first & 0x1F != 0x1F {
            return Ok((Self(vec![first]), 1));
        }
        for index in 1..data.len().min(MAX_TAG_BYTES) {
            if data[index] >> 7 == 0 {
                let tag = Self(data[..=index].to_vec());
                tag.validate_high_tag_number()?;
                return Ok((tag, index + 1));
            }
        }
        Err(EuiccError::TagEncoding(
            "high-tag-number encoding is incomplete".to_owned(),
        ))
    }

    /// Builds a tag from exact bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Complete BER tag bytes.
    ///
    /// # Returns
    ///
    /// A parsed [`Tag`].
    ///
    /// # Errors
    ///
    /// Returns [`EuiccError::TagEncoding`] when `bytes` does not contain exactly
    /// one complete BER tag.
    ///
    /// # Examples
    ///
    /// ```
    /// let tag = euicc::bertlv::Tag::from_bytes(&[0xBF, 0x36])?;
    /// assert_eq!(tag.value(), 54);
    /// # Ok::<(), euicc::EuiccError>(())
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (tag, consumed) = Self::from_prefix(bytes)?;
        if consumed != bytes.len() {
            return Err(EuiccError::TagEncoding("trailing tag bytes".to_owned()));
        }
        Ok(tag)
    }

    /// Returns encoded tag bytes.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Borrowed encoded tag bytes.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(euicc::bertlv::Class::Private.constructed(3).as_bytes(), &[0xE3]);
    /// ```
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the BER tag number.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// The decoded tag number.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(euicc::bertlv::Class::ContextSpecific.constructed(54).value(), 54);
    /// ```
    #[must_use]
    pub fn value(&self) -> u64 {
        let value = self.0[0] & 0x1F;
        if value != 0x1F {
            return u64::from(value);
        }

        let mut out = 0u64;
        for byte in &self.0[1..] {
            out <<= 7;
            out |= u64::from(byte & 0x7F);
            if byte >> 7 == 0 {
                break;
            }
        }
        out
    }

    /// Returns the BER tag class.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// The decoded tag class.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(
    ///     euicc::bertlv::Class::Application.primitive(26).class(),
    ///     euicc::bertlv::Class::Application,
    /// );
    /// ```
    #[must_use]
    pub fn class(&self) -> Class {
        match self.0[0] >> 6 {
            0 => Class::Universal,
            1 => Class::Application,
            2 => Class::ContextSpecific,
            _ => Class::Private,
        }
    }

    /// Returns the BER tag form.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// The decoded primitive or constructed form.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(
    ///     euicc::bertlv::Class::Application.primitive(26).form(),
    ///     euicc::bertlv::Form::Primitive,
    /// );
    /// ```
    #[must_use]
    pub fn form(&self) -> Form {
        if (self.0[0] >> 5) & 1 == 0 {
            Form::Primitive
        } else {
            Form::Constructed
        }
    }

    /// Returns true for primitive tags.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// `true` when the tag form is primitive.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(euicc::bertlv::Class::Application.primitive(26).is_primitive());
    /// ```
    #[must_use]
    pub fn is_primitive(&self) -> bool {
        self.form() == Form::Primitive
    }

    /// Returns true for constructed tags.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// `true` when the tag form is constructed.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(euicc::bertlv::Class::Private.constructed(3).is_constructed());
    /// ```
    #[must_use]
    pub fn is_constructed(&self) -> bool {
        self.form() == Form::Constructed
    }

    /// Returns true for universal tags.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// `true` when the tag class is universal.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(euicc::bertlv::Class::Universal.primitive(12).is_universal());
    /// ```
    #[must_use]
    pub fn is_universal(&self) -> bool {
        self.class() == Class::Universal
    }

    /// Returns true for application tags.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// `true` when the tag class is application.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(euicc::bertlv::Class::Application.primitive(26).is_application());
    /// ```
    #[must_use]
    pub fn is_application(&self) -> bool {
        self.class() == Class::Application
    }

    /// Returns true for context-specific tags.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// `true` when the tag class is context-specific.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(euicc::bertlv::Class::ContextSpecific.constructed(60).is_context_specific());
    /// ```
    #[must_use]
    pub fn is_context_specific(&self) -> bool {
        self.class() == Class::ContextSpecific
    }

    /// Returns true when class, form, and tag number all match.
    ///
    /// # Arguments
    ///
    /// * `class` - Expected BER class.
    /// * `form` - Expected BER form.
    /// * `value` - Expected tag number.
    ///
    /// # Returns
    ///
    /// `true` when all tag components match.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let tag = euicc::bertlv::Class::ContextSpecific.constructed(60);
    /// assert!(tag.is(euicc::bertlv::Class::ContextSpecific, euicc::bertlv::Form::Constructed, 60));
    /// ```
    #[must_use]
    pub fn is(&self, class: Class, form: Form, value: u64) -> bool {
        self.class() == class && self.form() == form && self.value() == value
    }

    pub(crate) fn hex(&self) -> String {
        encode_hex_upper(&self.0)
    }

    fn validate_high_tag_number(&self) -> Result<()> {
        let Some(&first_continuation) = self.0.get(1) else {
            return Err(EuiccError::TagEncoding(
                "high-tag-number encoding has no value octets".to_owned(),
            ));
        };
        if first_continuation & 0x7F == 0 {
            return Err(EuiccError::TagEncoding(
                "high-tag-number first value octet is zero".to_owned(),
            ));
        }
        if self.value() < 0x1F {
            return Err(EuiccError::TagEncoding(
                "high-tag-number form used for a short tag".to_owned(),
            ));
        }
        Ok(())
    }
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.class() {
            Class::Universal => write!(f, "[UNIVERSAL {}]", self.value()),
            Class::Application => write!(f, "[APPLICATION {}]", self.value()),
            Class::Private => write!(f, "[PRIVATE {}]", self.value()),
            Class::ContextSpecific => write!(f, "[{}]", self.value()),
        }
    }
}
