use std::fmt;

use crate::error::{EuiccError, Result};
use crate::identifier::encode_hex_upper;

const MAX_TAG_BYTES: usize = 11;

/// BER tag class.
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
    #[must_use]
    pub fn primitive(self, value: u64) -> Tag {
        Tag::new(self, Form::Primitive, value)
    }

    /// Builds a constructed tag in this class.
    #[must_use]
    pub fn constructed(self, value: u64) -> Tag {
        Tag::new(self, Form::Constructed, value)
    }
}

/// BER tag form.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Form {
    /// Primitive tag form.
    Primitive = 0,
    /// Constructed tag form.
    Constructed = 1,
}

impl Form {
    /// Builds a universal tag with this form.
    #[must_use]
    pub fn universal(self, value: u64) -> Tag {
        Tag::new(Class::Universal, self, value)
    }

    /// Builds an application tag with this form.
    #[must_use]
    pub fn application(self, value: u64) -> Tag {
        Tag::new(Class::Application, self, value)
    }

    /// Builds a context-specific tag with this form.
    #[must_use]
    pub fn context_specific(self, value: u64) -> Tag {
        Tag::new(Class::ContextSpecific, self, value)
    }

    /// Builds a private tag with this form.
    #[must_use]
    pub fn private(self, value: u64) -> Tag {
        Tag::new(Class::Private, self, value)
    }
}

/// BER tag bytes.
///
/// # Errors
///
/// Parsing from bytes returns [`EuiccError::TagEncoding`] when the encoding is
/// incomplete.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tag(Vec<u8>);

impl Tag {
    /// Builds a BER tag.
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
    /// # Errors
    ///
    /// Returns [`EuiccError::TagEncoding`] when the tag is empty or high-tag
    /// continuation bytes never terminate.
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
    /// # Errors
    ///
    /// Returns [`EuiccError::TagEncoding`] when `bytes` does not contain exactly
    /// one complete BER tag.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (tag, consumed) = Self::from_prefix(bytes)?;
        if consumed != bytes.len() {
            return Err(EuiccError::TagEncoding("trailing tag bytes".to_owned()));
        }
        Ok(tag)
    }

    /// Returns encoded tag bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the BER tag number.
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
    #[must_use]
    pub fn form(&self) -> Form {
        if (self.0[0] >> 5) & 1 == 0 {
            Form::Primitive
        } else {
            Form::Constructed
        }
    }

    /// Returns true for primitive tags.
    #[must_use]
    pub fn is_primitive(&self) -> bool {
        self.form() == Form::Primitive
    }

    /// Returns true for constructed tags.
    #[must_use]
    pub fn is_constructed(&self) -> bool {
        self.form() == Form::Constructed
    }

    /// Returns true for universal tags.
    #[must_use]
    pub fn is_universal(&self) -> bool {
        self.class() == Class::Universal
    }

    /// Returns true for application tags.
    #[must_use]
    pub fn is_application(&self) -> bool {
        self.class() == Class::Application
    }

    /// Returns true for context-specific tags.
    #[must_use]
    pub fn is_context_specific(&self) -> bool {
        self.class() == Class::ContextSpecific
    }

    /// Returns true when class, form, and tag number all match.
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
