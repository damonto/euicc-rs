/// Profile icon bytes.
///
/// # Arguments
///
/// This type is built from raw icon bytes.
///
/// # Returns
///
/// An icon wrapper with light MIME sniffing helpers.
///
/// # Errors
///
/// Constructing this type does not return errors.
///
/// # Examples
///
/// ```
/// let icon = euicc::profile::ProfileIcon::from_bytes([0x89, b'P', b'N', b'G']);
/// assert_eq!(icon.file_type(), Some("image/png"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileIcon(Vec<u8>);

impl ProfileIcon {
    /// Builds a profile icon from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Icon payload bytes.
    ///
    /// # Returns
    ///
    /// A [`ProfileIcon`] owning `bytes`.
    ///
    /// # Errors
    ///
    /// This function does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let icon = euicc::profile::ProfileIcon::from_bytes([0xFF, 0xD8, 0xFF, 0xDB]);
    /// assert_eq!(icon.file_type(), Some("image/jpeg"));
    /// ```
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Returns icon bytes.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// Borrowed icon bytes.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let icon = euicc::profile::ProfileIcon::from_bytes([0x89]);
    /// assert_eq!(icon.as_bytes(), &[0x89]);
    /// ```
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the detected image MIME type.
    ///
    /// # Arguments
    ///
    /// This method takes no arguments.
    ///
    /// # Returns
    ///
    /// `Some("image/jpeg")`, `Some("image/png")`, or `None`.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// let icon = euicc::profile::ProfileIcon::from_bytes([0x89, b'P', b'N', b'G']);
    /// assert_eq!(icon.file_type(), Some("image/png"));
    /// ```
    #[must_use]
    pub fn file_type(&self) -> Option<&'static str> {
        if self.0.starts_with(&[0xFF, 0xD8, 0xFF, 0xDB]) {
            return Some("image/jpeg");
        }
        if self.0.starts_with(b"\x89PNG") {
            return Some("image/png");
        }
        None
    }
}

/// Profile icon type reported by the eUICC.
///
/// # Arguments
///
/// Values are decoded from signed integer BER payloads.
///
/// # Returns
///
/// A typed icon format.
///
/// # Errors
///
/// Unknown numeric values are represented by [`Self::Unknown`].
///
/// # Examples
///
/// ```
/// assert_eq!(
///     euicc::profile::ProfileIconType::from_i64(1),
///     euicc::profile::ProfileIconType::Png,
/// );
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProfileIconType {
    /// JPEG profile icon.
    Jpg,
    /// PNG profile icon.
    Png,
    /// Unknown profile icon type.
    Unknown(i8),
}

impl ProfileIconType {
    /// Decodes a signed integer profile icon type.
    ///
    /// # Arguments
    ///
    /// * `value` - Signed integer icon type.
    ///
    /// # Returns
    ///
    /// A typed icon type, preserving unknown values.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(
    ///     euicc::profile::ProfileIconType::from_i64(0),
    ///     euicc::profile::ProfileIconType::Jpg,
    /// );
    /// ```
    #[must_use]
    pub const fn from_i64(value: i64) -> Self {
        match value {
            0 => Self::Jpg,
            1 => Self::Png,
            other => Self::Unknown(other as i8),
        }
    }
}
