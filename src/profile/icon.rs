/// Profile icon bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileIcon(Vec<u8>);

impl ProfileIcon {
    /// Builds a profile icon from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Returns icon bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the detected image MIME type.
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
/// # Errors
///
/// Unknown numeric values are represented by [`Self::Unknown`].
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
    #[must_use]
    pub const fn from_i64(value: i64) -> Self {
        match value {
            0 => Self::Jpg,
            1 => Self::Png,
            other => Self::Unknown(other as i8),
        }
    }
}
