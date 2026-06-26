/// Profile state reported by the eUICC.
///
/// # Errors
///
/// Unknown numeric values are represented by [`Self::Unknown`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProfileState {
    /// Disabled profile.
    Disabled,
    /// Enabled profile.
    Enabled,
    /// Unknown profile state.
    Unknown(i8),
}

impl ProfileState {
    /// Decodes a signed integer profile state.
    #[must_use]
    pub const fn from_i64(value: i64) -> Self {
        match value {
            0 => Self::Disabled,
            1 => Self::Enabled,
            other => Self::Unknown(other as i8),
        }
    }
}
