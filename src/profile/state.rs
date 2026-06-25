/// Profile state reported by the eUICC.
///
/// # Arguments
///
/// Values are decoded from signed integer BER payloads.
///
/// # Returns
///
/// A typed profile state.
///
/// # Errors
///
/// Unknown numeric values are represented by [`Self::Unknown`].
///
/// # Examples
///
/// ```
/// assert_eq!(
///     euicc::profile::ProfileState::from_i64(1),
///     euicc::profile::ProfileState::Enabled,
/// );
/// ```
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
    ///
    /// # Arguments
    ///
    /// * `value` - Signed integer profile state.
    ///
    /// # Returns
    ///
    /// A typed profile state, preserving unknown values.
    ///
    /// # Errors
    ///
    /// This method does not return errors.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(
    ///     euicc::profile::ProfileState::from_i64(0),
    ///     euicc::profile::ProfileState::Disabled,
    /// );
    /// ```
    #[must_use]
    pub const fn from_i64(value: i64) -> Self {
        match value {
            0 => Self::Disabled,
            1 => Self::Enabled,
            other => Self::Unknown(other as i8),
        }
    }
}
