use std::fmt;

/// SGP.22 profile class value.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProfileClass {
    /// Test profile.
    Test,
    /// Provisioning profile.
    Provisioning,
    /// Operational profile.
    Operational,
    /// Unknown profile class value.
    Unknown(i8),
}

impl ProfileClass {
    /// Decodes a signed integer profile class.
    #[must_use]
    pub const fn from_i64(value: i64) -> Self {
        match value {
            0 => Self::Test,
            1 => Self::Provisioning,
            2 => Self::Operational,
            other => Self::Unknown(other as i8),
        }
    }

    /// Returns a human-readable class label.
    #[must_use]
    pub fn as_str(self) -> String {
        match self {
            Self::Test => "test".to_owned(),
            Self::Provisioning => "provisioning".to_owned(),
            Self::Operational => "operational".to_owned(),
            Self::Unknown(value) => format!("unknown({value})"),
        }
    }
}

impl fmt::Display for ProfileClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}
