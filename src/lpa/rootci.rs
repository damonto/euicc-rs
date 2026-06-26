//! Embedded GSMA Root CI trust anchors used by the default HTTP transport.

use crate::{EuiccError, Result};

const PRODUCTION_BUNDLE: &[u8] = include_bytes!("rootci/bundle.pem");
const TEST_BUNDLE: &[u8] = include_bytes!("rootci/bundle-tests.pem");

pub(crate) fn certificates() -> Result<Vec<reqwest::Certificate>> {
    let production = reqwest::Certificate::from_pem_bundle(PRODUCTION_BUNDLE)
        .map_err(|error| EuiccError::Http(format!("load production Root CI bundle: {error}")))?;
    let test = reqwest::Certificate::from_pem_bundle(TEST_BUNDLE)
        .map_err(|error| EuiccError::Http(format!("load test Root CI bundle: {error}")))?;

    let mut certificates = Vec::with_capacity(production.len() + test.len());
    certificates.extend(production);
    certificates.extend(test);
    Ok(certificates)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_bundles_parse() {
        // Arrange and Act
        let certificates = certificates().expect("embedded GSMA Root CI bundles parse");

        // Assert
        assert!(!certificates.is_empty());
    }
}
