//! Load [`TlsProfile`] instances from JSON files or strings.

use super::types::TlsProfile;
use crate::error::{Result, TlsError};

/// Load a `TlsProfile` from a JSON string.
pub fn from_json_str(json_str: &str) -> Result<TlsProfile> {
    serde_json::from_str(json_str).map_err(|e| TlsError::InvalidProfile(e.to_string()))
}

/// Load a `TlsProfile` from a JSON file at the given path.
pub fn from_json_file(path: impl AsRef<std::path::Path>) -> Result<TlsProfile> {
    let contents = std::fs::read_to_string(path.as_ref()).map_err(TlsError::Io)?;
    from_json_str(&contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::types::TlsClientHelloStyle;

    #[test]
    fn load_chrome_131_json_file() {
        let profile = from_json_file("profiles/chrome_131.json").unwrap();
        assert_eq!(profile.name, "Chrome 131");
        assert!(!profile.cipher_suites.is_empty());
        assert!(!profile.extensions.is_empty());
    }

    #[test]
    fn load_chrome_144_json_file() {
        let profile = from_json_file("profiles/chrome_144.json").unwrap();
        assert_eq!(profile.name, "Chrome 144");
        assert!(!profile.cipher_suites.is_empty(), "cipher suites must load");
        assert!(!profile.extensions.is_empty(), "extensions must load");
    }

    #[test]
    fn load_firefox_147_json_file() {
        let profile = from_json_file("profiles/firefox_147.json").unwrap();
        assert!(profile.name.contains("Firefox"));
        assert!(!profile.cipher_suites.is_empty(), "cipher suites must load");
        assert!(!profile.extensions.is_empty(), "extensions must load");
    }

    #[test]
    fn load_safari_26_json_file() {
        let profile = from_json_file("profiles/safari_26.json").unwrap();
        assert!(profile.name.contains("Safari"));
        assert!(!profile.cipher_suites.is_empty(), "cipher suites must load");
        assert!(!profile.extensions.is_empty(), "extensions must load");
    }

    #[test]
    fn load_charles_5_1_json_file() {
        let profile = from_json_file("profiles/charles_5_1.json").unwrap();
        assert_eq!(
            profile.tls_client_hello_style,
            TlsClientHelloStyle::JavaJsse
        );
    }

    #[test]
    fn from_json_str_missing_style_defaults_to_generic() {
        let json = r#"{
            "name": "legacy profile",
            "tls_min_version": "tls12",
            "tls_max_version": "tls13",
            "cipher_suites": [4865],
            "extensions": [],
            "supported_groups": [29],
            "signature_algorithms": [1027],
            "key_share_curves": [29]
        }"#;

        let profile = from_json_str(json).unwrap();
        assert_eq!(profile.tls_client_hello_style, TlsClientHelloStyle::Generic);
    }

    #[test]
    fn from_json_str_empty_string_is_error() {
        let result = from_json_str("");
        assert!(result.is_err());
    }

    #[test]
    fn from_json_str_invalid_json_is_error() {
        let result = from_json_str("{not valid json}");
        assert!(result.is_err());
    }

    #[test]
    fn from_json_str_missing_required_fields_is_error() {
        let result = from_json_str(r#"{"name": "test"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn from_json_file_nonexistent_is_io_error() {
        let result = from_json_file("/nonexistent/path/profile.json");
        assert!(result.is_err());
        match result.unwrap_err() {
            TlsError::Io(_) => {}
            other => panic!("expected Io error, got: {:?}", other),
        }
    }
}
