//! Error types for the lkh2 crate.

/// Errors that can occur during HTTP/2 connection setup.
#[derive(Debug, thiserror::Error)]
pub enum H2Error {
    /// HTTP/2 handshake failed.
    #[error("H2 handshake failed: {0}")]
    Handshake(String),

    /// I/O error during connection.
    #[error("H2 I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type alias for lkh2 operations.
pub type Result<T> = std::result::Result<T, H2Error>;
