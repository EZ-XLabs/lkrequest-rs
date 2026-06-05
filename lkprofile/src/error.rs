//! Error types for profile parsing.

/// Errors that can occur while parsing TLS or HTTP/2 data.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// The input data is too short or truncated.
    #[error("data too short: {0}")]
    DataTooShort(String),

    /// The input data contains an unexpected value.
    #[error("unexpected value: {0}")]
    UnexpectedValue(String),

    /// I/O error while reading from a stream or buffer.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
