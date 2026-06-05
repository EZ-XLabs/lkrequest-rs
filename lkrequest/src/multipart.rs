//! Multipart/form-data request body builder.
//!
//! Supports file uploads and complex form submissions via the
//! `multipart/form-data` content type (RFC 2046 / RFC 7578).
//!
//! # Example
//!
//! ```rust,no_run
//! # use lkrequest::Client;
//! # use lktls::profile::presets;
//! # async fn example() -> Result<(), lkrequest::error::Error> {
//! # let client = Client::builder().fingerprint(presets::chrome_131()).build();
//! # let session = client.session().build();
//! # let image_bytes = vec![0u8; 100];
//! use lkrequest::multipart::{Multipart, Part};
//!
//! let form = Multipart::new()
//!     .text("username", "alice")
//!     .text("bio", "Rustacean")
//!     .file("avatar", "avatar.png", "image/png", image_bytes);
//!
//! let resp = session.post("https://example.com/upload")
//!     .multipart(form)
//!     .send()
//!     .await?;
//! # Ok(())
//! # }
//! ```

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use bytes::Bytes;

/// A multipart/form-data body builder.
///
/// Accumulates [`Part`]s and encodes them into a multipart body when sent.
pub struct Multipart {
    boundary: String,
    parts: Vec<Part>,
}

/// A single part in a multipart form.
pub struct Part {
    name: String,
    filename: Option<String>,
    content_type: Option<String>,
    body: Bytes,
}

impl Part {
    /// Create a new part with the given form field name and body bytes.
    ///
    /// Accepts any type that implements `Into<Bytes>`, including `Vec<u8>`,
    /// `&'static [u8]`, `Bytes`, etc.
    pub fn new(name: &str, body: impl Into<Bytes>) -> Self {
        Self {
            name: name.to_string(),
            filename: None,
            content_type: None,
            body: body.into(),
        }
    }

    /// Set the filename for this part (shown in `Content-Disposition`).
    pub fn filename(mut self, filename: &str) -> Self {
        self.filename = Some(filename.to_string());
        self
    }

    /// Set the MIME content type for this part.
    pub fn content_type(mut self, content_type: &str) -> Self {
        self.content_type = Some(content_type.to_string());
        self
    }
}

impl Default for Multipart {
    fn default() -> Self {
        Self::new()
    }
}

impl Multipart {
    /// Create a new empty multipart form with a random boundary.
    pub fn new() -> Self {
        Self {
            boundary: generate_boundary(),
            parts: Vec::new(),
        }
    }

    /// Add a plain text field.
    pub fn text(mut self, name: &str, value: &str) -> Self {
        self.parts.push(Part {
            name: name.to_string(),
            filename: None,
            content_type: None,
            body: Bytes::copy_from_slice(value.as_bytes()),
        });
        self
    }

    /// Add a file upload field.
    ///
    /// # Arguments
    ///
    /// * `name` - The form field name.
    /// * `filename` - The filename to report to the server.
    /// * `content_type` - The MIME type (e.g. `"image/png"`).
    /// * `data` - The file contents (accepts `Vec<u8>`, `Bytes`, etc.).
    pub fn file(
        mut self,
        name: &str,
        filename: &str,
        content_type: &str,
        data: impl Into<Bytes>,
    ) -> Self {
        self.parts.push(Part {
            name: name.to_string(),
            filename: Some(filename.to_string()),
            content_type: Some(content_type.to_string()),
            body: data.into(),
        });
        self
    }

    /// Add a custom [`Part`].
    pub fn part(mut self, part: Part) -> Self {
        self.parts.push(part);
        self
    }

    /// Returns the `Content-Type` header value including the boundary.
    ///
    /// Example: `multipart/form-data; boundary=----lkrequest8a3b2c1d`
    pub(crate) fn content_type_header(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }

    /// Encode all parts into the multipart body bytes (RFC 2046).
    ///
    /// ```text
    /// --boundary\r\n
    /// Content-Disposition: form-data; name="field"\r\n
    /// \r\n
    /// value\r\n
    /// --boundary\r\n
    /// Content-Disposition: form-data; name="file"; filename="a.txt"\r\n
    /// Content-Type: text/plain\r\n
    /// \r\n
    /// <file data>\r\n
    /// --boundary--\r\n
    /// ```
    pub(crate) fn encode(self) -> Vec<u8> {
        let mut buf = Vec::new();

        for part in &self.parts {
            // Boundary delimiter
            buf.extend_from_slice(b"--");
            buf.extend_from_slice(self.boundary.as_bytes());
            buf.extend_from_slice(b"\r\n");

            // Content-Disposition header
            buf.extend_from_slice(b"Content-Disposition: form-data; name=\"");
            buf.extend_from_slice(part.name.as_bytes());
            buf.push(b'"');

            if let Some(ref filename) = part.filename {
                buf.extend_from_slice(b"; filename=\"");
                buf.extend_from_slice(filename.as_bytes());
                buf.push(b'"');
            }
            buf.extend_from_slice(b"\r\n");

            // Content-Type header (if present)
            if let Some(ref ct) = part.content_type {
                buf.extend_from_slice(b"Content-Type: ");
                buf.extend_from_slice(ct.as_bytes());
                buf.extend_from_slice(b"\r\n");
            }

            // Empty line separating headers from body
            buf.extend_from_slice(b"\r\n");

            // Part body
            buf.extend_from_slice(&part.body);
            buf.extend_from_slice(b"\r\n");
        }

        // Closing boundary
        buf.extend_from_slice(b"--");
        buf.extend_from_slice(self.boundary.as_bytes());
        buf.extend_from_slice(b"--\r\n");

        buf
    }
}

/// Generate a random boundary string.
fn generate_boundary() -> String {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes).expect("RNG failure");
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("----lkrequest{hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multipart_text_only() {
        let form = Multipart::new()
            .text("field1", "value1")
            .text("field2", "value2");

        let ct = form.content_type_header();
        assert!(ct.starts_with("multipart/form-data; boundary="));

        let body = form.encode();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("name=\"field1\""));
        assert!(body_str.contains("value1"));
        assert!(body_str.contains("name=\"field2\""));
        assert!(body_str.contains("value2"));
        assert!(body_str.ends_with("--\r\n"));
    }

    #[test]
    fn test_multipart_with_file() {
        let form = Multipart::new().text("name", "test").file(
            "upload",
            "test.txt",
            "text/plain",
            b"hello world".to_vec(),
        );

        let body = form.encode();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("filename=\"test.txt\""));
        assert!(body_str.contains("Content-Type: text/plain"));
        assert!(body_str.contains("hello world"));
    }

    #[test]
    fn test_multipart_custom_part() {
        let part = Part::new("data", b"binary data".to_vec())
            .filename("data.bin")
            .content_type("application/octet-stream");

        let form = Multipart::new().part(part);
        let body = form.encode();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("name=\"data\""));
        assert!(body_str.contains("filename=\"data.bin\""));
        assert!(body_str.contains("Content-Type: application/octet-stream"));
        assert!(body_str.contains("binary data"));
    }

    #[test]
    fn test_boundary_uniqueness() {
        let b1 = generate_boundary();
        let b2 = generate_boundary();
        assert_ne!(b1, b2);
        assert!(b1.starts_with("----lkrequest"));
    }
}
