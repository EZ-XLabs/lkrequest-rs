//! # pcap_diff — Byte-level ClientHello comparison tool
//!
//! Compares two ClientHello hex dumps byte-by-byte with TLS field annotations.
//!
//! ## Usage
//!
//! ```bash
//! # Compare generated ClientHello against Chrome 131 baseline
//! pcap-diff --generated output.hex --baseline baselines/chrome_131.hex
//!
//! # Read from stdin (pipe from builder)
//! echo "160301..." | pcap-diff --baseline baselines/chrome_131.hex
//!
//! # Dump field annotations only (no diff)
//! pcap-diff --annotate baselines/chrome_131.hex
//! ```

use clap::{Parser, Subcommand};
use colored::Colorize;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

// =============================================================================
// CLI
// =============================================================================

#[derive(Parser)]
#[command(
    name = "pcap-diff",
    about = "Byte-level ClientHello comparison tool with TLS field annotations"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compare two ClientHello hex dumps byte-by-byte
    Diff {
        /// Path to the generated ClientHello hex file (or "-" for stdin)
        #[arg(short, long)]
        generated: String,

        /// Path to the baseline (real browser) ClientHello hex file
        #[arg(short, long)]
        baseline: PathBuf,

        /// Number of context bytes to show around differences
        #[arg(short, long, default_value = "8")]
        context: usize,
    },

    /// Annotate a single ClientHello hex dump with TLS field names
    Annotate {
        /// Path to the hex file to annotate (or "-" for stdin)
        input: String,
    },

    /// Show summary statistics of a ClientHello
    Info {
        /// Path to the hex file (or "-" for stdin)
        input: String,
    },
}

// =============================================================================
// TLS Field Annotation Engine
// =============================================================================

/// A region of bytes within a ClientHello and its TLS field name.
#[derive(Debug, Clone)]
struct FieldRegion {
    offset: usize,
    length: usize,
    name: String,
}

/// Known TLS extension type codes → human-readable names.
fn extension_name(ext_type: u16) -> &'static str {
    match ext_type {
        0x0000 => "server_name (SNI)",
        0x0001 => "max_fragment_length",
        0x0005 => "status_request (OCSP)",
        0x000a => "supported_groups",
        0x000b => "ec_point_formats",
        0x000d => "signature_algorithms",
        0x0010 => "application_layer_protocol_negotiation (ALPN)",
        0x0011 => "signed_certificate_timestamp (SCT)",
        0x0012 => "client_certificate_type",
        0x0013 => "server_certificate_type",
        0x0015 => "padding",
        0x0016 => "encrypt_then_mac",
        0x0017 => "extended_master_secret",
        0x001b => "compress_certificate",
        0x001c => "record_size_limit",
        0x0022 => "delegated_credentials",
        0x0023 => "session_ticket",
        0x002b => "supported_versions",
        0x002d => "psk_key_exchange_modes",
        0x0033 => "key_share",
        0x0039 => "post_handshake_auth",
        0x4469 => "application_settings (ALPS legacy)",
        0x44cd => "application_settings (ALPS)",
        0xfe0d => "encrypted_client_hello (ECH)",
        0xff01 => "renegotiation_info",
        _ => {
            if ext_type & 0x0f0f == 0x0a0a {
                "GREASE"
            } else {
                "unknown"
            }
        }
    }
}

/// Parse a ClientHello byte sequence and annotate each field region.
///
/// Expected input: raw TLS record starting with the record header (16 03 01 ...),
/// or just the Handshake message starting with 01 (ClientHello handshake type).
fn annotate_client_hello(data: &[u8]) -> Vec<FieldRegion> {
    let mut regions = Vec::new();
    let mut pos = 0;

    // --- TLS Record Header (5 bytes) ---
    // Some inputs may start with the record header, some may not.
    let handshake_start;
    if data.len() >= 6 && data[0] == 0x16 {
        // ContentType: Handshake (0x16)
        regions.push(FieldRegion {
            offset: 0,
            length: 1,
            name: "Record: ContentType (0x16 = Handshake)".into(),
        });
        regions.push(FieldRegion {
            offset: 1,
            length: 2,
            name: format!("Record: ProtocolVersion (0x{:02x}{:02x})", data[1], data[2]),
        });
        let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        regions.push(FieldRegion {
            offset: 3,
            length: 2,
            name: format!("Record: Length ({record_len})"),
        });
        pos = 5;
        handshake_start = 5;
    } else if !data.is_empty() && data[0] == 0x01 {
        handshake_start = 0;
    } else {
        regions.push(FieldRegion {
            offset: 0,
            length: data.len(),
            name: "Unknown format (expected TLS Record or Handshake)".into(),
        });
        return regions;
    }

    // --- Handshake Header (4 bytes) ---
    if pos + 4 > data.len() {
        return regions;
    }
    regions.push(FieldRegion {
        offset: pos,
        length: 1,
        name: format!(
            "Handshake: Type (0x{:02x} = {})",
            data[pos],
            if data[pos] == 0x01 {
                "ClientHello"
            } else {
                "Other"
            }
        ),
    });
    let hs_len =
        ((data[pos + 1] as usize) << 16) | ((data[pos + 2] as usize) << 8) | data[pos + 3] as usize;
    regions.push(FieldRegion {
        offset: pos + 1,
        length: 3,
        name: format!("Handshake: Length ({hs_len})"),
    });
    pos = handshake_start + 4;

    // --- ClientHello fields ---

    // ProtocolVersion (2 bytes)
    if pos + 2 > data.len() {
        return regions;
    }
    regions.push(FieldRegion {
        offset: pos,
        length: 2,
        name: format!(
            "ClientHello: ProtocolVersion (0x{:02x}{:02x})",
            data[pos],
            data[pos + 1]
        ),
    });
    pos += 2;

    // Random (32 bytes)
    if pos + 32 > data.len() {
        return regions;
    }
    regions.push(FieldRegion {
        offset: pos,
        length: 32,
        name: "ClientHello: Random (32 bytes)".into(),
    });
    pos += 32;

    // Session ID
    if pos + 1 > data.len() {
        return regions;
    }
    let session_id_len = data[pos] as usize;
    regions.push(FieldRegion {
        offset: pos,
        length: 1,
        name: format!("ClientHello: SessionID Length ({session_id_len})"),
    });
    pos += 1;
    if session_id_len > 0 {
        if pos + session_id_len > data.len() {
            return regions;
        }
        regions.push(FieldRegion {
            offset: pos,
            length: session_id_len,
            name: format!("ClientHello: SessionID ({session_id_len} bytes)"),
        });
        pos += session_id_len;
    }

    // Cipher Suites
    if pos + 2 > data.len() {
        return regions;
    }
    let cs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    regions.push(FieldRegion {
        offset: pos,
        length: 2,
        name: format!(
            "ClientHello: CipherSuites Length ({cs_len} bytes, {} suites)",
            cs_len / 2
        ),
    });
    pos += 2;

    // Individual cipher suites
    let cs_end = pos + cs_len;
    if cs_end > data.len() {
        return regions;
    }
    let mut suite_idx = 0;
    while pos + 2 <= cs_end {
        let suite = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let suite_name = cipher_suite_name(suite);
        regions.push(FieldRegion {
            offset: pos,
            length: 2,
            name: format!("  CipherSuite[{suite_idx}]: 0x{suite:04x} ({suite_name})"),
        });
        pos += 2;
        suite_idx += 1;
    }

    // Compression Methods
    if pos + 1 > data.len() {
        return regions;
    }
    let comp_len = data[pos] as usize;
    regions.push(FieldRegion {
        offset: pos,
        length: 1,
        name: format!("ClientHello: CompressionMethods Length ({comp_len})"),
    });
    pos += 1;
    if comp_len > 0 {
        if pos + comp_len > data.len() {
            return regions;
        }
        regions.push(FieldRegion {
            offset: pos,
            length: comp_len,
            name: format!("ClientHello: CompressionMethods ({comp_len} bytes)"),
        });
        pos += comp_len;
    }

    // Extensions
    if pos + 2 > data.len() {
        return regions;
    }
    let ext_total_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    regions.push(FieldRegion {
        offset: pos,
        length: 2,
        name: format!("ClientHello: Extensions Length ({ext_total_len})"),
    });
    pos += 2;

    let ext_end = pos + ext_total_len;
    let mut ext_idx = 0;

    while pos + 4 <= ext_end && pos + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        let ext_name = extension_name(ext_type);

        regions.push(FieldRegion {
            offset: pos,
            length: 2,
            name: format!("  Extension[{ext_idx}]: Type 0x{ext_type:04x} ({ext_name})"),
        });
        regions.push(FieldRegion {
            offset: pos + 2,
            length: 2,
            name: format!("  Extension[{ext_idx}]: Length ({ext_data_len})"),
        });

        if ext_data_len > 0 {
            let actual_len = ext_data_len.min(data.len().saturating_sub(pos + 4));
            regions.push(FieldRegion {
                offset: pos + 4,
                length: actual_len,
                name: format!("  Extension[{ext_idx}]: Data ({ext_name}, {actual_len} bytes)"),
            });
        }

        pos += 4 + ext_data_len;
        ext_idx += 1;
    }

    regions
}

/// Known cipher suite codes → names.
fn cipher_suite_name(suite: u16) -> &'static str {
    match suite {
        0x000a => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x003c => "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003d => "TLS_RSA_WITH_AES_256_CBC_SHA256",
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0xc008 => "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        0xc009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        0xc00a => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        0xc012 => "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        0xc013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0xc023 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        0xc024 => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        0xc027 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xc028 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        _ => {
            if suite & 0x0f0f == 0x0a0a {
                "GREASE"
            } else {
                "unknown"
            }
        }
    }
}

// =============================================================================
// Hex I/O
// =============================================================================

/// Read hex data from a file path or stdin ("-").
fn read_hex(source: &str) -> Result<Vec<u8>, String> {
    let raw = if source == "-" {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("Failed to read stdin: {e}"))?;
        buf
    } else {
        fs::read_to_string(source).map_err(|e| format!("Failed to read {source}: {e}"))?
    };

    // Strip whitespace, "0x" prefixes, newlines, comments (lines starting with #)
    let cleaned: String = raw
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .flat_map(|line| line.chars())
        .filter(|c| c.is_ascii_hexdigit())
        .collect();

    hex::decode(&cleaned).map_err(|e| format!("Invalid hex: {e}"))
}

// =============================================================================
// Diff Engine
// =============================================================================

/// A single byte difference.
struct ByteDiff {
    offset: usize,
    expected: Option<u8>,
    actual: Option<u8>,
    field: String,
}

/// Find the TLS field name for a given offset.
fn field_at_offset(regions: &[FieldRegion], offset: usize) -> String {
    for region in regions.iter().rev() {
        if offset >= region.offset && offset < region.offset + region.length {
            return format!("{} (byte {} of field)", region.name, offset - region.offset);
        }
    }
    "unknown field".into()
}

/// Compare two byte arrays and produce annotated diffs.
fn compute_diff(baseline: &[u8], generated: &[u8], regions: &[FieldRegion]) -> Vec<ByteDiff> {
    let max_len = baseline.len().max(generated.len());
    let mut diffs = Vec::new();

    for i in 0..max_len {
        let b = baseline.get(i).copied();
        let g = generated.get(i).copied();

        if b != g {
            diffs.push(ByteDiff {
                offset: i,
                expected: b,
                actual: g,
                field: field_at_offset(regions, i),
            });
        }
    }

    diffs
}

// =============================================================================
// Output Formatting
// =============================================================================

fn print_diff_report(diffs: &[ByteDiff], baseline_len: usize, generated_len: usize) {
    println!("{}", "═══ pcap-diff Report ═══".bold());
    println!();
    println!("Baseline:  {} bytes", baseline_len.to_string().cyan());
    println!("Generated: {} bytes", generated_len.to_string().cyan());

    if baseline_len != generated_len {
        println!(
            "{}",
            format!(
                "⚠ Length mismatch: baseline={baseline_len}, generated={generated_len} (diff={})",
                (baseline_len as isize - generated_len as isize).abs()
            )
            .yellow()
        );
    }

    println!();

    if diffs.is_empty() {
        println!(
            "{}",
            "✓ No differences found — ClientHello matches baseline perfectly!"
                .green()
                .bold()
        );
        return;
    }

    println!(
        "{}",
        format!("✗ Found {} byte difference(s):", diffs.len())
            .red()
            .bold()
    );
    println!();

    // Table header
    println!(
        "  {:<10} {:<12} {:<12} {}",
        "Offset".bold(),
        "Expected".bold(),
        "Actual".bold(),
        "TLS Field".bold()
    );
    println!("  {}", "─".repeat(76));

    for d in diffs {
        let expected_str = match d.expected {
            Some(b) => format!("0x{b:02x}"),
            None => "(eof)".into(),
        };
        let actual_str = match d.actual {
            Some(b) => format!("0x{b:02x}"),
            None => "(eof)".into(),
        };

        println!(
            "  {:<10} {:<12} {:<12} {}",
            format!("0x{:04x}", d.offset).yellow(),
            expected_str.green(),
            actual_str.red(),
            d.field.dimmed()
        );
    }

    println!();

    // Summary: group by field
    let mut field_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for d in diffs {
        // Extract the top-level field name (before " (byte")
        let field_key = d
            .field
            .split(" (byte")
            .next()
            .unwrap_or(&d.field)
            .to_string();
        *field_counts.entry(field_key).or_default() += 1;
    }

    println!("{}", "Summary by field:".bold());
    let mut sorted: Vec<_> = field_counts.into_iter().collect();
    sorted.sort_by_key(|b| std::cmp::Reverse(b.1));
    for (field, count) in &sorted {
        println!("  {count:>4} byte(s) in {field}");
    }
}

fn print_annotations(regions: &[FieldRegion], data: &[u8]) {
    println!("{}", "═══ ClientHello Field Annotations ═══".bold());
    println!();
    println!("Total size: {} bytes", data.len().to_string().cyan());
    println!();

    println!(
        "  {:<10} {:<8} {}    {}",
        "Offset".bold(),
        "Length".bold(),
        "Field".bold(),
        "Hex Preview".bold()
    );
    println!("  {}", "─".repeat(90));

    for region in regions {
        let end = (region.offset + region.length).min(data.len());
        let preview_end = (region.offset + 16).min(end);
        let preview: String = data[region.offset..preview_end]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let ellipsis = if end - region.offset > 16 { " ..." } else { "" };

        println!(
            "  {:<10} {:<8} {}    {}",
            format!("0x{:04x}", region.offset).yellow(),
            region.length,
            region.name,
            format!("{preview}{ellipsis}").dimmed()
        );
    }
}

fn print_info(regions: &[FieldRegion], data: &[u8]) {
    println!("{}", "═══ ClientHello Summary ═══".bold());
    println!();
    println!("Total size: {} bytes", data.len().to_string().cyan());
    println!();

    // Count extensions
    let ext_count = regions
        .iter()
        .filter(|r| r.name.starts_with("  Extension[") && r.name.contains("Type"))
        .count();
    println!("Extensions: {ext_count}");

    // Count cipher suites
    let cs_count = regions
        .iter()
        .filter(|r| r.name.starts_with("  CipherSuite["))
        .count();
    println!("Cipher Suites: {cs_count}");

    // List extensions
    println!();
    println!("{}", "Extensions:".bold());
    for region in regions {
        if region.name.starts_with("  Extension[") && region.name.contains("Type") {
            println!("  {}", region.name);
        }
    }

    // List cipher suites
    println!();
    println!("{}", "Cipher Suites:".bold());
    for region in regions {
        if region.name.starts_with("  CipherSuite[") {
            println!("  {}", region.name);
        }
    }

    // Check for GREASE
    let has_grease = regions.iter().any(|r| r.name.contains("GREASE"));
    println!();
    if has_grease {
        println!("GREASE: {}", "present".green());
    } else {
        println!("GREASE: {}", "absent".yellow());
    }

    // Check for padding
    let has_padding = regions.iter().any(|r| r.name.contains("padding"));
    if has_padding {
        println!("Padding: {}", "present".green());
    } else {
        println!("Padding: {}", "absent".yellow());
    }

    // Check for SNI
    let has_sni = regions.iter().any(|r| r.name.contains("server_name"));
    if has_sni {
        println!("SNI: {}", "present".green());
    } else {
        println!("SNI: {}", "absent".yellow());
    }

    // Ignore random bytes (32 bytes at known offset) for fingerprint
    // The random field and session ID should be excluded from fingerprint comparison
    let random_offset = regions
        .iter()
        .find(|r| r.name.contains("Random"))
        .map(|r| (r.offset, r.length));
    if let Some((off, len)) = random_offset {
        println!();
        println!(
            "{}",
            format!("Note: Random field at offset 0x{off:04x} ({len} bytes) — excluded from fingerprint comparison").dimmed()
        );
    }
}

// =============================================================================
// Main
// =============================================================================

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Diff {
            generated,
            baseline,
            context: _,
        } => {
            let baseline_data = match read_hex(baseline.to_str().unwrap_or("")) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("{}: {e}", "Error reading baseline".red());
                    std::process::exit(1);
                }
            };
            let generated_data = match read_hex(&generated) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("{}: {e}", "Error reading generated".red());
                    std::process::exit(1);
                }
            };

            let regions = annotate_client_hello(&baseline_data);
            let diffs = compute_diff(&baseline_data, &generated_data, &regions);

            print_diff_report(&diffs, baseline_data.len(), generated_data.len());

            if !diffs.is_empty() {
                std::process::exit(1);
            }
        }

        Commands::Annotate { input } => {
            let data = match read_hex(&input) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("{}: {e}", "Error reading input".red());
                    std::process::exit(1);
                }
            };
            let regions = annotate_client_hello(&data);
            print_annotations(&regions, &data);
        }

        Commands::Info { input } => {
            let data = match read_hex(&input) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("{}: {e}", "Error reading input".red());
                    std::process::exit(1);
                }
            };
            let regions = annotate_client_hello(&data);
            print_info(&regions, &data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal ClientHello for testing the parser.
    /// Record: 16 03 01 00 XX
    /// Handshake: 01 00 00 XX
    /// Version: 03 03
    /// Random: 32 bytes of 0x00
    /// SessionID length: 0x00
    /// CipherSuites length: 0x00 0x02, suite: 13 01
    /// Compression: 0x01, 0x00
    /// Extensions length: 0x00 0x00
    fn minimal_client_hello() -> Vec<u8> {
        let mut ch = Vec::new();

        // TLS Record Header
        ch.push(0x16); // ContentType: Handshake
        ch.push(0x03);
        ch.push(0x01); // TLS 1.0 record version
                       // Record length placeholder (will fill later)
        let record_len_pos = ch.len();
        ch.push(0x00);
        ch.push(0x00);

        // Handshake header
        let hs_start = ch.len();
        ch.push(0x01); // ClientHello
                       // Handshake length placeholder
        let hs_len_pos = ch.len();
        ch.push(0x00);
        ch.push(0x00);
        ch.push(0x00);

        let ch_start = ch.len();

        // ClientHello version
        ch.push(0x03);
        ch.push(0x03); // TLS 1.2

        // Random (32 bytes)
        ch.extend_from_slice(&[0xaa; 32]);

        // Session ID length = 0
        ch.push(0x00);

        // Cipher Suites: 2 bytes, 1 suite
        ch.push(0x00);
        ch.push(0x02);
        ch.push(0x13);
        ch.push(0x01); // TLS_AES_128_GCM_SHA256

        // Compression methods: length=1, null
        ch.push(0x01);
        ch.push(0x00);

        // Extensions length = 0
        ch.push(0x00);
        ch.push(0x00);

        // Fill in lengths
        let hs_len = ch.len() - ch_start;
        ch[hs_len_pos] = 0;
        ch[hs_len_pos + 1] = ((hs_len >> 8) & 0xff) as u8;
        ch[hs_len_pos + 2] = (hs_len & 0xff) as u8;

        let record_len = ch.len() - hs_start;
        ch[record_len_pos] = ((record_len >> 8) & 0xff) as u8;
        ch[record_len_pos + 1] = (record_len & 0xff) as u8;

        ch
    }

    #[test]
    fn test_annotate_minimal_client_hello() {
        let data = minimal_client_hello();
        let regions = annotate_client_hello(&data);

        // Should have parsed successfully
        assert!(!regions.is_empty());

        // Check first region is Record ContentType
        assert!(regions[0].name.contains("ContentType"));

        // Check we found the cipher suite
        let has_cipher = regions
            .iter()
            .any(|r| r.name.contains("TLS_AES_128_GCM_SHA256"));
        assert!(
            has_cipher,
            "Should find TLS_AES_128_GCM_SHA256 cipher suite"
        );
    }

    #[test]
    fn test_diff_identical() {
        let data = minimal_client_hello();
        let regions = annotate_client_hello(&data);
        let diffs = compute_diff(&data, &data, &regions);
        assert!(diffs.is_empty(), "Identical data should have no diffs");
    }

    #[test]
    fn test_diff_different() {
        let data = minimal_client_hello();
        let mut modified = data.clone();
        // Offset 11 = first byte of Random field
        // (5 record header + 4 handshake header + 2 version = 11)
        modified[11] = 0xff;

        let regions = annotate_client_hello(&data);
        let diffs = compute_diff(&data, &modified, &regions);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].offset, 11);
        assert!(
            diffs[0].field.contains("Random"),
            "Expected Random field, got: {}",
            diffs[0].field
        );
    }

    #[test]
    fn test_extension_name_known() {
        assert_eq!(extension_name(0x0000), "server_name (SNI)");
        assert_eq!(extension_name(0x0033), "key_share");
        assert_eq!(extension_name(0x002b), "supported_versions");
    }

    #[test]
    fn test_extension_name_grease() {
        assert_eq!(extension_name(0x0a0a), "GREASE");
        assert_eq!(extension_name(0x1a1a), "GREASE");
        assert_eq!(extension_name(0xfafa), "GREASE");
    }
}
