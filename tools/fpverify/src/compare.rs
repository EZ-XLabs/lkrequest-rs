//! Shape-aware comparison of canonical TLS fingerprints.
//!
//! Comparison is **exact equality after shape canonicalization**: GREASE is
//! already tokenized in [`crate::canonical`]; here we additionally fold away the
//! one remaining legitimate per-connection variation — **extension order** —
//! for profiles that shuffle (see [`TlsShapeSpec`]). Everything else (cipher
//! order, group/sigalg order, values) is compared exactly.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::Value;

use crate::canonical::{CanonicalExtSource, CanonicalExtension, CanonicalTlsFingerprint};
use crate::shape::TlsShapeSpec;

/// Return a copy of `fp` with extension order canonicalized per `shape`.
///
/// When the profile shuffles extensions, the shuffleable extensions are sorted
/// into a stable order and the `pinned_last` extensions are appended (also in a
/// stable order), so two shuffled instances of the *same* ClientHello
/// canonicalize identically. When it does not shuffle, order is left as-is.
pub fn canonicalize_tls(
    fp: &CanonicalTlsFingerprint,
    shape: &TlsShapeSpec,
) -> CanonicalTlsFingerprint {
    let mut out = fp.clone();
    if shape.extensions_shuffled {
        let (mut pinned, mut shuffleable): (Vec<CanonicalExtension>, Vec<CanonicalExtension>) = fp
            .extensions
            .iter()
            .cloned()
            .partition(|e| shape.pinned_last.contains(&e.extension_type));
        shuffleable.sort_by(ext_order);
        pinned.sort_by(ext_order);
        shuffleable.extend(pinned);
        out.extensions = shuffleable;
    }
    out
}

fn ext_order(a: &CanonicalExtension, b: &CanonicalExtension) -> Ordering {
    a.extension_type
        .cmp(&b.extension_type)
        .then_with(|| source_rank(&a.source).cmp(&source_rank(&b.source)))
}

fn source_rank(source: &CanonicalExtSource) -> u8 {
    match source {
        CanonicalExtSource::Auto => 0,
        CanonicalExtSource::Grease => 1,
        CanonicalExtSource::Raw { .. } => 2,
    }
}

/// A single field-level difference between two fingerprints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDiff {
    /// Dotted/indexed path, e.g. `cipher_suites[1]` or `extensions[3].source`.
    pub path: String,
    /// Value on the golden side (`None` = field absent there).
    pub golden: Option<Value>,
    /// Value on the current side (`None` = field absent there).
    pub current: Option<Value>,
}

impl std::fmt::Display for FieldDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let fmt_opt = |v: &Option<Value>| match v {
            Some(v) => v.to_string(),
            None => "<absent>".to_string(),
        };
        write!(
            f,
            "{}: golden={} current={}",
            self.path,
            fmt_opt(&self.golden),
            fmt_opt(&self.current)
        )
    }
}

/// Field-level diff of two arbitrary JSON values. Empty result = equal.
///
/// The generic comparison primitive: paths are dotted/indexed
/// (`a.b[2].c`), and a leaf mismatch / missing key / missing array element
/// each produces one [`FieldDiff`]. Useful for any serializable fingerprint
/// (TLS, H2, QUIC/H3) — the dimensions without per-connection randomness (H2
/// SETTINGS, QUIC transport params, …) compare directly with no shape step.
pub fn diff_values(golden: &Value, current: &Value) -> Vec<FieldDiff> {
    let mut out = Vec::new();
    diff_value("", golden, current, &mut out);
    out
}

/// Field-level diff of two serializable values (serializes both, then
/// [`diff_values`]).
pub fn diff_json<T: Serialize>(golden: &T, current: &T) -> Vec<FieldDiff> {
    let g = serde_json::to_value(golden).expect("golden serializes");
    let c = serde_json::to_value(current).expect("current serializes");
    diff_values(&g, &c)
}

/// Compare two canonical TLS fingerprints under `shape` (folds away shuffled
/// extension order), returning field-level mismatches. Empty result = match.
pub fn diff_tls(
    golden: &CanonicalTlsFingerprint,
    current: &CanonicalTlsFingerprint,
    shape: &TlsShapeSpec,
) -> Vec<FieldDiff> {
    diff_json(
        &canonicalize_tls(golden, shape),
        &canonicalize_tls(current, shape),
    )
}

fn diff_value(path: &str, a: &Value, b: &Value, out: &mut Vec<FieldDiff>) {
    match (a, b) {
        (Value::Object(ma), Value::Object(mb)) => {
            let keys: BTreeSet<&String> = ma.keys().chain(mb.keys()).collect();
            for k in keys {
                let p = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                match (ma.get(k), mb.get(k)) {
                    (Some(va), Some(vb)) => diff_value(&p, va, vb, out),
                    (ga, gb) => out.push(FieldDiff {
                        path: p,
                        golden: ga.cloned(),
                        current: gb.cloned(),
                    }),
                }
            }
        }
        (Value::Array(aa), Value::Array(ab)) => {
            let n = aa.len().max(ab.len());
            for i in 0..n {
                let p = format!("{path}[{i}]");
                match (aa.get(i), ab.get(i)) {
                    (Some(va), Some(vb)) => diff_value(&p, va, vb, out),
                    (ga, gb) => out.push(FieldDiff {
                        path: p,
                        golden: ga.cloned(),
                        current: gb.cloned(),
                    }),
                }
            }
        }
        _ => {
            if a != b {
                out.push(FieldDiff {
                    path: path.to_string(),
                    golden: Some(a.clone()),
                    current: Some(b.clone()),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::GREASE_TOKEN;

    fn auto(t: u16) -> CanonicalExtension {
        CanonicalExtension {
            extension_type: t,
            source: CanonicalExtSource::Auto,
        }
    }
    fn grease() -> CanonicalExtension {
        CanonicalExtension {
            extension_type: GREASE_TOKEN,
            source: CanonicalExtSource::Grease,
        }
    }

    fn fp_with_extensions(exts: Vec<CanonicalExtension>) -> CanonicalTlsFingerprint {
        CanonicalTlsFingerprint {
            legacy_version: 0x0303,
            cipher_suites: vec![GREASE_TOKEN, 0x1301, 0x1302],
            extensions: exts,
            supported_groups: vec![0x001d, 0x0017],
            signature_algorithms: vec![0x0403],
            ec_point_formats: vec![0x00],
            compression_methods: vec![0x00],
            supported_versions: vec![GREASE_TOKEN, 0x0304, 0x0303],
            key_share_curves: vec![0x001d],
            alpn_protocols: vec!["h2".into()],
            alps_protocols: None,
            compress_cert_algorithms: None,
            record_size_limit: None,
            session_id_length: 32,
            has_padding: false,
            has_ech: false,
        }
    }

    #[test]
    fn shuffled_order_difference_is_not_a_mismatch() {
        let a = fp_with_extensions(vec![grease(), auto(0x0000), auto(0x002b), auto(0x0033)]);
        // Same SET, different order (shuffle).
        let b = fp_with_extensions(vec![auto(0x0033), auto(0x0000), grease(), auto(0x002b)]);
        let shape = TlsShapeSpec::shuffled(vec![0x0029]);
        assert!(
            diff_tls(&a, &b, &shape).is_empty(),
            "shuffled extension order must not be a mismatch"
        );
    }

    #[test]
    fn fixed_order_difference_is_a_mismatch() {
        let a = fp_with_extensions(vec![auto(0x0000), auto(0x002b)]);
        let b = fp_with_extensions(vec![auto(0x002b), auto(0x0000)]);
        let shape = TlsShapeSpec::fixed_order();
        let diffs = diff_tls(&a, &b, &shape);
        assert!(
            !diffs.is_empty(),
            "fixed-order profiles must gate exact extension order"
        );
    }

    #[test]
    fn missing_extension_is_a_mismatch_even_when_shuffled() {
        let a = fp_with_extensions(vec![grease(), auto(0x0000), auto(0x002b), auto(0x0033)]);
        // b dropped 0x0033 — a real regression, must be caught despite shuffle.
        let b = fp_with_extensions(vec![grease(), auto(0x0000), auto(0x002b)]);
        let shape = TlsShapeSpec::shuffled(vec![0x0029]);
        assert!(!diff_tls(&a, &b, &shape).is_empty());
    }

    #[test]
    fn pinned_last_extension_is_appended_after_shuffleable() {
        let psk = auto(0x0029);
        let fp = fp_with_extensions(vec![psk.clone(), auto(0x0033), grease(), auto(0x0000)]);
        let shape = TlsShapeSpec::shuffled(vec![0x0029]);
        let c = canonicalize_tls(&fp, &shape);
        assert_eq!(
            c.extensions.last().unwrap().extension_type,
            0x0029,
            "pinned_last must end up last after canonicalization"
        );
    }

    #[test]
    fn cipher_change_is_reported_with_path() {
        let a = fp_with_extensions(vec![auto(0x0000)]);
        let mut b = fp_with_extensions(vec![auto(0x0000)]);
        b.cipher_suites[1] = 0x9999;
        let diffs = diff_tls(&a, &b, &TlsShapeSpec::fixed_order());
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "cipher_suites[1]");
    }
}
