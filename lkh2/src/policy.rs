//! Customisation traits for the h2-native engine.
//!
//! Three layers of control over HTTP/2 wire behaviour that affect
//! deep-inspection fingerprinting beyond the Akamai H2 hash:
//!
//! - [`FrameWritePolicy`] — controls how outbound frames are grouped
//!   into TLS records / TCP segments.
//! - [`FlowControlPolicy`] — controls when and how WINDOW_UPDATE
//!   frames are emitted in response to received DATA.
//! - [`HpackEncodePolicy`] — controls HPACK encoding choices
//!   (indexed vs literal, Huffman on/off) per header.

use crate::frame::H2Frame;

// ─── Frame Write Policy ──────────────────────────────────────────────────────

/// A *group* of frames that should be written in a single TLS record /
/// `write_all` call.
pub type FrameGroup = Vec<H2Frame>;

/// Controls how outbound frames are split across TLS writes.
///
/// Real browsers produce characteristic TCP segmentation patterns.
/// For example, Chrome sends:
///
/// - **Write 1**: `[Magic + SETTINGS + WINDOW_UPDATE]`
/// - **Write 2**: `[PRIORITY frames]` (if any)
/// - **Write 3**: `[HEADERS]`
/// - **Write 4**: `[DATA]` (if any, separate write)
///
/// The default implementation (`DefaultWritePolicy`) merges all frames
/// into a single write, which is functionally correct but produces a
/// single large TLS record that doesn't match browser behaviour.
pub trait FrameWritePolicy: Send + Sync + std::fmt::Debug {
    /// Split a sequence of outbound frames into groups.
    ///
    /// Each group will be encoded and flushed as a single `write_all`
    /// call, producing one TLS record.
    fn group_frames(&self, frames: Vec<H2Frame>) -> Vec<FrameGroup>;

    /// Clone into a boxed trait object.
    fn box_clone(&self) -> Box<dyn FrameWritePolicy>;
}

/// Data-driven write policy that replaces per-browser structs.
///
/// Two boolean knobs control which frame types get their own TLS record:
///
/// | Browser | `split_headers` | `split_data` |
/// |---------|-----------------|--------------|
/// | Default | false           | false        |
/// | Chrome  | true            | true         |
/// | Firefox | true            | true         |
/// | Safari  | false           | true         |
#[derive(Debug, Clone)]
pub struct ConfigurableWritePolicy {
    split_headers: bool,
    split_data: bool,
}

impl ConfigurableWritePolicy {
    pub fn new(split_headers: bool, split_data: bool) -> Self {
        Self {
            split_headers,
            split_data,
        }
    }

    /// Default: all frames in a single write.
    pub fn default_policy() -> Self {
        Self::new(false, false)
    }

    /// Chrome/Firefox: HEADERS and DATA each isolated.
    pub fn chrome() -> Self {
        Self::new(true, true)
    }

    /// Safari: only DATA isolated, HEADERS batched with control frames.
    pub fn safari() -> Self {
        Self::new(false, true)
    }
}

impl FrameWritePolicy for ConfigurableWritePolicy {
    fn group_frames(&self, frames: Vec<H2Frame>) -> Vec<FrameGroup> {
        if frames.is_empty() {
            return vec![];
        }
        if !self.split_headers && !self.split_data {
            return vec![frames];
        }

        let mut groups: Vec<FrameGroup> = Vec::new();
        let mut current: FrameGroup = Vec::new();

        for frame in frames {
            let isolate = match &frame {
                H2Frame::Headers(_) => self.split_headers,
                H2Frame::Data(_) => self.split_data,
                _ => false,
            };
            if isolate {
                if !current.is_empty() {
                    groups.push(std::mem::take(&mut current));
                }
                groups.push(vec![frame]);
            } else {
                current.push(frame);
            }
        }

        if !current.is_empty() {
            groups.push(current);
        }

        groups
    }

    fn box_clone(&self) -> Box<dyn FrameWritePolicy> {
        Box::new(self.clone())
    }
}

/// Sends all frames in a single write (backward-compatible default).
pub type DefaultWritePolicy = ConfigurableWritePolicy;
/// Chrome-like: HEADERS and DATA each isolated.
pub type ChromeWritePolicy = ConfigurableWritePolicy;
/// Firefox-like: HEADERS and DATA each isolated.
pub type FirefoxWritePolicy = ConfigurableWritePolicy;
/// Safari-like: only DATA isolated.
pub type SafariWritePolicy = ConfigurableWritePolicy;

// ─── Flow Control Policy ─────────────────────────────────────────────────────

/// Controls WINDOW_UPDATE emission strategy.
///
/// Real browsers don't send WINDOW_UPDATE for every DATA frame.
/// Instead they accumulate consumed bytes and send an update when
/// the consumed amount exceeds a threshold (typically half the initial
/// window size).
pub trait FlowControlPolicy: Send + Sync + std::fmt::Debug {
    /// Called when `data_len` bytes of DATA have been received on the
    /// connection (stream_id=0) or a specific stream.
    ///
    /// Returns `Some(increment)` if a WINDOW_UPDATE should be sent now,
    /// or `None` to defer.
    fn on_data_received(
        &mut self,
        stream_id: u32,
        data_len: u32,
        current_window: i32,
        initial_window: u32,
    ) -> Option<u32>;

    /// Called when a stream is closed — allows cleanup of per-stream state.
    fn on_stream_closed(&mut self, stream_id: u32);

    /// Clone into a boxed trait object.
    fn box_clone(&self) -> Box<dyn FlowControlPolicy>;
}

/// Immediate 1:1 WINDOW_UPDATE (current default behaviour).
///
/// Sends a WINDOW_UPDATE for every DATA frame received, returning
/// exactly the number of bytes consumed. Simple but creates a
/// distinctive wire pattern.
#[derive(Debug, Clone)]
pub struct ImmediateFlowControl;

impl FlowControlPolicy for ImmediateFlowControl {
    fn on_data_received(
        &mut self,
        _stream_id: u32,
        data_len: u32,
        _current_window: i32,
        _initial_window: u32,
    ) -> Option<u32> {
        if data_len > 0 {
            Some(data_len)
        } else {
            None
        }
    }

    fn on_stream_closed(&mut self, _stream_id: u32) {}

    fn box_clone(&self) -> Box<dyn FlowControlPolicy> {
        Box::new(self.clone())
    }
}

/// Threshold-based flow control, similar to Chrome/Firefox.
///
/// Accumulates consumed bytes per stream (and for connection level
/// using stream_id=0). A WINDOW_UPDATE is sent only when the
/// accumulated amount reaches `threshold_ratio` of the initial window size.
#[derive(Debug, Clone)]
pub struct ThresholdFlowControl {
    threshold_ratio: f32,
    accumulated: std::collections::HashMap<u32, u32>,
}

impl ThresholdFlowControl {
    pub fn new(threshold_ratio: f32) -> Self {
        Self {
            threshold_ratio: threshold_ratio.clamp(0.1, 1.0),
            accumulated: std::collections::HashMap::new(),
        }
    }

    /// Chrome-like threshold at 1/2 of initial window.
    pub fn chrome() -> Self {
        Self::new(0.5)
    }

    /// Firefox-like threshold at 1/2 of initial window.
    pub fn firefox() -> Self {
        Self::new(0.5)
    }
}

impl FlowControlPolicy for ThresholdFlowControl {
    fn on_data_received(
        &mut self,
        stream_id: u32,
        data_len: u32,
        _current_window: i32,
        initial_window: u32,
    ) -> Option<u32> {
        if data_len == 0 {
            return None;
        }

        let acc = self.accumulated.entry(stream_id).or_insert(0);
        *acc += data_len;

        let threshold = (initial_window as f32 * self.threshold_ratio) as u32;
        if *acc >= threshold {
            let increment = *acc;
            *acc = 0;
            Some(increment)
        } else {
            None
        }
    }

    fn on_stream_closed(&mut self, stream_id: u32) {
        self.accumulated.remove(&stream_id);
    }

    fn box_clone(&self) -> Box<dyn FlowControlPolicy> {
        Box::new(self.clone())
    }
}

// ─── HPACK Encode Policy ─────────────────────────────────────────────────────

/// Instruction for how a single header should be HPACK-encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpackFieldEncoding {
    /// Use indexed representation if the header is in the static/dynamic table.
    /// Falls back to `IncrementalIndexing` if not found.
    Indexed,

    /// Literal Header Field with Incremental Indexing (adds to dynamic table).
    IncrementalIndexing {
        /// Whether to Huffman-encode the value.
        huffman_value: bool,
    },

    /// Literal Header Field without Indexing (does NOT add to dynamic table).
    WithoutIndexing { huffman_value: bool },

    /// Literal Header Field Never Indexed (sensitive, must not be indexed).
    NeverIndexed { huffman_value: bool },
}

/// Controls HPACK encoding decisions per header.
///
/// The `hpack` crate uses a fixed strategy (always incremental indexing
/// with Huffman). Real browsers have subtly different patterns:
///
/// - Chrome: uses static-table indices for well-known pseudo-headers,
///   incremental + Huffman for everything else.
/// - Firefox: similar to Chrome but with slight table management differences.
/// - Safari: slightly different Huffman usage on certain headers.
///
/// By implementing this trait you can control exactly which encoding
/// is used for each header field.
pub trait HpackEncodePolicy: Send + Sync + std::fmt::Debug {
    /// Decide how a header field should be encoded.
    ///
    /// `name` is the lowercase header name (e.g. `:method`, `user-agent`).
    /// `value` is the header value.
    ///
    /// This is called for each header in order. The return value controls
    /// the HPACK encoding used for that specific field.
    fn encoding_for(&self, name: &str, value: &str) -> HpackFieldEncoding;

    /// Clone into a boxed trait object.
    fn box_clone(&self) -> Box<dyn HpackEncodePolicy>;
}

/// Default HPACK policy: always try indexed, fall back to
/// incremental indexing with Huffman.
#[derive(Debug, Clone)]
pub struct DefaultHpackPolicy;

impl HpackEncodePolicy for DefaultHpackPolicy {
    fn encoding_for(&self, _name: &str, _value: &str) -> HpackFieldEncoding {
        HpackFieldEncoding::Indexed
    }

    fn box_clone(&self) -> Box<dyn HpackEncodePolicy> {
        Box::new(self.clone())
    }
}

/// Chrome-like HPACK policy.
///
/// Pseudo-headers use indexed representation when available.
/// Regular headers use incremental indexing with Huffman encoding.
/// `cookie` headers use incremental indexing with Huffman.
#[derive(Debug, Clone)]
pub struct ChromeHpackPolicy;

impl HpackEncodePolicy for ChromeHpackPolicy {
    fn encoding_for(&self, name: &str, _value: &str) -> HpackFieldEncoding {
        if name.starts_with(':') {
            HpackFieldEncoding::Indexed
        } else {
            HpackFieldEncoding::IncrementalIndexing {
                huffman_value: true,
            }
        }
    }

    fn box_clone(&self) -> Box<dyn HpackEncodePolicy> {
        Box::new(self.clone())
    }
}

/// Firefox-like HPACK policy.
///
/// Similar to Chrome's policy. Firefox also tries indexed first
/// for pseudo-headers and uses incremental indexing with Huffman
/// for regular headers.
#[derive(Debug, Clone)]
pub struct FirefoxHpackPolicy;

impl HpackEncodePolicy for FirefoxHpackPolicy {
    fn encoding_for(&self, name: &str, _value: &str) -> HpackFieldEncoding {
        if name.starts_with(':') {
            HpackFieldEncoding::Indexed
        } else {
            HpackFieldEncoding::IncrementalIndexing {
                huffman_value: true,
            }
        }
    }

    fn box_clone(&self) -> Box<dyn HpackEncodePolicy> {
        Box::new(self.clone())
    }
}

/// Safari-like HPACK policy.
///
/// Safari generally uses indexed for pseudo-headers and
/// incremental indexing with Huffman for regular headers,
/// but does NOT Huffman-encode some short values.
#[derive(Debug, Clone)]
pub struct SafariHpackPolicy;

impl HpackEncodePolicy for SafariHpackPolicy {
    fn encoding_for(&self, name: &str, value: &str) -> HpackFieldEncoding {
        if name.starts_with(':') {
            HpackFieldEncoding::Indexed
        } else if value.len() <= 3 {
            HpackFieldEncoding::IncrementalIndexing {
                huffman_value: false,
            }
        } else {
            HpackFieldEncoding::IncrementalIndexing {
                huffman_value: true,
            }
        }
    }

    fn box_clone(&self) -> Box<dyn HpackEncodePolicy> {
        Box::new(self.clone())
    }
}

// ─── Composite Behavior ──────────────────────────────────────────────────────

/// Bundled behaviour strategies for the h2-native engine.
///
/// `H2Profile` describes *what* to send (SETTINGS values, pseudo-header order,
/// WINDOW_UPDATE size — the "Akamai fingerprint dimensions").
///
/// `H2Behavior` describes *how* to send it (frame grouping across TLS records,
/// WINDOW_UPDATE timing, HPACK encoding choices — deeper behavioural traits
/// that only the h2-native engine can control).
///
/// Together they form the full browser impersonation:
/// - `H2Profile`  = **identity** (declarative, serialisable)
/// - `H2Behavior` = **mannerisms** (runtime strategies)
#[derive(Debug)]
pub struct H2Behavior {
    pub write_policy: Box<dyn FrameWritePolicy>,
    pub flow_control: Box<dyn FlowControlPolicy>,
    pub hpack_policy: Box<dyn HpackEncodePolicy>,
}

impl H2Behavior {
    /// Baseline behaviour (backward-compatible: single write, immediate
    /// flow control, default HPACK).
    pub fn default_behavior() -> Self {
        Self {
            write_policy: Box::new(ConfigurableWritePolicy::new(false, false)),
            flow_control: Box::new(ImmediateFlowControl),
            hpack_policy: Box::new(DefaultHpackPolicy),
        }
    }

    /// Chrome-like behaviour.
    pub fn chrome() -> Self {
        Self {
            write_policy: Box::new(ConfigurableWritePolicy::new(true, true)),
            flow_control: Box::new(ThresholdFlowControl::chrome()),
            hpack_policy: Box::new(ChromeHpackPolicy),
        }
    }

    /// Firefox-like behaviour.
    pub fn firefox() -> Self {
        Self {
            write_policy: Box::new(ConfigurableWritePolicy::new(true, true)),
            flow_control: Box::new(ThresholdFlowControl::firefox()),
            hpack_policy: Box::new(FirefoxHpackPolicy),
        }
    }

    /// Safari-like behaviour.
    pub fn safari() -> Self {
        Self {
            write_policy: Box::new(ConfigurableWritePolicy::new(false, true)),
            flow_control: Box::new(ThresholdFlowControl::new(0.5)),
            hpack_policy: Box::new(SafariHpackPolicy),
        }
    }
}

impl Clone for H2Behavior {
    fn clone(&self) -> Self {
        Self {
            write_policy: self.write_policy.box_clone(),
            flow_control: self.flow_control.box_clone(),
            hpack_policy: self.hpack_policy.box_clone(),
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_settings() -> H2Frame {
        H2Frame::Settings(crate::frame::SettingsFrame {
            ack: false,
            settings: vec![],
        })
    }

    fn make_window_update() -> H2Frame {
        H2Frame::WindowUpdate(crate::frame::WindowUpdateFrame {
            stream_id: 0,
            increment: 100,
        })
    }

    fn make_headers(stream_id: u32) -> H2Frame {
        H2Frame::Headers(crate::frame::HeadersFrame {
            stream_id,
            header_block: bytes::Bytes::new(),
            end_stream: true,
            end_headers: true,
            priority: None,
            padding: None,
        })
    }

    fn make_data(stream_id: u32) -> H2Frame {
        H2Frame::Data(crate::frame::DataFrame {
            stream_id,
            data: bytes::Bytes::from_static(b"hello"),
            end_stream: true,
            padding: None,
        })
    }

    #[test]
    fn test_default_write_policy_merges_all() {
        let policy = ConfigurableWritePolicy::new(false, false);
        let frames = vec![make_settings(), make_window_update(), make_headers(1)];
        let groups = policy.group_frames(frames);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 3);
    }

    #[test]
    fn test_chrome_write_policy_separates_headers_and_data() {
        let policy = ConfigurableWritePolicy::new(true, true);
        let frames = vec![
            make_settings(),
            make_window_update(),
            make_headers(1),
            make_data(1),
        ];
        let groups = policy.group_frames(frames);
        // [SETTINGS + WU], [HEADERS], [DATA]
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].len(), 2); // SETTINGS + WU
        assert_eq!(groups[1].len(), 1); // HEADERS
        assert_eq!(groups[2].len(), 1); // DATA
    }

    #[test]
    fn test_safari_write_policy_only_splits_data() {
        let policy = ConfigurableWritePolicy::new(false, true);
        let frames = vec![
            make_settings(),
            make_window_update(),
            make_headers(1),
            make_data(1),
        ];
        let groups = policy.group_frames(frames);
        // [SETTINGS + WU + HEADERS], [DATA]
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].len(), 3);
        assert_eq!(groups[1].len(), 1);
    }

    #[test]
    fn test_immediate_flow_control() {
        let mut fc = ImmediateFlowControl;
        assert_eq!(fc.on_data_received(1, 1000, 60000, 65535), Some(1000));
        assert_eq!(fc.on_data_received(1, 0, 60000, 65535), None);
    }

    #[test]
    fn test_threshold_flow_control_accumulates() {
        let mut fc = ThresholdFlowControl::new(0.5);
        let initial_window = 65535;

        // First DATA: 10000 bytes — below threshold (~32767)
        assert_eq!(fc.on_data_received(1, 10000, 55535, initial_window), None);

        // Second DATA: 15000 bytes — still below (25000 < 32767)
        assert_eq!(fc.on_data_received(1, 15000, 40535, initial_window), None);

        // Third DATA: 10000 bytes — crosses threshold (35000 >= 32767)
        let result = fc.on_data_received(1, 10000, 30535, initial_window);
        assert_eq!(result, Some(35000));
    }

    #[test]
    fn test_threshold_flow_control_connection_level() {
        let mut fc = ThresholdFlowControl::chrome();
        let initial_window = 65535;

        // Connection level (stream_id=0)
        assert_eq!(
            fc.on_data_received(0, 40000, 25535, initial_window),
            Some(40000)
        );
    }

    #[test]
    fn test_threshold_flow_control_cleanup() {
        let mut fc = ThresholdFlowControl::new(0.5);
        fc.on_data_received(1, 100, 65435, 65535);
        fc.on_stream_closed(1);
        // After cleanup, accumulator should be reset
        assert_eq!(fc.on_data_received(1, 100, 65435, 65535), None);
    }

    #[test]
    fn test_chrome_hpack_policy() {
        let policy = ChromeHpackPolicy;
        assert_eq!(
            policy.encoding_for(":method", "GET"),
            HpackFieldEncoding::Indexed
        );
        assert_eq!(
            policy.encoding_for("user-agent", "Chrome/144"),
            HpackFieldEncoding::IncrementalIndexing {
                huffman_value: true
            }
        );
    }

    #[test]
    fn test_safari_hpack_policy_short_values() {
        let policy = SafariHpackPolicy;
        assert_eq!(
            policy.encoding_for("sec-fetch-mode", "no-cors"),
            HpackFieldEncoding::IncrementalIndexing {
                huffman_value: true
            }
        );
        // Short value (<=3 chars): no Huffman
        assert_eq!(
            policy.encoding_for("te", "gzip"),
            HpackFieldEncoding::IncrementalIndexing {
                huffman_value: true
            }
        );
        assert_eq!(
            policy.encoding_for("te", "gz"),
            HpackFieldEncoding::IncrementalIndexing {
                huffman_value: false
            }
        );
    }

    #[test]
    fn test_h2_behavior_presets() {
        let chrome = H2Behavior::chrome();
        let wp = format!("{:?}", chrome.write_policy);
        assert!(wp.contains("split_headers: true") && wp.contains("split_data: true"));
        assert!(format!("{:?}", chrome.flow_control).contains("Threshold"));
        assert!(format!("{:?}", chrome.hpack_policy).contains("Chrome"));

        let ff = H2Behavior::firefox();
        let wp = format!("{:?}", ff.write_policy);
        assert!(wp.contains("split_headers: true") && wp.contains("split_data: true"));

        let safari = H2Behavior::safari();
        let wp = format!("{:?}", safari.write_policy);
        assert!(wp.contains("split_headers: false") && wp.contains("split_data: true"));
    }

    #[test]
    fn test_h2_behavior_clone() {
        let chrome = H2Behavior::chrome();
        let cloned = chrome.clone();
        let wp = format!("{:?}", cloned.write_policy);
        assert!(wp.contains("split_headers: true"));
    }
}
