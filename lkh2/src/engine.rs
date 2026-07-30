//! Sans-I/O HTTP/2 protocol engine.
//!
//! `H2Engine` processes inbound bytes and emits outbound bytes + events,
//! with no I/O, no async, no threads.  An external async driver feeds it
//! data from the network and drains frames to be written.
//!
//! ## Lifecycle
//!
//! 1. `H2Engine::client(profile)` — build engine, populate `output_buf`
//!    with the connection preface (magic + SETTINGS + WINDOW_UPDATE + PRIORITYs).
//! 2. Driver writes `output_buf` to the wire.
//! 3. Driver reads bytes from the wire into `input_buf`.
//! 4. `engine.process()` — decode frames, update state, produce events,
//!    and potentially append new frames to `output_buf`.
//! 5. Repeat 2–4.

use crate::codec::{DecodeResult, H2Codec};
use crate::conn_state::{ConnState, H2ErrorCode};
use crate::frame::*;
use crate::policy::{FlowControlPolicy, HpackEncodePolicy, ImmediateFlowControl};
use crate::profile::H2Profile;
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use tracing::debug;

// ─── CONTINUATION assembler ──────────────────────────────────────────────────

/// Reassembles HEADERS + CONTINUATION sequences into complete header blocks.
///
/// Per RFC 7540 §6.10, CONTINUATION frames must arrive on the same stream
/// immediately following the HEADERS frame with `END_HEADERS=false`.
/// This struct tracks that state and buffers the partial header block.
// Default maximum accumulated header block size (256 KB).
const DEFAULT_MAX_HEADER_BLOCK_SIZE: usize = 256 * 1024;
/// Maximum number of CONTINUATION frames per stream.
const MAX_CONTINUATION_FRAMES: usize = 64;

#[derive(Debug)]
pub struct ContinuationAssembler {
    bufs: HashMap<u32, (Vec<u8>, bool, usize)>, // (buf, end_stream, continuation_count)
    active_stream: Option<u32>,
    max_header_block_size: usize,
}

/// Result of pushing a HEADERS or CONTINUATION fragment.
#[derive(Debug)]
pub enum AssemblyResult {
    /// Header block is not yet complete; more CONTINUATION frames expected.
    Incomplete,
    /// Header block is complete.
    Complete {
        stream_id: u32,
        header_block: Bytes,
        end_stream: bool,
    },
    /// Protocol violation detected.
    Error(String),
}

impl Default for ContinuationAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl ContinuationAssembler {
    pub fn new() -> Self {
        Self {
            bufs: HashMap::new(),
            active_stream: None,
            max_header_block_size: DEFAULT_MAX_HEADER_BLOCK_SIZE,
        }
    }

    pub fn set_max_header_block_size(&mut self, size: usize) {
        self.max_header_block_size = size;
    }

    /// Returns `true` when a CONTINUATION sequence is in progress and
    /// the only valid next frame types are CONTINUATION on the same stream.
    pub fn is_active(&self) -> bool {
        self.active_stream.is_some()
    }

    /// Push the header block from a HEADERS frame.
    pub fn push_headers(
        &mut self,
        stream_id: u32,
        header_block: &[u8],
        end_stream: bool,
        end_headers: bool,
    ) -> AssemblyResult {
        if end_headers {
            return AssemblyResult::Complete {
                stream_id,
                header_block: Bytes::copy_from_slice(header_block),
                end_stream,
            };
        }
        if header_block.len() > self.max_header_block_size {
            return AssemblyResult::Error(format!(
                "header block size {} exceeds limit {}",
                header_block.len(),
                self.max_header_block_size,
            ));
        }
        self.bufs
            .insert(stream_id, (header_block.to_vec(), end_stream, 0));
        self.active_stream = Some(stream_id);
        AssemblyResult::Incomplete
    }

    /// Push a CONTINUATION fragment.
    pub fn push_continuation(
        &mut self,
        stream_id: u32,
        header_block: &[u8],
        end_headers: bool,
    ) -> AssemblyResult {
        match self.active_stream {
            None => {
                return AssemblyResult::Error(format!(
                    "CONTINUATION received for stream {stream_id} without preceding HEADERS"
                ));
            }
            Some(expected) if expected != stream_id => {
                return AssemblyResult::Error(format!(
                    "unexpected CONTINUATION for stream {stream_id}, expected {expected}"
                ));
            }
            _ => {}
        }

        // Check limits before extending
        let overflow = if let Some((buf, _, count)) = self.bufs.get(&stream_id) {
            let new_count = count + 1;
            let new_len = buf.len() + header_block.len();
            if new_count > MAX_CONTINUATION_FRAMES {
                Some(format!(
                    "too many CONTINUATION frames ({new_count}) for stream {stream_id}",
                ))
            } else if new_len > self.max_header_block_size {
                Some(format!(
                    "accumulated header block size {new_len} exceeds limit {}",
                    self.max_header_block_size,
                ))
            } else {
                None
            }
        } else {
            None
        };

        if let Some(msg) = overflow {
            self.bufs.remove(&stream_id);
            self.active_stream = None;
            return AssemblyResult::Error(msg);
        }

        if let Some((ref mut buf, _, ref mut count)) = self.bufs.get_mut(&stream_id) {
            *count += 1;
            buf.extend_from_slice(header_block);
        }

        if end_headers {
            if let Some((block, end_stream, _)) = self.bufs.remove(&stream_id) {
                self.active_stream = None;
                return AssemblyResult::Complete {
                    stream_id,
                    header_block: Bytes::from(block),
                    end_stream,
                };
            }
        }

        AssemblyResult::Incomplete
    }
}

// ─── Events ──────────────────────────────────────────────────────────────────

/// Events emitted by the engine for the async driver to act on.
#[derive(Debug)]
pub enum H2Event {
    /// Remote SETTINGS received and ACKed.  
    SettingsAcked,

    /// Our SETTINGS was ACKed by the remote.
    LocalSettingsAcked,

    /// Response headers received for a stream.
    ResponseHeaders {
        stream_id: u32,
        headers: Vec<(String, String)>,
        end_stream: bool,
    },

    /// Response body data received for a stream.
    ResponseData {
        stream_id: u32,
        data: Bytes,
        end_stream: bool,
    },

    /// Stream was reset by the remote.
    StreamReset { stream_id: u32, error_code: u32 },

    /// PING received — engine already queued a PONG in output_buf.
    PingAck,

    /// GOAWAY received — connection is shutting down.
    GoAway {
        last_stream_id: u32,
        error_code: u32,
        debug_data: Bytes,
    },

    /// Connection-level WINDOW_UPDATE received.
    WindowUpdate { stream_id: u32, increment: u32 },

    /// A protocol error occurred — the engine has queued a GOAWAY.
    Error(String),
}

// ─── Engine ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct H2Engine {
    codec: H2Codec,
    state: ConnState,
    /// Pseudo-header ordering extracted from profile (only field needed post-init).
    pseudo_header_order: Vec<crate::profile::PseudoHeaderId>,
    /// Reassembles HEADERS + CONTINUATION sequences.
    continuation: ContinuationAssembler,
    /// Whether we've received the remote SETTINGS.
    remote_settings_received: bool,
    /// Fallback stream-level priority specs from the profile.
    /// Used when `priority_config.urgency_weights` is `None`.
    headers_priority: Option<PrioritySpec>,
    /// Per-browser priority strategy (urgency→weight mapping, stream dep policy).
    priority_config: crate::profile::PriorityConfig,
    /// Last client stream ID we opened, for Chain dependency policy.
    last_client_stream_id: Option<u32>,
    /// Flow control strategy (controls WINDOW_UPDATE emission).
    flow_control: Box<dyn FlowControlPolicy>,
    /// HPACK encoding policy (controls per-header encoding choices).
    hpack_policy: Option<Box<dyn HpackEncodePolicy>>,
    /// Highest peer stream ID we have successfully processed.
    last_peer_stream_id: u32,
    /// Connection-level initial receive window (65535 + window_update from profile).
    conn_initial_recv_window: u32,
    /// Reusable buffer for events (cleared each `process()` call).
    event_buf: Vec<H2Event>,
    /// Reusable buffer for outbound frames (cleared each `process()` call).
    outbound_buf: Vec<H2Frame>,
    /// Body data that couldn't be sent due to flow control window exhaustion.
    /// When WINDOW_UPDATE frames arrive, pending data is drained automatically.
    pending_data: Vec<PendingBodyData>,
}

/// Body data buffered because the flow control window was exhausted.
#[derive(Debug)]
struct PendingBodyData {
    stream_id: u32,
    data: Bytes,
    end_stream: bool,
}

impl H2Engine {
    /// Create a client-side engine from an `H2Profile`.
    ///
    /// Returns `(engine, preface_frames)`. The driver should encode and
    /// write the preface frames (preceded by the connection magic) via
    /// its `FrameWritePolicy`.
    ///
    /// Uses default policies. Use `client_with_policies` to customise.
    pub fn client(profile: &H2Profile) -> (Self, Vec<H2Frame>) {
        Self::client_with_policies(profile, Box::new(ImmediateFlowControl), None)
    }

    /// Create a client-side engine with custom flow-control and HPACK policies.
    ///
    /// Returns `(engine, preface_frames)` where `preface_frames` contains
    /// the SETTINGS, WINDOW_UPDATE, and optional PRIORITY frames that
    /// the driver must send after the connection magic bytes.
    pub fn client_with_policies(
        profile: &H2Profile,
        flow_control: Box<dyn FlowControlPolicy>,
        hpack_policy: Option<Box<dyn HpackEncodePolicy>>,
    ) -> (Self, Vec<H2Frame>) {
        let preface_frames = profile.to_preface_frames();
        let headers_priority = profile.to_headers_priority_spec();

        let mut state = ConnState::client();
        state.apply_profile_settings(&profile.settings);

        if profile.window_update > 0 {
            let _ = state.update_recv_window(profile.window_update);
        }

        // Sync ContinuationAssembler limit with profile's max_header_list_size
        let mut continuation = ContinuationAssembler::new();
        if let Some(mhls) = profile
            .settings
            .iter()
            .find(|s| s.id == crate::profile::H2SettingId::MaxHeaderListSize)
        {
            continuation.set_max_header_block_size(mhls.value as usize);
        }

        // Our receive/decode frame-size cap is whatever we advertise in our
        // own SETTINGS (SETTINGS_MAX_FRAME_SIZE, RFC 7540 §4.2). It is fixed
        // for the connection's lifetime and is NEVER raised by the server's
        // advertised value — that only bounds the size of frames *we emit*
        // (see `build_data`/`build_headers`, which read `remote_settings`).
        let mut codec = H2Codec::new();
        if let Some(mfs) = profile
            .settings
            .iter()
            .find(|s| s.id == crate::profile::H2SettingId::MaxFrameSize)
        {
            codec.set_max_frame_size(mfs.value);
        }

        let engine = Self {
            codec,
            state,
            pseudo_header_order: profile.pseudo_header_order.clone(),
            continuation,
            remote_settings_received: false,
            headers_priority,
            priority_config: profile.priority_config.clone(),
            last_client_stream_id: None,
            flow_control,
            hpack_policy,
            last_peer_stream_id: 0,
            conn_initial_recv_window: 65535u32.saturating_add(profile.window_update),
            event_buf: Vec::new(),
            outbound_buf: Vec::new(),
            pending_data: Vec::new(),
        };

        (engine, preface_frames)
    }

    // ── Public API ───────────────────────────────────────────────────────

    /// Feed inbound bytes and process all complete frames.
    ///
    /// Returns `(events, outbound_frames)`. The driver is responsible for
    /// encoding the outbound frames through its `FrameWritePolicy` before
    /// writing to the wire.
    pub fn process(&mut self, input: &mut BytesMut) -> (Vec<H2Event>, Vec<H2Frame>) {
        let mut events = std::mem::take(&mut self.event_buf);
        let mut outbound = std::mem::take(&mut self.outbound_buf);
        events.clear();
        outbound.clear();

        loop {
            match self.codec.decode(input) {
                DecodeResult::Frame(frame) => {
                    self.handle_frame(frame, &mut events, &mut outbound);
                }
                DecodeResult::NeedMoreData { .. } => break,
                DecodeResult::Error(e) => {
                    let msg = e.to_string();
                    self.emit_goaway(H2ErrorCode::ProtocolError, &mut outbound);
                    events.push(H2Event::Error(msg));
                    break;
                }
            }
        }

        (events, outbound)
    }

    /// Recycle consumed buffers back into the engine for capacity reuse.
    ///
    /// Call after processing the events/frames returned by `process()`.
    /// The vectors are cleared and stored for the next `process()` call,
    /// avoiding repeated heap allocations.
    pub fn recycle_buffers(&mut self, mut events: Vec<H2Event>, mut outbound: Vec<H2Frame>) {
        events.clear();
        outbound.clear();
        if events.capacity() > self.event_buf.capacity() {
            self.event_buf = events;
        }
        if outbound.capacity() > self.outbound_buf.capacity() {
            self.outbound_buf = outbound;
        }
    }

    /// Check if the server's MAX_CONCURRENT_STREAMS allows opening another stream.
    pub fn can_open_stream(&self) -> bool {
        self.state.can_open_stream()
    }

    /// Allocate a new stream ID and return it.
    pub fn open_stream(&mut self) -> u32 {
        self.state.open_stream()
    }

    /// Encode a HEADERS frame for a request.
    ///
    /// `headers` should include pseudo-headers (`:method`, `:path`, etc.)
    /// already ordered according to `profile.pseudo_header_order`.
    pub fn send_headers<N: AsRef<str>, V: AsRef<str>>(
        &mut self,
        stream_id: u32,
        headers: &[(N, V)],
        end_stream: bool,
        output: &mut BytesMut,
    ) {
        let frames = self.build_headers(stream_id, headers, end_stream, None);
        for frame in &frames {
            self.codec.encode(frame, output);
        }
    }

    /// Build HEADERS frame(s) without encoding them.
    ///
    /// If the header block exceeds `max_frame_size`, the block is split
    /// into a HEADERS frame followed by CONTINUATION frames per RFC 7540 §4.2.
    ///
    /// When `req_priority` is provided and the profile has `urgency_weights`,
    /// the H2 priority weight is derived from the urgency level.  Otherwise
    /// the static `headers_priority` from the profile is used.
    ///
    /// Stream dependency is computed according to `StreamDepPolicy`:
    /// - `Flat`: always depends on stream 0
    /// - `Chain`: depends on the previous client stream ID
    pub fn build_headers<N: AsRef<str>, V: AsRef<str>>(
        &mut self,
        stream_id: u32,
        headers: &[(N, V)],
        end_stream: bool,
        req_priority: Option<crate::profile::RequestPriority>,
    ) -> Vec<H2Frame> {
        let priority = self.resolve_priority(stream_id, req_priority);

        let header_block = match &self.hpack_policy {
            Some(policy) => self.state.encode_headers_with_policy(headers, &**policy),
            None => self.state.encode_headers(headers),
        };

        let max_frame_size = self.state.remote_settings().max_frame_size as usize;
        let priority_overhead = if priority.is_some() { 5 } else { 0 };
        let first_max = max_frame_size.saturating_sub(priority_overhead);

        let mut frames = Vec::new();

        if header_block.len() <= first_max {
            frames.push(H2Frame::Headers(HeadersFrame {
                stream_id,
                header_block,
                end_stream,
                end_headers: true,
                priority,
                padding: None,
            }));
        } else {
            let first_block = header_block.slice(..first_max);
            let mut remaining = header_block.slice(first_max..);

            frames.push(H2Frame::Headers(HeadersFrame {
                stream_id,
                header_block: first_block,
                end_stream,
                end_headers: false,
                priority,
                padding: None,
            }));

            while !remaining.is_empty() {
                let chunk_len = remaining.len().min(max_frame_size);
                let chunk = remaining.slice(..chunk_len);
                remaining = remaining.slice(chunk_len..);

                frames.push(H2Frame::Continuation(ContinuationFrame {
                    stream_id,
                    header_block: chunk,
                    end_headers: remaining.is_empty(),
                }));
            }
        }

        if end_stream {
            if let Some(stream) = self.state.get_stream_mut(stream_id) {
                let _ = stream.send_end_stream();
            }
        }

        // Track for Chain dependency policy
        self.last_client_stream_id = Some(stream_id);

        frames
    }

    /// Compute the H2 PrioritySpec for a given request.
    ///
    /// Resolution order:
    /// 1. If `urgency_weights` is set → map urgency to weight, apply dep policy
    /// 2. Else → use static `headers_priority` from profile (fallback)
    fn resolve_priority(
        &self,
        _stream_id: u32,
        req_priority: Option<crate::profile::RequestPriority>,
    ) -> Option<PrioritySpec> {
        let cfg = &self.priority_config;
        let rp = cfg.effective_priority(req_priority);

        if let Some(weight) = cfg.weight_for_urgency(rp.urgency) {
            let dep = match cfg.stream_dep_policy {
                crate::profile::StreamDepPolicy::Flat => 0,
                crate::profile::StreamDepPolicy::Chain => self.last_client_stream_id.unwrap_or(0),
            };
            Some(PrioritySpec {
                exclusive: cfg.exclusive,
                stream_dependency: dep,
                weight,
            })
        } else {
            // No urgency_weights → use static fallback from profile
            self.headers_priority
        }
    }

    /// Encode DATA frame(s) for a request body.
    ///
    /// Splits the body into multiple DATA frames respecting `max_frame_size`
    /// and flow control windows. Any data that cannot be sent immediately is
    /// buffered internally and will be emitted as outbound frames when
    /// WINDOW_UPDATE frames arrive.
    pub fn send_data(
        &mut self,
        stream_id: u32,
        data: Bytes,
        end_stream: bool,
        output: &mut BytesMut,
    ) {
        let frames = self.build_data(stream_id, data, end_stream);
        for frame in &frames {
            self.codec.encode(frame, output);
        }
    }

    /// Build DATA frame(s) for a request body.
    ///
    /// Splits data into frames respecting `max_frame_size` and the
    /// connection/stream-level flow control windows. If the window is
    /// exhausted before all data is sent, the remainder is stored in
    /// `pending_data` and will be flushed when WINDOW_UPDATE is received.
    /// `end_stream` is only set on the final DATA frame when all data
    /// has actually been sent.
    pub fn build_data(&mut self, stream_id: u32, data: Bytes, end_stream: bool) -> Vec<H2Frame> {
        let max_frame_size = self.state.remote_settings().max_frame_size as usize;
        let mut frames = Vec::new();
        let mut remaining = data;

        while !remaining.is_empty() {
            let conn_avail = self.state.send_window_available() as usize;
            let stream_avail = self
                .state
                .get_stream(stream_id)
                .map(|s| s.send_window_available() as usize)
                .unwrap_or(0);
            let window = conn_avail.min(stream_avail);

            if window == 0 {
                tracing::debug!(
                    stream_id,
                    pending_bytes = remaining.len(),
                    "h2.flow_control_blocked"
                );
                self.pending_data.push(PendingBodyData {
                    stream_id,
                    data: remaining,
                    end_stream,
                });
                return frames;
            }

            let chunk_size = remaining.len().min(max_frame_size).min(window);
            let chunk = remaining.slice(..chunk_size);
            remaining = remaining.slice(chunk_size..);

            self.state.consume_send_window(chunk_size as u32);
            if let Some(s) = self.state.get_stream_mut(stream_id) {
                s.consume_send_window(chunk_size as u32);
            }

            let is_last = remaining.is_empty();
            let frame_end_stream = end_stream && is_last;

            frames.push(H2Frame::Data(DataFrame {
                stream_id,
                data: chunk,
                end_stream: frame_end_stream,
                padding: None,
            }));

            if frame_end_stream {
                if let Some(stream) = self.state.get_stream_mut(stream_id) {
                    let _ = stream.send_end_stream();
                }
            }
        }

        if remaining.is_empty() && frames.is_empty() && end_stream {
            frames.push(H2Frame::Data(DataFrame {
                stream_id,
                data: Bytes::new(),
                end_stream: true,
                padding: None,
            }));
            if let Some(stream) = self.state.get_stream_mut(stream_id) {
                let _ = stream.send_end_stream();
            }
        }

        frames
    }

    /// Drain pending body data that can now be sent after a window update.
    ///
    /// Returns DATA frames for any pending data that fits in the updated
    /// flow control window. Any data that still doesn't fit remains in
    /// `pending_data` (re-buffered by `build_data`).
    fn drain_pending_data(&mut self) -> Vec<H2Frame> {
        let mut frames = Vec::new();

        // Take all pending items; `build_data` will re-buffer anything
        // that still can't be sent.
        for pending in std::mem::take(&mut self.pending_data) {
            let new_frames = self.build_data(pending.stream_id, pending.data, pending.end_stream);
            frames.extend(new_frames);
        }

        frames
    }

    /// Encode a RST_STREAM frame directly to a buffer.
    pub fn send_rst_stream(&mut self, stream_id: u32, error_code: u32, output: &mut BytesMut) {
        let frame = self.make_rst_stream(stream_id, error_code);
        self.codec.encode(&frame, output);
    }

    /// Encode a WINDOW_UPDATE frame directly to a buffer.
    pub fn send_window_update(&mut self, stream_id: u32, increment: u32, output: &mut BytesMut) {
        let frame = Self::make_window_update(stream_id, increment);
        self.codec.encode(&frame, output);
    }

    /// Encode a vec of frames into a `BytesMut` buffer.
    pub fn encode_frames(&self, frames: &[H2Frame], output: &mut BytesMut) {
        for frame in frames {
            self.codec.encode(frame, output);
        }
    }

    // ── Frame builders (produce H2Frame without encoding) ────────────

    fn make_rst_stream(&mut self, stream_id: u32, error_code: u32) -> H2Frame {
        if let Some(stream) = self.state.get_stream_mut(stream_id) {
            stream.reset();
        }
        H2Frame::RstStream(RstStreamFrame {
            stream_id,
            error_code,
        })
    }

    fn make_window_update(stream_id: u32, increment: u32) -> H2Frame {
        H2Frame::WindowUpdate(WindowUpdateFrame {
            stream_id,
            increment,
        })
    }

    fn make_settings_ack() -> H2Frame {
        H2Frame::Settings(SettingsFrame {
            ack: true,
            settings: vec![],
        })
    }

    fn make_goaway(&self, error_code: H2ErrorCode) -> H2Frame {
        H2Frame::GoAway(GoAwayFrame {
            last_stream_id: self.last_peer_stream_id,
            error_code: error_code.as_u32(),
            debug_data: Bytes::new(),
        })
    }

    fn make_ping_ack(data: [u8; 8]) -> H2Frame {
        H2Frame::Ping(PingFrame { ack: true, data })
    }

    // ── Emit helpers (push frames to outbound vec) ───────────────────

    fn emit_rst_stream(&mut self, stream_id: u32, error_code: u32, outbound: &mut Vec<H2Frame>) {
        outbound.push(self.make_rst_stream(stream_id, error_code));
    }

    fn emit_window_update(stream_id: u32, increment: u32, outbound: &mut Vec<H2Frame>) {
        outbound.push(Self::make_window_update(stream_id, increment));
    }

    fn emit_settings_ack(outbound: &mut Vec<H2Frame>) {
        outbound.push(Self::make_settings_ack());
    }

    fn emit_goaway(&self, error_code: H2ErrorCode, outbound: &mut Vec<H2Frame>) {
        outbound.push(self.make_goaway(error_code));
    }

    fn emit_ping_ack(data: [u8; 8], outbound: &mut Vec<H2Frame>) {
        outbound.push(Self::make_ping_ack(data));
    }

    /// Check if the connection has received a GOAWAY.
    pub fn is_goaway(&self) -> bool {
        self.state.has_error()
    }

    /// Get the connection-level send window size.
    pub fn send_window(&self) -> i32 {
        self.state.send_window()
    }

    // ── Internal frame handling ──────────────────────────────────────────

    fn handle_frame(
        &mut self,
        frame: H2Frame,
        events: &mut Vec<H2Event>,
        outbound: &mut Vec<H2Frame>,
    ) {
        match frame {
            H2Frame::Settings(f) => self.handle_settings(f, events, outbound),
            H2Frame::Headers(f) => self.handle_headers(f, events, outbound),
            H2Frame::Data(f) => self.handle_data(f, events, outbound),
            H2Frame::WindowUpdate(f) => self.handle_window_update(f, events, outbound),
            H2Frame::Ping(f) => self.handle_ping(f, events, outbound),
            H2Frame::GoAway(f) => self.handle_goaway(f, events),
            H2Frame::RstStream(f) => self.handle_rst_stream(f, events),
            H2Frame::Continuation(f) => self.handle_continuation(f, events, outbound),
            H2Frame::PushPromise(_) => {
                self.emit_goaway(H2ErrorCode::ProtocolError, outbound);
                events.push(H2Event::Error("server push not supported".into()));
            }
            H2Frame::Priority(_) | H2Frame::Unknown(_) => {}
        }
    }

    fn handle_settings(
        &mut self,
        frame: SettingsFrame,
        events: &mut Vec<H2Event>,
        outbound: &mut Vec<H2Frame>,
    ) {
        if frame.ack {
            events.push(H2Event::LocalSettingsAcked);
            if let Err(e) = self.state.apply_remote_settings(&frame) {
                events.push(H2Event::Error(e.to_string()));
            }
            return;
        }

        // Capture old header_table_size before applying
        let old_header_table_size = self.state.remote_settings().header_table_size;

        if let Err(e) = self.state.apply_remote_settings(&frame) {
            self.emit_goaway(H2ErrorCode::ProtocolError, outbound);
            events.push(H2Event::Error(e.to_string()));
            return;
        }

        // P0: sync encoder dynamic table size when remote HEADER_TABLE_SIZE changes
        let new_header_table_size = self.state.remote_settings().header_table_size;
        if new_header_table_size != old_header_table_size {
            self.state
                .set_encoder_table_size(new_header_table_size as usize);
        }

        // NOTE: the server's SETTINGS_MAX_FRAME_SIZE is intentionally NOT used
        // to size our receive/decode cap (`self.codec`). Per RFC 7540 §4.2 the
        // limit on frames the peer may send us is *our* advertised value, fixed
        // at construction. The remote value only bounds frames we emit, which
        // `build_data`/`build_headers` read from `remote_settings()` directly.

        Self::emit_settings_ack(outbound);
        self.remote_settings_received = true;
        events.push(H2Event::SettingsAcked);

        debug!(
            max_concurrent = ?self.state.remote_settings().max_concurrent_streams,
            initial_window = self.state.remote_settings().initial_window_size,
            max_frame_size = self.state.remote_settings().max_frame_size,
            "h2.remote_settings_applied"
        );
    }

    fn handle_headers(
        &mut self,
        frame: HeadersFrame,
        events: &mut Vec<H2Event>,
        outbound: &mut Vec<H2Frame>,
    ) {
        match self.continuation.push_headers(
            frame.stream_id,
            &frame.header_block,
            frame.end_stream,
            frame.end_headers,
        ) {
            AssemblyResult::Complete {
                stream_id,
                header_block,
                end_stream,
            } => self.complete_headers(stream_id, &header_block, end_stream, events, outbound),
            AssemblyResult::Incomplete => {}
            AssemblyResult::Error(msg) => {
                self.emit_goaway(H2ErrorCode::ProtocolError, outbound);
                events.push(H2Event::Error(msg));
            }
        }
    }

    fn handle_continuation(
        &mut self,
        frame: ContinuationFrame,
        events: &mut Vec<H2Event>,
        outbound: &mut Vec<H2Frame>,
    ) {
        match self.continuation.push_continuation(
            frame.stream_id,
            &frame.header_block,
            frame.end_headers,
        ) {
            AssemblyResult::Complete {
                stream_id,
                header_block,
                end_stream,
            } => self.complete_headers(stream_id, &header_block, end_stream, events, outbound),
            AssemblyResult::Incomplete => {}
            AssemblyResult::Error(msg) => {
                self.emit_goaway(H2ErrorCode::ProtocolError, outbound);
                events.push(H2Event::Error(msg));
            }
        }
    }

    fn complete_headers(
        &mut self,
        stream_id: u32,
        header_block: &[u8],
        end_stream: bool,
        events: &mut Vec<H2Event>,
        outbound: &mut Vec<H2Frame>,
    ) {
        let headers = match self.state.decode_header_block(header_block) {
            Ok(h) => h,
            Err(e) => {
                self.emit_goaway(H2ErrorCode::CompressionError, outbound);
                events.push(H2Event::Error(format!(
                    "HPACK decode error on stream {stream_id}: {e}"
                )));
                return;
            }
        };

        // For client-side, incoming HEADERS = response headers
        let stream = match self.state.get_stream_mut(stream_id) {
            Some(s) => s,
            None => {
                tracing::warn!(stream_id, "h2.headers_for_unknown_stream");
                events.push(H2Event::Error(format!(
                    "received HEADERS for unknown stream {stream_id}"
                )));
                return;
            }
        };

        if end_stream {
            let _ = stream.recv_end_stream();
        }

        events.push(H2Event::ResponseHeaders {
            stream_id,
            headers,
            end_stream,
        });
    }

    fn handle_data(
        &mut self,
        frame: DataFrame,
        events: &mut Vec<H2Event>,
        outbound: &mut Vec<H2Frame>,
    ) {
        let flow_len = if let Some(pad_len) = frame.padding {
            1 + frame.data.len() as u32 + pad_len as u32
        } else {
            frame.data.len() as u32
        };

        if let Err(e) = self.state.consume_recv_window(flow_len) {
            self.emit_goaway(H2ErrorCode::FlowControlError, outbound);
            events.push(H2Event::Error(e.to_string()));
            return;
        }

        let stream_recv_window;
        let stream_initial_window;
        if let Some(stream) = self.state.get_stream_mut(frame.stream_id) {
            if !stream.state().can_receive() {
                tracing::warn!(
                    stream_id = frame.stream_id,
                    state = %stream.state(),
                    "h2.data_after_end_stream"
                );
                self.emit_rst_stream(
                    frame.stream_id,
                    H2ErrorCode::StreamClosed.as_u32(),
                    outbound,
                );
                return;
            }

            if let Err(_e) = stream.consume_recv_window(flow_len) {
                self.emit_rst_stream(
                    frame.stream_id,
                    H2ErrorCode::FlowControlError.as_u32(),
                    outbound,
                );
                events.push(H2Event::StreamReset {
                    stream_id: frame.stream_id,
                    error_code: H2ErrorCode::FlowControlError.as_u32(),
                });
                return;
            }

            stream_recv_window = stream.recv_window();
            stream_initial_window = stream.initial_window_size();

            if frame.end_stream {
                let _ = stream.recv_end_stream();
            }
        } else {
            stream_recv_window = 0;
            stream_initial_window = 65535;
        }

        if flow_len > 0 {
            if let Some(increment) = self.flow_control.on_data_received(
                0,
                flow_len,
                self.state.recv_window(),
                self.conn_initial_recv_window,
            ) {
                Self::emit_window_update(0, increment, outbound);
                let _ = self.state.update_recv_window(increment);
            }

            if let Some(increment) = self.flow_control.on_data_received(
                frame.stream_id,
                flow_len,
                stream_recv_window,
                stream_initial_window,
            ) {
                Self::emit_window_update(frame.stream_id, increment, outbound);
                if let Some(stream) = self.state.get_stream_mut(frame.stream_id) {
                    let _ = stream.update_recv_window(increment);
                }
            }
        }

        if frame.end_stream {
            self.flow_control.on_stream_closed(frame.stream_id);
            self.state.cleanup_closed_streams();
        }

        events.push(H2Event::ResponseData {
            stream_id: frame.stream_id,
            data: frame.data,
            end_stream: frame.end_stream,
        });
    }

    fn handle_window_update(
        &mut self,
        frame: WindowUpdateFrame,
        events: &mut Vec<H2Event>,
        outbound: &mut Vec<H2Frame>,
    ) {
        if frame.increment == 0 {
            if frame.stream_id == 0 {
                self.emit_goaway(H2ErrorCode::ProtocolError, outbound);
                events.push(H2Event::Error(
                    "WINDOW_UPDATE increment=0 on connection".into(),
                ));
            } else {
                self.emit_rst_stream(
                    frame.stream_id,
                    H2ErrorCode::ProtocolError.as_u32(),
                    outbound,
                );
            }
            return;
        }

        if frame.stream_id == 0 {
            if let Err(e) = self.state.update_send_window(frame.increment) {
                self.emit_goaway(H2ErrorCode::FlowControlError, outbound);
                events.push(H2Event::Error(e.to_string()));
                return;
            }
        } else if let Some(stream) = self.state.get_stream_mut(frame.stream_id) {
            if let Err(e) = stream.update_send_window(frame.increment) {
                self.emit_rst_stream(
                    frame.stream_id,
                    H2ErrorCode::FlowControlError.as_u32(),
                    outbound,
                );
                events.push(H2Event::Error(e.to_string()));
                return;
            }
        }

        // Drain any pending body data that can now be sent
        if !self.pending_data.is_empty() {
            let drained = self.drain_pending_data();
            outbound.extend(drained);
        }

        events.push(H2Event::WindowUpdate {
            stream_id: frame.stream_id,
            increment: frame.increment,
        });
    }

    fn handle_ping(
        &mut self,
        frame: PingFrame,
        events: &mut Vec<H2Event>,
        outbound: &mut Vec<H2Frame>,
    ) {
        if !frame.ack {
            Self::emit_ping_ack(frame.data, outbound);
            events.push(H2Event::PingAck);
        }
    }

    fn handle_goaway(&mut self, frame: GoAwayFrame, events: &mut Vec<H2Event>) {
        self.state
            .handle_goaway(frame.last_stream_id, frame.error_code);
        events.push(H2Event::GoAway {
            last_stream_id: frame.last_stream_id,
            error_code: frame.error_code,
            debug_data: frame.debug_data,
        });
    }

    fn handle_rst_stream(&mut self, frame: RstStreamFrame, events: &mut Vec<H2Event>) {
        if let Some(stream) = self.state.get_stream_mut(frame.stream_id) {
            stream.reset();
        }
        self.state.cleanup_closed_streams();
        events.push(H2Event::StreamReset {
            stream_id: frame.stream_id,
            error_code: frame.error_code,
        });
    }

    /// Build all frames for an HTTP request (HEADERS + optional DATA).
    ///
    /// Extracts method/scheme/authority/path from the request URI,
    /// orders pseudo-headers according to the profile, HPACK-encodes
    /// them, and returns the frames ready for the write policy to group.
    ///
    /// Uses `&str` references internally to avoid per-header `String`
    /// allocations — headers go straight from `http::HeaderMap` into
    /// the HPACK encoder without intermediate copying.
    pub fn build_request(
        &mut self,
        stream_id: u32,
        request: http::Request<Option<Bytes>>,
    ) -> Vec<H2Frame> {
        let (parts, body) = request.into_parts();

        let req_priority = parts
            .extensions
            .get::<crate::profile::RequestPriority>()
            .copied();

        let method = parts.method.as_str();
        let authority = parts.uri.authority().map(|a| a.as_str()).unwrap_or("");
        let scheme = parts.uri.scheme_str().unwrap_or("https");
        let path_and_query = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        let ordered =
            self.order_headers_ref(method, scheme, authority, path_and_query, &parts.headers);

        let has_body = body.as_ref().is_some_and(|b| !b.is_empty());
        let headers_end_stream = !has_body;

        let mut frames = self.build_headers(stream_id, &ordered, headers_end_stream, req_priority);

        if let Some(body_data) = body {
            if !body_data.is_empty() {
                frames.extend(self.build_data(stream_id, body_data, true));
            }
        }

        frames
    }

    /// Build request frames from a NativeH2Request with pre-ordered headers.
    ///
    /// Unlike `build_request`, this accepts headers as a Vec (guaranteed order)
    /// instead of iterating a HeaderMap (unspecified iteration order).
    pub(crate) fn build_native_request(
        &mut self,
        stream_id: u32,
        request: crate::adapter::NativeH2Request,
    ) -> Vec<H2Frame> {
        let method = request.method.as_str();
        let authority = request.uri.authority().map(|a| a.as_str()).unwrap_or("");
        let scheme = request.uri.scheme_str().unwrap_or("https");
        let path_and_query = request
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        use crate::profile::PseudoHeaderId;
        let mut ordered = Vec::with_capacity(4 + request.ordered_headers.len());

        for pseudo in &self.pseudo_header_order {
            match pseudo {
                PseudoHeaderId::Method => ordered.push((":method", method)),
                PseudoHeaderId::Authority => ordered.push((":authority", authority)),
                PseudoHeaderId::Scheme => ordered.push((":scheme", scheme)),
                PseudoHeaderId::Path => ordered.push((":path", path_and_query)),
            }
        }

        for (name, value) in &request.ordered_headers {
            ordered.push((name.as_str(), value.as_str()));
        }

        let has_body = request.body.as_ref().is_some_and(|b| !b.is_empty());
        let headers_end_stream = !has_body;

        let mut frames =
            self.build_headers(stream_id, &ordered, headers_end_stream, request.priority);

        if let Some(body_data) = request.body {
            if !body_data.is_empty() {
                frames.extend(self.build_data(stream_id, body_data, true));
            }
        }

        frames
    }

    /// Zero-allocation header ordering: builds `Vec<(&str, &str)>` from
    /// the request URI components and `http::HeaderMap`, avoiding
    /// intermediate `String` allocations.
    fn order_headers_ref<'a>(
        &self,
        method: &'a str,
        scheme: &'a str,
        authority: &'a str,
        path: &'a str,
        header_map: &'a http::HeaderMap,
    ) -> Vec<(&'a str, &'a str)> {
        use crate::profile::PseudoHeaderId;

        let mut result = Vec::with_capacity(4 + header_map.len());

        for pseudo in &self.pseudo_header_order {
            match pseudo {
                PseudoHeaderId::Method => result.push((":method", method)),
                PseudoHeaderId::Authority => result.push((":authority", authority)),
                PseudoHeaderId::Scheme => result.push((":scheme", scheme)),
                PseudoHeaderId::Path => result.push((":path", path)),
            }
        }

        for (name, value) in header_map {
            if let Ok(v) = value.to_str() {
                result.push((name.as_str(), v));
            }
        }

        result
    }

    /// Arrange request headers according to the profile's pseudo-header order.
    ///
    /// Returns owned `String` pairs for backward compatibility; prefer
    /// `build_request()` which avoids intermediate allocations.
    pub fn order_headers(
        &self,
        method: &str,
        scheme: &str,
        authority: &str,
        path: &str,
        extra_headers: &[(String, String)],
    ) -> Vec<(String, String)> {
        use crate::profile::PseudoHeaderId;

        let mut result = Vec::with_capacity(4 + extra_headers.len());

        for pseudo in &self.pseudo_header_order {
            match pseudo {
                PseudoHeaderId::Method => {
                    result.push((":method".to_string(), method.to_string()));
                }
                PseudoHeaderId::Authority => {
                    result.push((":authority".to_string(), authority.to_string()));
                }
                PseudoHeaderId::Scheme => {
                    result.push((":scheme".to_string(), scheme.to_string()));
                }
                PseudoHeaderId::Path => {
                    result.push((":path".to_string(), path.to_string()));
                }
            }
        }

        result.extend_from_slice(extra_headers);
        result
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::H2Codec;
    use crate::profile::{chrome_144_h2, firefox_147_h2, safari_26_h2};

    /// Helper: decode all frames from a buffer.
    fn decode_all(buf: &mut BytesMut) -> Vec<H2Frame> {
        let mut codec = H2Codec::new();
        let mut frames = Vec::new();
        while let DecodeResult::Frame(f) = codec.decode(buf) {
            frames.push(f);
        }
        frames
    }

    #[test]
    fn test_client_preface_chrome() {
        let (_engine, preface_frames) = H2Engine::client(&chrome_144_h2());

        assert!(preface_frames.len() >= 2); // SETTINGS + WINDOW_UPDATE
        assert!(matches!(preface_frames[0], H2Frame::Settings(_)));
        assert!(matches!(preface_frames[1], H2Frame::WindowUpdate(_)));

        if let H2Frame::WindowUpdate(wu) = &preface_frames[1] {
            assert_eq!(wu.increment, 15663105);
        }
    }

    #[test]
    fn test_client_preface_safari() {
        let (_engine, preface_frames) = H2Engine::client(&safari_26_h2());

        assert!(preface_frames.len() >= 2);

        if let H2Frame::Settings(s) = &preface_frames[0] {
            assert_eq!(s.settings.len(), 4);
            assert!(s.settings.iter().any(|p| p.id == 0x09 && p.value == 1));
        }
    }

    #[test]
    fn test_open_stream() {
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());
        assert_eq!(engine.open_stream(), 1);
        assert_eq!(engine.open_stream(), 3);
        assert_eq!(engine.open_stream(), 5);
    }

    #[test]
    fn test_send_headers_chrome() {
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());
        let sid = engine.open_stream();
        let mut output = BytesMut::new();

        let headers = engine.order_headers("GET", "https", "example.com", "/", &[]);
        engine.send_headers(sid, &headers, true, &mut output);

        let frames = decode_all(&mut output);
        assert_eq!(frames.len(), 1);

        if let H2Frame::Headers(h) = &frames[0] {
            assert_eq!(h.stream_id, 1);
            assert!(h.end_stream);
            assert!(h.end_headers);
            // Chrome default priority: u=1 (fetch) → weight 219
            assert!(h.priority.is_some());
            let p = h.priority.unwrap();
            assert!(p.exclusive);
            assert_eq!(p.stream_dependency, 0);
            assert_eq!(p.weight, 219);
        } else {
            panic!("expected Headers frame");
        }
    }

    #[test]
    fn test_send_headers_safari_no_priority() {
        let (mut engine, _) = H2Engine::client(&safari_26_h2());
        let sid = engine.open_stream();
        let mut output = BytesMut::new();

        let headers = engine.order_headers("GET", "https", "example.com", "/", &[]);
        engine.send_headers(sid, &headers, true, &mut output);

        let frames = decode_all(&mut output);
        if let H2Frame::Headers(h) = &frames[0] {
            // Safari 26 has NO_RFC7540_PRIORITIES → no PRIORITY flag
            assert!(h.priority.is_none());
        }
    }

    #[test]
    fn test_handle_settings() {
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());

        // Simulate server SETTINGS
        let codec = H2Codec::new();
        let mut server_buf = BytesMut::new();
        codec.encode(
            &H2Frame::Settings(SettingsFrame {
                ack: false,
                settings: vec![
                    SettingsParameter {
                        id: 0x03,
                        value: 128,
                    },
                    SettingsParameter {
                        id: 0x04,
                        value: 65536,
                    },
                ],
            }),
            &mut server_buf,
        );

        let (events, outbound) = engine.process(&mut server_buf);

        assert!(events.iter().any(|e| matches!(e, H2Event::SettingsAcked)));

        assert_eq!(outbound.len(), 1);
        if let H2Frame::Settings(s) = &outbound[0] {
            assert!(s.ack);
        }
    }

    #[test]
    fn server_settings_must_not_raise_our_receive_frame_size_limit() {
        // Our advertised SETTINGS_MAX_FRAME_SIZE bounds how large a frame the
        // server may send us (RFC 7540 §4.2). A malicious server advertising a
        // huge MAX_FRAME_SIZE must NOT be able to raise our *decode* limit and
        // make us buffer ~16 MB single frames.
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());

        // Baseline: the decode limit starts at our advertised value (16384).
        assert_eq!(engine.codec.max_frame_size(), 16384);

        let codec = H2Codec::new();
        let mut server_buf = BytesMut::new();
        codec.encode(
            &H2Frame::Settings(SettingsFrame {
                ack: false,
                settings: vec![SettingsParameter {
                    id: 0x05,          // SETTINGS_MAX_FRAME_SIZE
                    value: 16_777_215, // maximum legal value
                }],
            }),
            &mut server_buf,
        );
        let _ = engine.process(&mut server_buf);

        // The receive/decode cap must remain our advertised local value; the
        // server's value only bounds frames *we emit*, not frames we accept.
        assert_eq!(
            engine.codec.max_frame_size(),
            16384,
            "server SETTINGS must not raise our receive frame-size limit"
        );
    }

    #[test]
    fn test_handle_ping() {
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());

        let codec = H2Codec::new();
        let mut server_buf = BytesMut::new();
        codec.encode(
            &H2Frame::Ping(PingFrame {
                ack: false,
                data: [1, 2, 3, 4, 5, 6, 7, 8],
            }),
            &mut server_buf,
        );

        let (events, outbound) = engine.process(&mut server_buf);
        assert!(events.iter().any(|e| matches!(e, H2Event::PingAck)));

        assert_eq!(outbound.len(), 1);
        if let H2Frame::Ping(p) = &outbound[0] {
            assert!(p.ack);
            assert_eq!(p.data, [1, 2, 3, 4, 5, 6, 7, 8]);
        }
    }

    #[test]
    fn test_handle_goaway() {
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());

        let codec = H2Codec::new();
        let mut server_buf = BytesMut::new();
        codec.encode(
            &H2Frame::GoAway(GoAwayFrame {
                last_stream_id: 0,
                error_code: 0,
                debug_data: Bytes::new(),
            }),
            &mut server_buf,
        );

        let (events, _) = engine.process(&mut server_buf);
        assert!(events.iter().any(|e| matches!(e, H2Event::GoAway { .. })));
    }

    #[test]
    fn test_pseudo_header_order_chrome() {
        let (engine, _) = H2Engine::client(&chrome_144_h2());
        let h = engine.order_headers("GET", "https", "example.com", "/foo", &[]);
        assert_eq!(h[0], (":method".to_string(), "GET".to_string()));
        assert_eq!(h[1], (":authority".to_string(), "example.com".to_string()));
        assert_eq!(h[2], (":scheme".to_string(), "https".to_string()));
        assert_eq!(h[3], (":path".to_string(), "/foo".to_string()));
    }

    #[test]
    fn test_pseudo_header_order_safari() {
        let (engine, _) = H2Engine::client(&safari_26_h2());
        let h = engine.order_headers("GET", "https", "example.com", "/bar", &[]);
        // Safari 26: m,s,a,p
        assert_eq!(h[0].0, ":method");
        assert_eq!(h[1].0, ":scheme");
        assert_eq!(h[2].0, ":authority");
        assert_eq!(h[3].0, ":path");
    }

    #[test]
    fn test_handle_response_headers_and_data() {
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());
        let sid = engine.open_stream();

        // Simulate server sending response HEADERS
        let mut hpack_encoder = crate::hpack::HeaderEncoder::with_default_size();
        let block = hpack_encoder.encode(vec![(":status", "200"), ("content-type", "text/plain")]);

        let codec = H2Codec::new();
        let mut server_buf = BytesMut::new();
        codec.encode(
            &H2Frame::Headers(HeadersFrame {
                stream_id: sid,
                header_block: Bytes::from(block),
                end_stream: false,
                end_headers: true,
                priority: None,
                padding: None,
            }),
            &mut server_buf,
        );

        // Simulate server sending DATA
        codec.encode(
            &H2Frame::Data(DataFrame {
                stream_id: sid,
                data: Bytes::from_static(b"Hello, World!"),
                end_stream: true,
                padding: None,
            }),
            &mut server_buf,
        );

        let (events, _) = engine.process(&mut server_buf);

        // Should have ResponseHeaders and ResponseData events
        let has_headers = events.iter().any(|e| {
            matches!(e, H2Event::ResponseHeaders { stream_id, headers, .. }
                if *stream_id == sid && headers.iter().any(|(n, v)| n == ":status" && v == "200"))
        });
        assert!(
            has_headers,
            "expected ResponseHeaders event with :status=200"
        );

        let has_data = events.iter().any(|e| {
            matches!(e, H2Event::ResponseData { stream_id, data, end_stream }
                if *stream_id == sid && data.as_ref() == b"Hello, World!" && *end_stream)
        });
        assert!(has_data, "expected ResponseData event with body");
    }

    // ── Body / flow-control tests ─────────────────────────────────────

    #[test]
    fn test_build_data_small_body_single_frame() {
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());
        let sid = engine.open_stream();

        let body = Bytes::from(vec![0xAA; 1024]);
        let frames = engine.build_data(sid, body.clone(), true);

        assert_eq!(frames.len(), 1);
        if let H2Frame::Data(d) = &frames[0] {
            assert_eq!(d.stream_id, sid);
            assert_eq!(d.data.len(), 1024);
            assert!(d.end_stream);
        } else {
            panic!("expected DATA frame");
        }
        assert!(engine.pending_data.is_empty());
    }

    #[test]
    fn test_build_data_splits_by_max_frame_size() {
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());
        let sid = engine.open_stream();

        // Increase the send window so flow control doesn't block
        engine.state.update_send_window(1_000_000).unwrap();
        engine
            .state
            .get_stream_mut(sid)
            .unwrap()
            .update_send_window(1_000_000)
            .unwrap();

        // Default max_frame_size is 16384
        let max_frame_size = engine.state.remote_settings().max_frame_size as usize;
        assert_eq!(max_frame_size, 16384);

        // Body larger than one frame but within window
        let body_size = max_frame_size * 3 + 100;
        let body = Bytes::from(vec![0xBB; body_size]);
        let frames = engine.build_data(sid, body, true);

        assert_eq!(frames.len(), 4, "should split into 4 DATA frames");

        let mut total = 0usize;
        for (i, frame) in frames.iter().enumerate() {
            if let H2Frame::Data(d) = frame {
                assert_eq!(d.stream_id, sid);
                total += d.data.len();
                if i < frames.len() - 1 {
                    assert!(!d.end_stream, "only last frame should have end_stream");
                    assert_eq!(d.data.len(), max_frame_size);
                } else {
                    assert!(d.end_stream, "last frame must have end_stream");
                    assert_eq!(d.data.len(), 100);
                }
            } else {
                panic!("expected DATA frame at index {i}");
            }
        }
        assert_eq!(total, body_size);
        assert!(engine.pending_data.is_empty());
    }

    #[test]
    fn test_build_data_large_body_exceeds_window_buffers_pending() {
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());
        let sid = engine.open_stream();

        // Default connection + stream window is 65535 each
        let window = engine.state.send_window_available();
        assert_eq!(window, 65535);

        let body_size = 100_000; // > 65535
        let body = Bytes::from(vec![0xCC; body_size]);
        let frames = engine.build_data(sid, body, true);

        // Should have sent as much as the window allows (split by max_frame_size)
        let sent: usize = frames
            .iter()
            .map(|f| match f {
                H2Frame::Data(d) => d.data.len(),
                _ => 0,
            })
            .sum();
        assert_eq!(sent, 65535, "should send exactly the window size");

        // None of these frames should have end_stream (data still pending)
        for frame in &frames {
            if let H2Frame::Data(d) = frame {
                assert!(
                    !d.end_stream,
                    "end_stream must not be set while data is pending"
                );
            }
        }

        // Remainder should be buffered
        assert_eq!(engine.pending_data.len(), 1);
        assert_eq!(engine.pending_data[0].data.len(), body_size - 65535);
        assert!(engine.pending_data[0].end_stream);
    }

    #[test]
    fn test_window_update_drains_pending_data() {
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());
        let sid = engine.open_stream();

        let body_size = 100_000;
        let body = Bytes::from(vec![0xDD; body_size]);
        let initial_frames = engine.build_data(sid, body, true);

        let initial_sent: usize = initial_frames
            .iter()
            .map(|f| match f {
                H2Frame::Data(d) => d.data.len(),
                _ => 0,
            })
            .sum();
        assert_eq!(initial_sent, 65535);
        assert_eq!(engine.pending_data.len(), 1);

        // Simulate server sending WINDOW_UPDATE for both connection and stream
        let codec = H2Codec::new();
        let mut server_buf = BytesMut::new();
        // Connection-level WINDOW_UPDATE
        codec.encode(
            &H2Frame::WindowUpdate(WindowUpdateFrame {
                stream_id: 0,
                increment: 100_000,
            }),
            &mut server_buf,
        );
        // Stream-level WINDOW_UPDATE
        codec.encode(
            &H2Frame::WindowUpdate(WindowUpdateFrame {
                stream_id: sid,
                increment: 100_000,
            }),
            &mut server_buf,
        );

        let (_events, outbound) = engine.process(&mut server_buf);

        // Outbound should contain the remaining DATA frames
        let drained: usize = outbound
            .iter()
            .filter_map(|f| match f {
                H2Frame::Data(d) => Some(d.data.len()),
                _ => None,
            })
            .sum();
        let remaining = body_size - initial_sent;
        assert_eq!(drained, remaining, "all remaining data should be drained");

        // Last DATA frame must have end_stream
        let last_data = outbound
            .iter()
            .rev()
            .find(|f| matches!(f, H2Frame::Data(_)));
        if let Some(H2Frame::Data(d)) = last_data {
            assert!(d.end_stream, "last DATA frame must have end_stream=true");
        } else {
            panic!("expected at least one DATA frame in outbound");
        }

        assert!(engine.pending_data.is_empty(), "no more pending data");
    }

    #[test]
    fn test_build_data_preserves_content() {
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());
        let sid = engine.open_stream();

        // Increase window to avoid flow control blocking
        engine.state.update_send_window(500_000).unwrap();
        engine
            .state
            .get_stream_mut(sid)
            .unwrap()
            .update_send_window(500_000)
            .unwrap();

        // Create body with recognizable pattern
        let body_size = 80_000;
        let body: Vec<u8> = (0..body_size).map(|i| (i % 256) as u8).collect();
        let body = Bytes::from(body.clone());
        let frames = engine.build_data(sid, body.clone(), true);

        // Reassemble and verify content integrity
        let mut reassembled = Vec::new();
        for frame in &frames {
            if let H2Frame::Data(d) = frame {
                reassembled.extend_from_slice(&d.data);
            }
        }
        assert_eq!(reassembled.len(), body_size);
        assert_eq!(
            reassembled,
            body.as_ref(),
            "reassembled data must match original"
        );
    }

    #[test]
    fn test_build_data_exactly_at_window_boundary() {
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());
        let sid = engine.open_stream();

        // Body exactly equals window size (65535)
        let body = Bytes::from(vec![0xEE; 65535]);
        let frames = engine.build_data(sid, body, true);

        let total: usize = frames
            .iter()
            .map(|f| match f {
                H2Frame::Data(d) => d.data.len(),
                _ => 0,
            })
            .sum();
        assert_eq!(total, 65535);

        // Last frame should have end_stream
        if let Some(H2Frame::Data(d)) = frames.last() {
            assert!(d.end_stream);
        }
        assert!(engine.pending_data.is_empty());
    }

    #[test]
    fn test_build_request_large_body_not_truncated() {
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());

        // Increase window to accommodate the full body
        engine.state.update_send_window(500_000).unwrap();

        let body_size = 200_000;
        let body_data: Vec<u8> = (0..body_size).map(|i| (i % 256) as u8).collect();
        let body = Bytes::from(body_data.clone());

        let request = http::Request::builder()
            .method("POST")
            .uri("https://example.com/api")
            .body(Some(body))
            .unwrap();

        let sid = engine.open_stream();
        // Bump stream window too
        engine
            .state
            .get_stream_mut(sid)
            .unwrap()
            .update_send_window(500_000)
            .unwrap();

        let frames = engine.build_request(sid, request);

        // First frame(s) are HEADERS, rest are DATA
        let mut total_body = Vec::new();
        let mut found_headers = false;
        for frame in &frames {
            match frame {
                H2Frame::Headers(_) | H2Frame::Continuation(_) => {
                    found_headers = true;
                }
                H2Frame::Data(d) => {
                    total_body.extend_from_slice(&d.data);
                }
                _ => {}
            }
        }
        assert!(found_headers, "must have HEADERS frame");
        assert_eq!(
            total_body.len(),
            body_size,
            "body must NOT be truncated: got {} expected {}",
            total_body.len(),
            body_size
        );
        assert_eq!(total_body, body_data, "body content must match");

        // Last DATA frame must have end_stream
        let last_data = frames.iter().rev().find(|f| matches!(f, H2Frame::Data(_)));
        if let Some(H2Frame::Data(d)) = last_data {
            assert!(d.end_stream);
        }
    }

    #[test]
    fn test_multiple_window_updates_drain_large_body() {
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());
        let sid = engine.open_stream();

        let body_size = 200_000;
        let body: Vec<u8> = (0..body_size).map(|i| (i % 256) as u8).collect();
        let body = Bytes::from(body);
        let initial_frames = engine.build_data(sid, body, true);

        let mut total_sent: usize = initial_frames
            .iter()
            .map(|f| match f {
                H2Frame::Data(d) => d.data.len(),
                _ => 0,
            })
            .sum();
        assert_eq!(total_sent, 65535);

        // Simulate multiple rounds of WINDOW_UPDATE
        let codec = H2Codec::new();
        let mut rounds = 0;
        while !engine.pending_data.is_empty() {
            rounds += 1;
            assert!(rounds < 100, "too many rounds — likely infinite loop");

            let mut server_buf = BytesMut::new();
            codec.encode(
                &H2Frame::WindowUpdate(WindowUpdateFrame {
                    stream_id: 0,
                    increment: 50_000,
                }),
                &mut server_buf,
            );
            codec.encode(
                &H2Frame::WindowUpdate(WindowUpdateFrame {
                    stream_id: sid,
                    increment: 50_000,
                }),
                &mut server_buf,
            );

            let (_events, outbound) = engine.process(&mut server_buf);
            let round_sent: usize = outbound
                .iter()
                .filter_map(|f| match f {
                    H2Frame::Data(d) => Some(d.data.len()),
                    _ => None,
                })
                .sum();
            total_sent += round_sent;
        }

        assert_eq!(
            total_sent, body_size,
            "total sent across all rounds must equal body size"
        );
    }

    #[test]
    fn test_zero_window_buffers_everything() {
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());
        let sid = engine.open_stream();

        // Exhaust the connection send window entirely
        engine.state.consume_send_window(65535);

        let body = Bytes::from(vec![0xFF; 1000]);
        let frames = engine.build_data(sid, body, true);

        assert!(
            frames.is_empty(),
            "no frames should be emitted with zero window"
        );
        assert_eq!(engine.pending_data.len(), 1);
        assert_eq!(engine.pending_data[0].data.len(), 1000);
    }

    // ── build_native_request tests ────────────────────────────────────

    /// Decode the HPACK header block of a HEADERS frame back into name/value
    /// pairs so tests can assert on the actually-encoded wire headers.
    fn decode_header_block(frame: &H2Frame) -> Vec<(String, String)> {
        match frame {
            H2Frame::Headers(h) => crate::hpack::HeaderDecoder::new(65536)
                .decode(h.header_block.as_ref())
                .expect("HPACK header block should decode"),
            other => panic!("expected Headers frame, got {other:?}"),
        }
    }

    #[test]
    fn test_build_native_request_preserves_header_order() {
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());
        let sid = engine.open_stream();

        let native_req = crate::adapter::NativeH2Request {
            method: http::Method::GET,
            uri: "https://example.com/foo".parse().unwrap(),
            ordered_headers: vec![
                ("user-agent".to_string(), "test/1.0".to_string()),
                ("accept".to_string(), "text/html".to_string()),
                ("cookie".to_string(), "a=1".to_string()),
                ("cookie".to_string(), "b=2".to_string()),
            ],
            body: None,
            priority: None,
        };

        let frames = engine.build_native_request(sid, native_req);
        assert!(matches!(frames[0], H2Frame::Headers(_)));

        // The regular (non-pseudo) headers must appear in the supplied order,
        // including both `cookie` entries.
        let regular: Vec<(String, String)> = decode_header_block(&frames[0])
            .into_iter()
            .filter(|(name, _)| !name.starts_with(':'))
            .collect();
        assert_eq!(
            regular,
            vec![
                ("user-agent".to_string(), "test/1.0".to_string()),
                ("accept".to_string(), "text/html".to_string()),
                ("cookie".to_string(), "a=1".to_string()),
                ("cookie".to_string(), "b=2".to_string()),
            ]
        );
    }

    #[test]
    fn test_build_native_request_pseudo_headers_not_duplicated() {
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());
        let sid = engine.open_stream();

        let native_req = crate::adapter::NativeH2Request {
            method: http::Method::GET,
            uri: "https://example.com/".parse().unwrap(),
            ordered_headers: vec![("accept".to_string(), "text/html".to_string())],
            body: None,
            priority: None,
        };

        let frames = engine.build_native_request(sid, native_req);

        // Each pseudo-header must appear exactly once in the encoded block.
        let headers = decode_header_block(&frames[0]);
        for pseudo in [":method", ":authority", ":scheme", ":path"] {
            let count = headers.iter().filter(|(name, _)| name == pseudo).count();
            assert_eq!(count, 1, "pseudo-header {pseudo} must appear exactly once");
        }
    }

    // ── Priority resolution tests ─────────────────────────────────────

    #[test]
    fn test_chrome_priority_weight_fetch() {
        use crate::profile::RequestPriority;
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());
        let sid = engine.open_stream();
        let headers = engine.order_headers("GET", "https", "example.com", "/api", &[]);
        let frames = engine.build_headers(sid, &headers, true, Some(RequestPriority::fetch()));

        if let H2Frame::Headers(h) = &frames[0] {
            let p = h.priority.expect("Chrome should have priority");
            assert_eq!(p.weight, 219, "fetch = u=1 → weight 219");
            assert!(p.exclusive);
            assert_eq!(p.stream_dependency, 0, "first stream deps on 0");
        } else {
            panic!("expected Headers frame");
        }
    }

    #[test]
    fn test_chrome_priority_weight_image() {
        use crate::profile::RequestPriority;
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());
        let sid = engine.open_stream();
        let headers = engine.order_headers("GET", "https", "example.com", "/img.png", &[]);
        let frames = engine.build_headers(sid, &headers, true, Some(RequestPriority::image()));

        if let H2Frame::Headers(h) = &frames[0] {
            let p = h.priority.expect("Chrome should have priority");
            assert_eq!(p.weight, 146, "image = u=2 → weight 146");
        } else {
            panic!("expected Headers frame");
        }
    }

    #[test]
    fn test_chrome_priority_weight_navigation() {
        use crate::profile::RequestPriority;
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());
        let sid = engine.open_stream();
        let headers = engine.order_headers("GET", "https", "example.com", "/", &[]);
        let frames = engine.build_headers(sid, &headers, true, Some(RequestPriority::navigation()));

        if let H2Frame::Headers(h) = &frames[0] {
            let p = h.priority.expect("Chrome should have priority");
            assert_eq!(p.weight, 255, "navigation = u=0 → weight 255");
        } else {
            panic!("expected Headers frame");
        }
    }

    #[test]
    fn test_chrome_stream_dependency_chain() {
        use crate::profile::RequestPriority;
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());

        // First request: dep=0
        let sid1 = engine.open_stream();
        let headers = engine.order_headers("GET", "https", "example.com", "/a", &[]);
        let f1 = engine.build_headers(sid1, &headers, true, Some(RequestPriority::image()));
        if let H2Frame::Headers(h) = &f1[0] {
            assert_eq!(h.priority.unwrap().stream_dependency, 0);
        }

        // Second request: dep=sid1 (chain)
        let sid2 = engine.open_stream();
        let headers = engine.order_headers("GET", "https", "example.com", "/b", &[]);
        let f2 = engine.build_headers(sid2, &headers, true, Some(RequestPriority::image()));
        if let H2Frame::Headers(h) = &f2[0] {
            assert_eq!(
                h.priority.unwrap().stream_dependency,
                sid1,
                "second stream should depend on first"
            );
        }

        // Third request: dep=sid2 (chain continues)
        let sid3 = engine.open_stream();
        let headers = engine.order_headers("GET", "https", "example.com", "/c", &[]);
        let f3 = engine.build_headers(sid3, &headers, true, Some(RequestPriority::image()));
        if let H2Frame::Headers(h) = &f3[0] {
            assert_eq!(
                h.priority.unwrap().stream_dependency,
                sid2,
                "third stream should depend on second"
            );
        }
    }

    #[test]
    fn test_firefox_fixed_weight_ignores_urgency() {
        use crate::profile::RequestPriority;
        let (mut engine, _) = H2Engine::client(&firefox_147_h2());

        let sid = engine.open_stream();
        let headers = engine.order_headers("GET", "https", "example.com", "/", &[]);
        let frames = engine.build_headers(sid, &headers, true, Some(RequestPriority::fetch()));

        if let H2Frame::Headers(h) = &frames[0] {
            let p = h.priority.expect("Firefox should have priority");
            assert_eq!(p.weight, 42, "Firefox always uses fixed weight 42");
            assert!(!p.exclusive, "Firefox exclusive=false");
            assert_eq!(p.stream_dependency, 0, "Firefox always dep=0 (flat)");
        } else {
            panic!("expected Headers frame");
        }
    }

    #[test]
    fn test_firefox_flat_dependency() {
        use crate::profile::RequestPriority;
        let (mut engine, _) = H2Engine::client(&firefox_147_h2());

        let sid1 = engine.open_stream();
        let headers = engine.order_headers("GET", "https", "example.com", "/a", &[]);
        engine.build_headers(sid1, &headers, true, Some(RequestPriority::fetch()));

        let sid2 = engine.open_stream();
        let headers = engine.order_headers("GET", "https", "example.com", "/b", &[]);
        let f2 = engine.build_headers(sid2, &headers, true, Some(RequestPriority::fetch()));

        if let H2Frame::Headers(h) = &f2[0] {
            assert_eq!(
                h.priority.unwrap().stream_dependency,
                0,
                "Firefox uses flat dep (always 0)"
            );
        }
    }

    #[test]
    fn test_safari_26_no_priority() {
        use crate::profile::RequestPriority;
        let (mut engine, _) = H2Engine::client(&safari_26_h2());

        let sid = engine.open_stream();
        let headers = engine.order_headers("GET", "https", "example.com", "/", &[]);
        let frames = engine.build_headers(sid, &headers, true, Some(RequestPriority::fetch()));

        if let H2Frame::Headers(h) = &frames[0] {
            assert!(
                h.priority.is_none(),
                "Safari 26 should not embed H2 priority"
            );
        } else {
            panic!("expected Headers frame");
        }
    }

    #[test]
    fn test_chrome_default_priority_is_fetch() {
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());
        let sid = engine.open_stream();
        let headers = engine.order_headers("GET", "https", "example.com", "/", &[]);
        // None → uses default (u=1 for Chrome)
        let frames = engine.build_headers(sid, &headers, true, None);

        if let H2Frame::Headers(h) = &frames[0] {
            let p = h.priority.expect("Chrome should have priority");
            assert_eq!(p.weight, 219, "default u=1 → weight 219");
        } else {
            panic!("expected Headers frame");
        }
    }
}
