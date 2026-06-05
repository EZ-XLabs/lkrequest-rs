//! TCP fingerprint configuration for JA4T anti-detection.
//!
//! Modern WAFs (e.g. Cloudflare, Akamai) inspect TCP-level parameters from the
//! SYN packet to fingerprint the client OS and detect non-browser traffic.
//! This module allows configuring these parameters to match real browser TCP
//! fingerprints.
//!
//! # JA4T Format
//!
//! JA4T is a TCP fingerprinting method that captures four fields from the SYN:
//!
//! ```text
//! {window_size}_{tcp_options}_{mss}_{window_scale}
//!
//! Example: 64240_2-4-8-1-3_1460_8
//! ```
//!
//! | Part | Description | Example |
//! |------|-------------|---------|
//! | A    | TCP Window Size | `64240` |
//! | B    | TCP Options (kind numbers, dash-separated, SYN order) | `2-4-8-1-3` |
//! | C    | Maximum Segment Size (MSS) | `1460` |
//! | D    | Window Scale factor | `8` |
//!
//! # Platform notes
//!
//! - **TTL** and **TCP_NODELAY**: supported on all platforms.
//! - **Window Size / Window Scale**: influenced via `SO_RCVBUF` on all platforms.
//!   The kernel computes the actual window scale from the receive buffer size.
//! - **MSS** (`TCP_MAXSEG`): only settable on Linux via `setsockopt`. On other
//!   platforms the MSS field is stored for informational/JA4T purposes only.
//! - **TCP Options order**: determined by the OS kernel TCP stack and cannot be
//!   changed from userspace. The [`tcp_options`](TcpFingerprint::tcp_options)
//!   field is used for JA4T string formatting and documentation.

use std::fmt;
use std::time::Duration;

// ---------------------------------------------------------------------------
// TcpOption — TCP option kinds for JA4T
// ---------------------------------------------------------------------------

/// TCP option kind values as used in JA4T fingerprinting.
///
/// These represent the option types present in the TCP SYN packet.
/// The order of options is determined by the OS kernel and cannot be
/// changed via socket options.
///
/// # Common option orders by OS
///
/// | OS | Options | JA4T Part B |
/// |----|---------|-------------|
/// | Linux | MSS, SACK, TS, NOP, WS | `2-4-8-1-3` |
/// | Windows 10+ | MSS, NOP, WS, NOP, NOP, SACK | `2-1-3-1-1-4` |
/// | macOS/iOS | MSS, NOP, WS, NOP, NOP, TS, SACK, EOL | `2-1-3-1-1-8-4-0` |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[repr(u8)]
pub enum TcpOption {
    /// End of Option List (kind 0).
    EOL = 0,
    /// No-Operation / Padding (kind 1).
    NOP = 1,
    /// Maximum Segment Size (kind 2).
    MSS = 2,
    /// Window Scale (kind 3).
    WindowScale = 3,
    /// SACK Permitted (kind 4).
    SACKPermitted = 4,
    /// Timestamps (kind 8).
    Timestamps = 8,
}

impl TcpOption {
    /// Create from raw kind number.
    pub fn from_kind(kind: u8) -> Option<Self> {
        match kind {
            0 => Some(Self::EOL),
            1 => Some(Self::NOP),
            2 => Some(Self::MSS),
            3 => Some(Self::WindowScale),
            4 => Some(Self::SACKPermitted),
            8 => Some(Self::Timestamps),
            _ => None,
        }
    }

    /// Return the raw kind number.
    pub fn kind(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for TcpOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind())
    }
}

// ---------------------------------------------------------------------------
// TcpKeepalive
// ---------------------------------------------------------------------------

/// TCP keep-alive parameters.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TcpKeepalive {
    /// Enable keep-alive.
    pub enabled: bool,
    /// Idle time before the first keep-alive probe.
    pub idle: Option<Duration>,
    /// Interval between keep-alive probes.
    pub interval: Option<Duration>,
}

// ---------------------------------------------------------------------------
// TcpFingerprint
// ---------------------------------------------------------------------------

/// TCP fingerprint configuration targeting JA4T anti-detection.
///
/// Controls TCP socket parameters to match the JA4T fingerprint of a target
/// browser.  All fields are optional — `None` means "use the OS default".
///
/// # JA4T fields
///
/// The four core JA4T fields map directly to struct fields:
///
/// | JA4T Part | Field | Description |
/// |-----------|-------|-------------|
/// | A | [`window_size`](Self::window_size) | TCP Window Size in SYN |
/// | B | [`tcp_options`](Self::tcp_options) | TCP options order (kernel-determined) |
/// | C | [`mss`](Self::mss) | Maximum Segment Size |
/// | D | [`window_scale`](Self::window_scale) | Window Scale factor |
///
/// # Example
///
/// ```rust,no_run
/// use lkrequest::{Client, TcpFingerprint};
/// use lktls::profile::presets;
///
/// // Use a preset
/// let client = Client::builder()
///     .fingerprint(presets::chrome_144())
///     .tcp_fingerprint(TcpFingerprint::chrome())
///     .build();
///
/// // Or parse from a JA4T string
/// let fp = TcpFingerprint::from_ja4t("64240_2-4-8-1-3_1460_8").unwrap()
///     .with_ttl(128);
///
/// let client = Client::builder()
///     .fingerprint(presets::chrome_144())
///     .tcp_fingerprint(fp)
///     .build();
/// ```
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct TcpFingerprint {
    // === JA4T Part A: Window Size ===
    /// TCP Window Size advertised in the SYN packet (JA4T Part A).
    ///
    /// Common values:
    /// - `64240` — Windows 10/11
    /// - `65535` — macOS, iOS, Linux (common)
    /// - `29200` — Linux (some kernels)
    ///
    /// When set together with [`window_scale`](Self::window_scale), the
    /// `SO_RCVBUF` socket option is computed automatically to produce the
    /// desired combination. If [`recv_buf_size`](Self::recv_buf_size) is
    /// also set, it takes precedence as a raw override.
    pub window_size: Option<u32>,

    // === JA4T Part B: TCP Options ===
    /// TCP options in SYN packet order (JA4T Part B).
    ///
    /// **Note**: The actual options and their order are determined by the OS
    /// kernel TCP stack and cannot be changed from userspace via socket
    /// options.  This field is used for:
    /// - JA4T string generation ([`to_ja4t()`](Self::to_ja4t))
    /// - Documentation of the target fingerprint
    /// - Validation against captured traffic
    ///
    /// See [`TcpOption`] for common OS-specific orderings.
    pub tcp_options: Option<Vec<TcpOption>>,

    // === JA4T Part C: Maximum Segment Size ===
    /// Maximum Segment Size (JA4T Part C).
    ///
    /// Standard value is `1460` (Ethernet MTU 1500 minus 40 bytes of IP+TCP
    /// headers). Lower values like `1380` suggest VPN/tunnel overhead.
    ///
    /// **Platform support**: applied via `TCP_MAXSEG` setsockopt on Linux.
    /// On Windows/macOS the MSS is determined by the network MTU and cannot
    /// be overridden per-socket; the value is stored for JA4T purposes only.
    pub mss: Option<u32>,

    // === JA4T Part D: Window Scale ===
    /// Window Scale factor (JA4T Part D).
    ///
    /// Acts as a multiplier: `effective_window = window_size × 2^window_scale`.
    ///
    /// Common values:
    /// - `8` — Windows 10/11, Linux (common)
    /// - `7` — Linux (some configurations)
    /// - `6` — macOS/iOS
    ///
    /// The kernel chooses the window scale based on `SO_RCVBUF`. When both
    /// `window_size` and `window_scale` are set, we compute an appropriate
    /// `SO_RCVBUF` value to coax the kernel into using the desired scale.
    pub window_scale: Option<u8>,

    // === Additional TCP parameters (not in JA4T string) ===
    /// IP Time-To-Live.
    ///
    /// Typical values: `64` (Linux/macOS), `128` (Windows).
    /// While not part of the JA4T string, TTL is a key OS fingerprint
    /// dimension checked by some WAFs.
    pub ttl: Option<u32>,

    /// Raw TCP receive buffer size override (`SO_RCVBUF`).
    ///
    /// When set, this value is used directly as `SO_RCVBUF`, bypassing
    /// the automatic calculation from `window_size` + `window_scale`.
    ///
    /// Prefer using `window_size` + `window_scale` for JA4T-based
    /// configuration. Use this only when you need precise control over
    /// the socket buffer.
    pub recv_buf_size: Option<u32>,

    /// TCP send buffer size (`SO_SNDBUF`).
    pub send_buf_size: Option<u32>,

    /// Disable Nagle's algorithm (`TCP_NODELAY`).
    ///
    /// Browsers typically enable `TCP_NODELAY` (set to `true`).
    pub tcp_nodelay: Option<bool>,

    /// TCP keep-alive configuration.
    pub keepalive: Option<TcpKeepalive>,
}

// ---------------------------------------------------------------------------
// JA4T parsing / formatting
// ---------------------------------------------------------------------------

/// Error returned when parsing a JA4T string fails.
#[derive(Debug, Clone)]
pub struct Ja4tParseError {
    pub message: String,
}

impl fmt::Display for Ja4tParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JA4T parse error: {}", self.message)
    }
}

impl std::error::Error for Ja4tParseError {}

impl TcpFingerprint {
    // -------------------------------------------------------------------
    // JA4T string operations
    // -------------------------------------------------------------------

    /// Parse a JA4T fingerprint string into a `TcpFingerprint`.
    ///
    /// Format: `{window_size}_{tcp_options}_{mss}_{window_scale}`
    ///
    /// # Examples
    ///
    /// ```rust
    /// use lkrequest::TcpFingerprint;
    ///
    /// // Chrome on Windows
    /// let fp = TcpFingerprint::from_ja4t("64240_2-4-8-1-3_1460_8").unwrap();
    /// assert_eq!(fp.window_size, Some(64240));
    /// assert_eq!(fp.mss, Some(1460));
    /// assert_eq!(fp.window_scale, Some(8));
    ///
    /// // Safari on macOS
    /// let fp = TcpFingerprint::from_ja4t("65535_2-1-3-1-1-8-4-0_1460_6").unwrap();
    /// assert_eq!(fp.window_size, Some(65535));
    /// assert_eq!(fp.window_scale, Some(6));
    /// ```
    pub fn from_ja4t(s: &str) -> Result<Self, Ja4tParseError> {
        let parts: Vec<&str> = s.split('_').collect();
        if parts.len() != 4 {
            return Err(Ja4tParseError {
                message: format!(
                    "expected 4 underscore-separated parts, got {}. Format: window_size_options_mss_scale",
                    parts.len()
                ),
            });
        }

        // Part A: Window Size
        let window_size: u32 = parts[0].parse().map_err(|e| Ja4tParseError {
            message: format!("invalid window_size '{}': {}", parts[0], e),
        })?;

        // Part B: TCP Options (dash-separated kind numbers)
        let tcp_options: Vec<TcpOption> = parts[1]
            .split('-')
            .map(|s| {
                let kind: u8 = s.parse().map_err(|e| Ja4tParseError {
                    message: format!("invalid TCP option kind '{}': {}", s, e),
                })?;
                TcpOption::from_kind(kind).ok_or_else(|| Ja4tParseError {
                    message: format!("unknown TCP option kind: {}", kind),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Part C: MSS
        let mss: u32 = parts[2].parse().map_err(|e| Ja4tParseError {
            message: format!("invalid MSS '{}': {}", parts[2], e),
        })?;

        // Part D: Window Scale
        let window_scale: u8 = parts[3].parse().map_err(|e| Ja4tParseError {
            message: format!("invalid window_scale '{}': {}", parts[3], e),
        })?;

        Ok(Self {
            window_size: Some(window_size),
            tcp_options: Some(tcp_options),
            mss: Some(mss),
            window_scale: Some(window_scale),
            // Non-JA4T fields left as None
            ttl: None,
            recv_buf_size: None,
            send_buf_size: None,
            tcp_nodelay: None,
            keepalive: None,
        })
    }

    /// Format this fingerprint as a JA4T string.
    ///
    /// Returns `None` if any of the four JA4T parts is not set.
    ///
    /// # Example
    ///
    /// ```rust
    /// use lkrequest::TcpFingerprint;
    ///
    /// let fp = TcpFingerprint::chrome_win();
    /// assert_eq!(fp.to_ja4t().unwrap(), "64240_2-1-3-1-1-4_1460_8");
    /// ```
    pub fn to_ja4t(&self) -> Option<String> {
        let ws = self.window_size?;
        let opts = self.tcp_options.as_ref()?;
        let mss = self.mss?;
        let scale = self.window_scale?;

        let opts_str: String = opts
            .iter()
            .map(|o| o.kind().to_string())
            .collect::<Vec<_>>()
            .join("-");

        Some(format!("{}_{}_{}_{}", ws, opts_str, mss, scale))
    }

    // -------------------------------------------------------------------
    // Builder-style setters (chainable after from_ja4t or preset)
    // -------------------------------------------------------------------

    /// Set the IP TTL.
    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set TCP_NODELAY.
    pub fn with_tcp_nodelay(mut self, nodelay: bool) -> Self {
        self.tcp_nodelay = Some(nodelay);
        self
    }

    /// Set the window size (JA4T Part A).
    pub fn with_window_size(mut self, size: u32) -> Self {
        self.window_size = Some(size);
        self
    }

    /// Set the window scale factor (JA4T Part D).
    pub fn with_window_scale(mut self, scale: u8) -> Self {
        self.window_scale = Some(scale);
        self
    }

    /// Set the MSS (JA4T Part C).
    pub fn with_mss(mut self, mss: u32) -> Self {
        self.mss = Some(mss);
        self
    }

    /// Set the TCP options (JA4T Part B).
    pub fn with_tcp_options(mut self, options: Vec<TcpOption>) -> Self {
        self.tcp_options = Some(options);
        self
    }

    /// Override the raw receive buffer size (`SO_RCVBUF`).
    pub fn with_recv_buf_size(mut self, size: u32) -> Self {
        self.recv_buf_size = Some(size);
        self
    }

    /// Set TCP send buffer size (`SO_SNDBUF`).
    pub fn with_send_buf_size(mut self, size: u32) -> Self {
        self.send_buf_size = Some(size);
        self
    }

    /// Set TCP keep-alive configuration.
    pub fn with_keepalive(mut self, keepalive: TcpKeepalive) -> Self {
        self.keepalive = Some(keepalive);
        self
    }

    // -------------------------------------------------------------------
    // Presets
    // -------------------------------------------------------------------

    /// No TCP fingerprint customization (all OS defaults).
    pub fn none() -> Self {
        Self::default()
    }

    /// Chrome on Windows TCP fingerprint.
    ///
    /// ```text
    /// JA4T: 64240_2-1-3-1-1-4_1460_8
    /// TTL:  128
    /// ```
    pub fn chrome_win() -> Self {
        Self {
            window_size: Some(64240),
            tcp_options: Some(vec![
                TcpOption::MSS,
                TcpOption::NOP,
                TcpOption::WindowScale,
                TcpOption::NOP,
                TcpOption::NOP,
                TcpOption::SACKPermitted,
            ]),
            mss: Some(1460),
            window_scale: Some(8),
            ttl: Some(128),
            recv_buf_size: None,
            send_buf_size: None,
            tcp_nodelay: Some(true),
            keepalive: None,
        }
    }

    /// Chrome on Linux TCP fingerprint.
    ///
    /// ```text
    /// JA4T: 65535_2-4-8-1-3_1460_7
    /// TTL:  64
    /// ```
    pub fn chrome_linux() -> Self {
        Self {
            window_size: Some(65535),
            tcp_options: Some(vec![
                TcpOption::MSS,
                TcpOption::SACKPermitted,
                TcpOption::Timestamps,
                TcpOption::NOP,
                TcpOption::WindowScale,
            ]),
            mss: Some(1460),
            window_scale: Some(7),
            ttl: Some(64),
            recv_buf_size: None,
            send_buf_size: None,
            tcp_nodelay: Some(true),
            keepalive: None,
        }
    }

    /// Chrome on macOS TCP fingerprint.
    ///
    /// ```text
    /// JA4T: 65535_2-1-3-1-1-8-4-0_1460_6
    /// TTL:  64
    /// ```
    pub fn chrome_macos() -> Self {
        Self {
            window_size: Some(65535),
            tcp_options: Some(vec![
                TcpOption::MSS,
                TcpOption::NOP,
                TcpOption::WindowScale,
                TcpOption::NOP,
                TcpOption::NOP,
                TcpOption::Timestamps,
                TcpOption::SACKPermitted,
                TcpOption::EOL,
            ]),
            mss: Some(1460),
            window_scale: Some(6),
            ttl: Some(64),
            recv_buf_size: None,
            send_buf_size: None,
            tcp_nodelay: Some(true),
            keepalive: None,
        }
    }

    /// Chrome TCP fingerprint (auto-detect OS).
    pub fn chrome() -> Self {
        if cfg!(target_os = "windows") {
            Self::chrome_win()
        } else if cfg!(target_os = "macos") {
            Self::chrome_macos()
        } else {
            Self::chrome_linux()
        }
    }

    /// Firefox on Windows TCP fingerprint.
    ///
    /// ```text
    /// JA4T: 65535_2-1-3-1-1-4_1460_8
    /// TTL:  128
    /// ```
    pub fn firefox_win() -> Self {
        Self {
            window_size: Some(65535),
            tcp_options: Some(vec![
                TcpOption::MSS,
                TcpOption::NOP,
                TcpOption::WindowScale,
                TcpOption::NOP,
                TcpOption::NOP,
                TcpOption::SACKPermitted,
            ]),
            mss: Some(1460),
            window_scale: Some(8),
            ttl: Some(128),
            recv_buf_size: None,
            send_buf_size: None,
            tcp_nodelay: Some(true),
            keepalive: None,
        }
    }

    /// Firefox on Linux TCP fingerprint.
    ///
    /// ```text
    /// JA4T: 65535_2-4-8-1-3_1460_7
    /// TTL:  64
    /// ```
    pub fn firefox_linux() -> Self {
        Self {
            window_size: Some(65535),
            tcp_options: Some(vec![
                TcpOption::MSS,
                TcpOption::SACKPermitted,
                TcpOption::Timestamps,
                TcpOption::NOP,
                TcpOption::WindowScale,
            ]),
            mss: Some(1460),
            window_scale: Some(7),
            ttl: Some(64),
            recv_buf_size: None,
            send_buf_size: None,
            tcp_nodelay: Some(true),
            keepalive: None,
        }
    }

    /// Firefox on macOS TCP fingerprint.
    ///
    /// ```text
    /// JA4T: 65535_2-1-3-1-1-8-4-0_1460_6
    /// TTL:  64
    /// ```
    pub fn firefox_macos() -> Self {
        Self {
            window_size: Some(65535),
            tcp_options: Some(vec![
                TcpOption::MSS,
                TcpOption::NOP,
                TcpOption::WindowScale,
                TcpOption::NOP,
                TcpOption::NOP,
                TcpOption::Timestamps,
                TcpOption::SACKPermitted,
                TcpOption::EOL,
            ]),
            mss: Some(1460),
            window_scale: Some(6),
            ttl: Some(64),
            recv_buf_size: None,
            send_buf_size: None,
            tcp_nodelay: Some(true),
            keepalive: None,
        }
    }

    /// Firefox TCP fingerprint (auto-detect OS).
    pub fn firefox() -> Self {
        if cfg!(target_os = "windows") {
            Self::firefox_win()
        } else if cfg!(target_os = "macos") {
            Self::firefox_macos()
        } else {
            Self::firefox_linux()
        }
    }

    /// Safari on macOS TCP fingerprint.
    ///
    /// ```text
    /// JA4T: 65535_2-1-3-1-1-8-4-0_1460_6
    /// TTL:  64
    /// ```
    pub fn safari() -> Self {
        Self {
            window_size: Some(65535),
            tcp_options: Some(vec![
                TcpOption::MSS,
                TcpOption::NOP,
                TcpOption::WindowScale,
                TcpOption::NOP,
                TcpOption::NOP,
                TcpOption::Timestamps,
                TcpOption::SACKPermitted,
                TcpOption::EOL,
            ]),
            mss: Some(1460),
            window_scale: Some(6),
            ttl: Some(64),
            recv_buf_size: None,
            send_buf_size: None,
            tcp_nodelay: Some(true),
            keepalive: None,
        }
    }

    /// Safari on iOS TCP fingerprint.
    ///
    /// ```text
    /// JA4T: 65535_2-1-3-1-1-8-4-0_1460_6
    /// TTL:  64
    /// ```
    pub fn safari_ios() -> Self {
        Self {
            window_size: Some(65535),
            tcp_options: Some(vec![
                TcpOption::MSS,
                TcpOption::NOP,
                TcpOption::WindowScale,
                TcpOption::NOP,
                TcpOption::NOP,
                TcpOption::Timestamps,
                TcpOption::SACKPermitted,
                TcpOption::EOL,
            ]),
            mss: Some(1460),
            window_scale: Some(6),
            ttl: Some(64),
            recv_buf_size: None,
            send_buf_size: None,
            tcp_nodelay: Some(true),
            keepalive: None,
        }
    }

    // -------------------------------------------------------------------
    // Socket application
    // -------------------------------------------------------------------

    /// Compute the `SO_RCVBUF` value from `window_size` and `window_scale`.
    ///
    /// The kernel chooses `window_scale` based on the receive buffer capacity.
    /// To produce a specific `window_scale = S`, we need:
    ///
    /// ```text
    /// SO_RCVBUF >= window_size × 2^S
    /// ```
    ///
    /// On Linux, the kernel internally doubles `SO_RCVBUF` for bookkeeping
    /// overhead, so we halve the target value on Linux.
    fn compute_recv_buf(&self) -> Option<u32> {
        let ws = self.window_size?;
        let scale = self.window_scale?;

        // Target receive buffer: window_size * 2^scale
        let target = (ws as u64) << (scale as u64);

        // On Linux, kernel doubles SO_RCVBUF internally, so set half
        #[cfg(target_os = "linux")]
        let adjusted = (target / 2).min(u32::MAX as u64) as u32;

        #[cfg(not(target_os = "linux"))]
        let adjusted = target.min(u32::MAX as u64) as u32;

        Some(adjusted)
    }

    /// Apply this fingerprint to a `socket2::Socket` before connecting.
    ///
    /// Parameters are applied in the correct order for maximum SYN packet
    /// influence. Platform-specific options are guarded by `#[cfg]` and
    /// silently skipped on unsupported platforms.
    pub(crate) fn apply_to_socket(
        &self,
        socket: &socket2::Socket,
        is_ipv6: bool,
    ) -> std::io::Result<()> {
        // --- TTL / Hop Limit ---
        if let Some(ttl) = self.ttl {
            if is_ipv6 {
                socket.set_unicast_hops_v6(ttl)?;
            } else {
                socket.set_ttl_v4(ttl)?;
            }
        }

        // --- Receive buffer (Window Size + Window Scale) ---
        // Priority: recv_buf_size (raw override) > computed from window_size + window_scale
        if let Some(size) = self.recv_buf_size {
            socket.set_recv_buffer_size(size as usize)?;
        } else if let Some(computed) = self.compute_recv_buf() {
            socket.set_recv_buffer_size(computed as usize)?;
        }

        // --- Send buffer ---
        if let Some(size) = self.send_buf_size {
            socket.set_send_buffer_size(size as usize)?;
        }

        // --- TCP_NODELAY ---
        if let Some(nodelay) = self.tcp_nodelay {
            socket.set_tcp_nodelay(nodelay)?;
        }

        // --- MSS (TCP_MAXSEG) — Linux only ---
        #[cfg(target_os = "linux")]
        if let Some(mss) = self.mss {
            apply_mss_linux(socket, mss)?;
        }

        #[cfg(not(target_os = "linux"))]
        if self.mss.is_some() {
            tracing::trace!(
                mss = self.mss,
                "tcp_fingerprint: MSS stored for JA4T but not applied (Linux only)"
            );
        }

        // --- Keep-alive ---
        if let Some(ref ka) = self.keepalive {
            if ka.enabled {
                let mut keepalive = socket2::TcpKeepalive::new();
                if let Some(idle) = ka.idle {
                    keepalive = keepalive.with_time(idle);
                }
                if let Some(interval) = ka.interval {
                    keepalive = keepalive.with_interval(interval);
                }
                socket.set_tcp_keepalive(&keepalive)?;
            }
        }

        tracing::trace!(
            ja4t = ?self.to_ja4t(),
            ttl = ?self.ttl,
            "tcp_fingerprint: applied to socket"
        );

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Platform-specific: MSS on Linux
// ---------------------------------------------------------------------------

/// Apply MSS via `setsockopt(IPPROTO_TCP, TCP_MAXSEG)` on Linux.
///
/// This must be called **before** `connect()` to influence the MSS option
/// in the outgoing SYN packet.
#[cfg(target_os = "linux")]
fn apply_mss_linux(socket: &socket2::Socket, mss: u32) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let fd = socket.as_raw_fd();
    let mss_val: libc::c_int = mss as libc::c_int;

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_MAXSEG,
            &mss_val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        tracing::warn!(mss, error = %err, "tcp_fingerprint: failed to set TCP_MAXSEG");
        return Err(err);
    }

    tracing::trace!(mss, "tcp_fingerprint: TCP_MAXSEG applied");
    Ok(())
}

// ---------------------------------------------------------------------------
// connect_tcp_with_fingerprint
// ---------------------------------------------------------------------------

/// Create a connected TCP stream with optional TCP fingerprint applied.
///
/// Uses `socket2::Socket` for low-level socket configuration, then converts
/// to a `tokio::net::TcpStream` for async use.
///
/// DNS resolution is performed via the provided [`crate::dns::DnsResolver`].
pub(crate) async fn connect_tcp_with_fingerprint(
    host: &str,
    port: u16,
    fingerprint: Option<&TcpFingerprint>,
    resolver: &dyn crate::dns::DnsResolver,
) -> std::io::Result<tokio::net::TcpStream> {
    use socket2::{Domain, Protocol, Socket, Type};

    let dns_started = std::time::Instant::now();
    let resolved = resolver.resolve(host, port).await;
    crate::diagnostics::record_dns_ms(dns_started.elapsed().as_millis() as u64);
    let socket_addr = resolved?.into_iter().next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("DNS resolution returned no addresses for {host}"),
        )
    })?;

    let domain = if socket_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    // Set non-blocking before connect (required for tokio)
    socket.set_nonblocking(true)?;

    // Apply TCP fingerprint parameters BEFORE connect — this is critical
    // because TTL, window size, and MSS must be set before the SYN packet.
    let is_ipv6 = socket_addr.is_ipv6();
    if let Some(fp) = fingerprint {
        fp.apply_to_socket(&socket, is_ipv6)?;
    }

    // Initiate non-blocking connect
    let sock_addr = socket2::SockAddr::from(socket_addr);
    match socket.connect(&sock_addr) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(connect_in_progress_code()) => {
            // Connection in progress — expected for non-blocking socket
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
            // Some platforms return this for non-blocking connect-in-progress
        }
        Err(e) => return Err(e),
    }

    // Convert to tokio TcpStream and wait for connection
    let std_stream: std::net::TcpStream = socket.into();
    let stream = tokio::net::TcpStream::from_std(std_stream)?;

    // Wait for the connection to complete
    let tcp_started = std::time::Instant::now();
    stream.writable().await?;

    // Check for connection errors
    if let Some(e) = stream.take_error()? {
        return Err(e);
    }
    crate::diagnostics::record_tcp_ms(tcp_started.elapsed().as_millis() as u64);
    if let Ok(addr) = stream.peer_addr() {
        crate::diagnostics::record_remote_addr(addr.to_string());
    }

    Ok(stream)
}

/// Platform-specific "in progress" error code for non-blocking connect.
#[cfg(target_os = "windows")]
fn connect_in_progress_code() -> i32 {
    // WSAEWOULDBLOCK
    10035
}

#[cfg(not(target_os = "windows"))]
fn connect_in_progress_code() -> i32 {
    libc::EINPROGRESS
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- JA4T parsing --

    #[test]
    fn parse_ja4t_chrome_win() {
        let fp = TcpFingerprint::from_ja4t("64240_2-1-3-1-1-4_1460_8").unwrap();
        assert_eq!(fp.window_size, Some(64240));
        assert_eq!(fp.mss, Some(1460));
        assert_eq!(fp.window_scale, Some(8));
        assert_eq!(
            fp.tcp_options,
            Some(vec![
                TcpOption::MSS,
                TcpOption::NOP,
                TcpOption::WindowScale,
                TcpOption::NOP,
                TcpOption::NOP,
                TcpOption::SACKPermitted,
            ])
        );
    }

    #[test]
    fn parse_ja4t_linux() {
        let fp = TcpFingerprint::from_ja4t("65535_2-4-8-1-3_1460_7").unwrap();
        assert_eq!(fp.window_size, Some(65535));
        assert_eq!(fp.mss, Some(1460));
        assert_eq!(fp.window_scale, Some(7));
        assert_eq!(
            fp.tcp_options,
            Some(vec![
                TcpOption::MSS,
                TcpOption::SACKPermitted,
                TcpOption::Timestamps,
                TcpOption::NOP,
                TcpOption::WindowScale,
            ])
        );
    }

    #[test]
    fn parse_ja4t_macos() {
        let fp = TcpFingerprint::from_ja4t("65535_2-1-3-1-1-8-4-0_1460_6").unwrap();
        assert_eq!(fp.window_size, Some(65535));
        assert_eq!(fp.window_scale, Some(6));
        assert!(fp.tcp_options.as_ref().unwrap().contains(&TcpOption::EOL));
    }

    #[test]
    fn parse_ja4t_invalid_parts() {
        assert!(TcpFingerprint::from_ja4t("64240_2-4_1460").is_err());
        assert!(TcpFingerprint::from_ja4t("").is_err());
    }

    #[test]
    fn parse_ja4t_invalid_values() {
        assert!(TcpFingerprint::from_ja4t("abc_2-4_1460_8").is_err());
        assert!(TcpFingerprint::from_ja4t("64240_2-99_1460_8").is_err());
    }

    // -- JA4T formatting --

    #[test]
    fn format_ja4t_roundtrip() {
        let ja4t = "64240_2-1-3-1-1-4_1460_8";
        let fp = TcpFingerprint::from_ja4t(ja4t).unwrap();
        assert_eq!(fp.to_ja4t().unwrap(), ja4t);
    }

    #[test]
    fn format_ja4t_linux_roundtrip() {
        let ja4t = "65535_2-4-8-1-3_1460_7";
        let fp = TcpFingerprint::from_ja4t(ja4t).unwrap();
        assert_eq!(fp.to_ja4t().unwrap(), ja4t);
    }

    #[test]
    fn format_ja4t_none_when_missing() {
        let fp = TcpFingerprint::none();
        assert!(fp.to_ja4t().is_none());
    }

    // -- Presets --

    #[test]
    fn preset_chrome_win_ja4t() {
        let fp = TcpFingerprint::chrome_win();
        assert_eq!(fp.to_ja4t().unwrap(), "64240_2-1-3-1-1-4_1460_8");
        assert_eq!(fp.ttl, Some(128));
        assert_eq!(fp.tcp_nodelay, Some(true));
    }

    #[test]
    fn preset_chrome_linux_ja4t() {
        let fp = TcpFingerprint::chrome_linux();
        assert_eq!(fp.to_ja4t().unwrap(), "65535_2-4-8-1-3_1460_7");
        assert_eq!(fp.ttl, Some(64));
    }

    #[test]
    fn preset_chrome_macos_ja4t() {
        let fp = TcpFingerprint::chrome_macos();
        assert_eq!(fp.to_ja4t().unwrap(), "65535_2-1-3-1-1-8-4-0_1460_6");
        assert_eq!(fp.ttl, Some(64));
    }

    #[test]
    fn preset_firefox_win_ja4t() {
        let fp = TcpFingerprint::firefox_win();
        assert_eq!(fp.to_ja4t().unwrap(), "65535_2-1-3-1-1-4_1460_8");
        assert_eq!(fp.ttl, Some(128));
    }

    #[test]
    fn preset_firefox_linux_ja4t() {
        let fp = TcpFingerprint::firefox_linux();
        assert_eq!(fp.to_ja4t().unwrap(), "65535_2-4-8-1-3_1460_7");
        assert_eq!(fp.ttl, Some(64));
    }

    #[test]
    fn preset_safari_ja4t() {
        let fp = TcpFingerprint::safari();
        assert_eq!(fp.to_ja4t().unwrap(), "65535_2-1-3-1-1-8-4-0_1460_6");
        assert_eq!(fp.ttl, Some(64));
    }

    #[test]
    fn preset_none() {
        let fp = TcpFingerprint::none();
        assert!(fp.ttl.is_none());
        assert!(fp.window_size.is_none());
        assert!(fp.tcp_nodelay.is_none());
        assert!(fp.to_ja4t().is_none());
    }

    // -- Builder chain --

    #[test]
    fn builder_chain_from_ja4t() {
        let fp = TcpFingerprint::from_ja4t("64240_2-1-3-1-1-4_1460_8")
            .unwrap()
            .with_ttl(128)
            .with_tcp_nodelay(true);

        assert_eq!(fp.ttl, Some(128));
        assert_eq!(fp.tcp_nodelay, Some(true));
        assert_eq!(fp.to_ja4t().unwrap(), "64240_2-1-3-1-1-4_1460_8");
    }

    #[test]
    fn builder_chain_individual_fields() {
        let fp = TcpFingerprint::none()
            .with_window_size(64240)
            .with_window_scale(8)
            .with_mss(1460)
            .with_tcp_options(vec![
                TcpOption::MSS,
                TcpOption::NOP,
                TcpOption::WindowScale,
                TcpOption::NOP,
                TcpOption::NOP,
                TcpOption::SACKPermitted,
            ])
            .with_ttl(128);

        assert_eq!(fp.to_ja4t().unwrap(), "64240_2-1-3-1-1-4_1460_8");
    }

    // -- Recv buffer computation --

    #[test]
    fn compute_recv_buf_from_window() {
        let fp = TcpFingerprint::none()
            .with_window_size(64240)
            .with_window_scale(8);

        let computed = fp.compute_recv_buf().unwrap();

        // 64240 * 2^8 = 16,445,440
        #[cfg(target_os = "linux")]
        assert_eq!(computed, 16_445_440 / 2);

        #[cfg(not(target_os = "linux"))]
        assert_eq!(computed, 16_445_440);
    }

    #[test]
    fn compute_recv_buf_none_when_missing() {
        let fp = TcpFingerprint::none().with_window_size(64240);
        // window_scale is None, so compute_recv_buf returns None
        assert!(fp.compute_recv_buf().is_none());
    }

    // -- TcpOption --

    #[test]
    fn tcp_option_from_kind() {
        assert_eq!(TcpOption::from_kind(0), Some(TcpOption::EOL));
        assert_eq!(TcpOption::from_kind(1), Some(TcpOption::NOP));
        assert_eq!(TcpOption::from_kind(2), Some(TcpOption::MSS));
        assert_eq!(TcpOption::from_kind(3), Some(TcpOption::WindowScale));
        assert_eq!(TcpOption::from_kind(4), Some(TcpOption::SACKPermitted));
        assert_eq!(TcpOption::from_kind(8), Some(TcpOption::Timestamps));
        assert_eq!(TcpOption::from_kind(99), None);
    }

    #[test]
    fn tcp_option_kind_roundtrip() {
        for kind in [0u8, 1, 2, 3, 4, 8] {
            let opt = TcpOption::from_kind(kind).unwrap();
            assert_eq!(opt.kind(), kind);
        }
    }
}
