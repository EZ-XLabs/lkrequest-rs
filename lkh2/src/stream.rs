//! HTTP/2 stream state machine (RFC 7540 Section 5.1).

/// HTTP/2 stream state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Idle,
    ReservedLocal,
    ReservedRemote,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

impl StreamState {
    pub fn can_send(&self) -> bool {
        matches!(self, Self::Open | Self::HalfClosedRemote)
    }

    pub fn can_receive(&self) -> bool {
        matches!(self, Self::Open | Self::HalfClosedLocal)
    }

    pub fn is_closed(&self) -> bool {
        matches!(self, Self::Closed)
    }

    pub fn is_active(&self) -> bool {
        !matches!(self, Self::Idle | Self::Closed)
    }
}

impl std::fmt::Display for StreamState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::ReservedLocal => write!(f, "reserved (local)"),
            Self::ReservedRemote => write!(f, "reserved (remote)"),
            Self::Open => write!(f, "open"),
            Self::HalfClosedLocal => write!(f, "half-closed (local)"),
            Self::HalfClosedRemote => write!(f, "half-closed (remote)"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

// ─── Stream ──────────────────────────────────────────────────────────────────

/// HTTP/2 stream with flow-control state.
#[derive(Debug)]
pub struct H2Stream {
    pub id: u32,
    state: StreamState,
    send_window: i32,
    recv_window: i32,
    initial_window_size: u32,
}

const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65535;

impl H2Stream {
    pub fn new(id: u32, initial_window_size: u32) -> Self {
        Self {
            id,
            state: StreamState::Idle,
            send_window: initial_window_size as i32,
            recv_window: initial_window_size as i32,
            initial_window_size,
        }
    }

    pub fn new_with_windows(id: u32, send_initial_window: u32, recv_initial_window: u32) -> Self {
        Self {
            id,
            state: StreamState::Idle,
            send_window: send_initial_window as i32,
            recv_window: recv_initial_window as i32,
            initial_window_size: send_initial_window,
        }
    }

    pub fn with_default_window(id: u32) -> Self {
        Self::new(id, DEFAULT_INITIAL_WINDOW_SIZE)
    }

    pub fn state(&self) -> StreamState {
        self.state
    }

    pub fn send_window(&self) -> i32 {
        self.send_window
    }

    pub fn send_window_available(&self) -> u32 {
        self.send_window.max(0) as u32
    }

    pub fn recv_window(&self) -> i32 {
        self.recv_window
    }

    pub fn initial_window_size(&self) -> u32 {
        self.initial_window_size
    }

    pub fn open(&mut self) -> Result<(), StreamError> {
        match self.state {
            StreamState::Idle | StreamState::ReservedLocal | StreamState::ReservedRemote => {
                self.state = StreamState::Open;
                Ok(())
            }
            _ => Err(StreamError::InvalidTransition {
                from: self.state,
                event: "open",
            }),
        }
    }

    pub fn send_end_stream(&mut self) -> Result<(), StreamError> {
        match self.state {
            StreamState::Open => {
                self.state = StreamState::HalfClosedLocal;
                Ok(())
            }
            StreamState::HalfClosedRemote => {
                self.state = StreamState::Closed;
                Ok(())
            }
            _ => Err(StreamError::InvalidTransition {
                from: self.state,
                event: "send_end_stream",
            }),
        }
    }

    pub fn recv_end_stream(&mut self) -> Result<(), StreamError> {
        match self.state {
            StreamState::Open => {
                self.state = StreamState::HalfClosedRemote;
                Ok(())
            }
            StreamState::HalfClosedLocal => {
                self.state = StreamState::Closed;
                Ok(())
            }
            _ => Err(StreamError::InvalidTransition {
                from: self.state,
                event: "recv_end_stream",
            }),
        }
    }

    pub fn reset(&mut self) {
        self.state = StreamState::Closed;
    }

    pub fn consume_send_window(&mut self, amount: u32) -> u32 {
        let available = self.send_window.max(0) as u32;
        let consumed = amount.min(available);
        self.send_window -= consumed as i32;
        consumed
    }

    pub fn consume_recv_window(&mut self, amount: u32) -> Result<(), StreamError> {
        if self.recv_window < 0 || (self.recv_window as u32) < amount {
            return Err(StreamError::FlowControlError {
                window: self.recv_window,
                requested: amount,
            });
        }
        self.recv_window -= amount as i32;
        Ok(())
    }

    pub fn update_send_window(&mut self, increment: u32) -> Result<(), StreamError> {
        let new_window = self.send_window as i64 + increment as i64;
        if new_window > i32::MAX as i64 {
            return Err(StreamError::WindowOverflow);
        }
        self.send_window = new_window as i32;
        Ok(())
    }

    pub fn update_recv_window(&mut self, increment: u32) -> Result<(), StreamError> {
        let new_window = self.recv_window as i64 + increment as i64;
        if new_window > i32::MAX as i64 {
            return Err(StreamError::WindowOverflow);
        }
        self.recv_window = new_window as i32;
        Ok(())
    }

    pub fn apply_initial_window_size(&mut self, new_size: u32) -> Result<(), StreamError> {
        let delta = new_size as i64 - self.initial_window_size as i64;
        let new_window = self.send_window as i64 + delta;
        if new_window > i32::MAX as i64 {
            return Err(StreamError::WindowOverflow);
        }
        self.send_window = new_window as i32;
        self.initial_window_size = new_size;
        Ok(())
    }
}

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum StreamError {
    InvalidTransition {
        from: StreamState,
        event: &'static str,
    },
    FlowControlError {
        window: i32,
        requested: u32,
    },
    WindowOverflow,
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTransition { from, event } => {
                write!(f, "invalid transition from {from} on event {event}")
            }
            Self::FlowControlError { window, requested } => {
                write!(
                    f,
                    "flow control error: window={window}, requested={requested}"
                )
            }
            Self::WindowOverflow => write!(f, "window size overflow"),
        }
    }
}

impl std::error::Error for StreamError {}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_lifecycle() {
        let mut stream = H2Stream::with_default_window(1);
        assert_eq!(stream.state(), StreamState::Idle);

        stream.open().unwrap();
        assert_eq!(stream.state(), StreamState::Open);

        stream.send_end_stream().unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);

        stream.recv_end_stream().unwrap();
        assert_eq!(stream.state(), StreamState::Closed);
    }

    #[test]
    fn test_flow_control() {
        let mut stream = H2Stream::new(1, 1000);
        assert_eq!(stream.send_window(), 1000);

        let consumed = stream.consume_send_window(300);
        assert_eq!(consumed, 300);
        assert_eq!(stream.send_window(), 700);

        let consumed = stream.consume_send_window(1000);
        assert_eq!(consumed, 700);
        assert_eq!(stream.send_window(), 0);

        stream.update_send_window(500).unwrap();
        assert_eq!(stream.send_window(), 500);
    }

    #[test]
    fn test_window_overflow() {
        let mut stream = H2Stream::new(1, i32::MAX as u32);
        assert!(stream.update_send_window(1).is_err());
    }

    #[test]
    fn test_invalid_transition() {
        let mut stream = H2Stream::with_default_window(1);
        assert!(stream.send_end_stream().is_err());
    }
}
