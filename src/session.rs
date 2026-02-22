//! Session finite state machine
//!
//! Models the lifecycle of a presence exchange session through
//! five states: Idle → Discovering → Exchanging → Verified → Closed.
//! Enforces valid transitions and tracks timeout.
//!
//! Author: Moroya Sakamoto

use crate::fnv1a;

/// Session state in the presence protocol FSM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionState {
    /// No active session; waiting for discovery.
    Idle = 0,
    /// Peer discovered; proximity check in progress.
    Discovering = 1,
    /// ZKP identity exchange in progress.
    Exchanging = 2,
    /// Both parties verified; crossing recorded.
    Verified = 3,
    /// Session closed (success or timeout/cancel).
    Closed = 4,
}

/// Reason a session was closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// Successfully completed (reached Verified, then closed).
    Success,
    /// Timed out waiting for the next step.
    Timeout,
    /// Cancelled by one party.
    Cancelled,
    /// Proximity check failed.
    ProximityFailed,
    /// ZKP verification failed.
    VerificationFailed,
}

/// Session configuration.
#[derive(Debug, Clone, Copy)]
pub struct SessionConfig {
    /// Maximum time (ns) to stay in Discovering before timeout.
    pub discovery_timeout_ns: u64,
    /// Maximum time (ns) to stay in Exchanging before timeout.
    pub exchange_timeout_ns: u64,
    /// Maximum number of retry attempts per phase.
    pub max_retries: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            discovery_timeout_ns: 5_000_000_000, // 5 seconds
            exchange_timeout_ns: 10_000_000_000, // 10 seconds
            max_retries: 3,
        }
    }
}

/// A presence session tracking the FSM state, timestamps, and retries.
#[derive(Debug, Clone)]
pub struct Session {
    /// Unique session identifier.
    pub session_id: u64,
    /// Current FSM state.
    pub state: SessionState,
    /// Local party ID.
    pub local_id: u32,
    /// Remote party ID (set after discovery).
    pub remote_id: Option<u32>,
    /// Timestamp (ns) when session entered current state.
    pub state_entered_ns: u64,
    /// Timestamp (ns) when session was created.
    pub created_ns: u64,
    /// Number of retries used in current phase.
    pub retries: u32,
    /// Close reason (set when state == Closed).
    pub close_reason: Option<CloseReason>,
    /// Configuration for this session.
    pub config: SessionConfig,
    /// Content hash of session state for integrity.
    pub content_hash: u64,
}

impl Session {
    /// Create a new session in Idle state.
    pub fn new(local_id: u32, timestamp_ns: u64, config: SessionConfig) -> Self {
        let mut buf = [0u8; 12];
        buf[..4].copy_from_slice(&local_id.to_le_bytes());
        buf[4..12].copy_from_slice(&timestamp_ns.to_le_bytes());
        let session_id = fnv1a(&buf);

        let mut s = Self {
            session_id,
            state: SessionState::Idle,
            local_id,
            remote_id: None,
            state_entered_ns: timestamp_ns,
            created_ns: timestamp_ns,
            retries: 0,
            close_reason: None,
            config,
            content_hash: 0,
        };
        s.update_hash();
        s
    }

    /// Transition: Idle → Discovering (peer found).
    pub fn discover(&mut self, remote_id: u32, timestamp_ns: u64) -> bool {
        if self.state != SessionState::Idle {
            return false;
        }
        self.remote_id = Some(remote_id);
        self.state = SessionState::Discovering;
        self.state_entered_ns = timestamp_ns;
        self.retries = 0;
        self.update_hash();
        true
    }

    /// Transition: Discovering → Exchanging (proximity OK).
    pub fn begin_exchange(&mut self, timestamp_ns: u64) -> bool {
        if self.state != SessionState::Discovering {
            return false;
        }
        self.state = SessionState::Exchanging;
        self.state_entered_ns = timestamp_ns;
        self.retries = 0;
        self.update_hash();
        true
    }

    /// Transition: Exchanging → Verified (ZKP OK).
    pub fn verify(&mut self, timestamp_ns: u64) -> bool {
        if self.state != SessionState::Exchanging {
            return false;
        }
        self.state = SessionState::Verified;
        self.state_entered_ns = timestamp_ns;
        self.update_hash();
        true
    }

    /// Transition: any → Closed.
    pub fn close(&mut self, reason: CloseReason, timestamp_ns: u64) -> bool {
        if self.state == SessionState::Closed {
            return false;
        }
        self.state = SessionState::Closed;
        self.state_entered_ns = timestamp_ns;
        self.close_reason = Some(reason);
        self.update_hash();
        true
    }

    /// Check if the current phase has timed out.
    pub fn is_timed_out(&self, current_ns: u64) -> bool {
        if self.state == SessionState::Idle || self.state == SessionState::Closed {
            return false;
        }
        let elapsed = current_ns.saturating_sub(self.state_entered_ns);
        match self.state {
            SessionState::Discovering => elapsed > self.config.discovery_timeout_ns,
            SessionState::Exchanging => elapsed > self.config.exchange_timeout_ns,
            _ => false,
        }
    }

    /// Increment retry counter. Returns false if max retries exceeded.
    pub fn retry(&mut self) -> bool {
        if self.retries >= self.config.max_retries {
            return false;
        }
        self.retries += 1;
        self.update_hash();
        true
    }

    /// Duration (ns) spent in the current state.
    pub fn state_duration_ns(&self, current_ns: u64) -> u64 {
        current_ns.saturating_sub(self.state_entered_ns)
    }

    /// Total session duration (ns) from creation.
    pub fn total_duration_ns(&self, current_ns: u64) -> u64 {
        current_ns.saturating_sub(self.created_ns)
    }

    /// Is this session still active (not Closed)?
    pub fn is_active(&self) -> bool {
        self.state != SessionState::Closed
    }

    fn update_hash(&mut self) {
        let mut buf = [0u8; 25];
        buf[..8].copy_from_slice(&self.session_id.to_le_bytes());
        buf[8] = self.state as u8;
        buf[9..13].copy_from_slice(&self.local_id.to_le_bytes());
        buf[13..21].copy_from_slice(&self.state_entered_ns.to_le_bytes());
        buf[21..25].copy_from_slice(&self.retries.to_le_bytes());
        self.content_hash = fnv1a(&buf);
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_is_idle() {
        let s = Session::new(1, 1000, SessionConfig::default());
        assert_eq!(s.state, SessionState::Idle);
        assert!(s.is_active());
        assert!(s.close_reason.is_none());
        assert_ne!(s.session_id, 0);
    }

    #[test]
    fn full_happy_path() {
        let mut s = Session::new(1, 1000, SessionConfig::default());
        assert!(s.discover(2, 2000));
        assert_eq!(s.state, SessionState::Discovering);
        assert_eq!(s.remote_id, Some(2));

        assert!(s.begin_exchange(3000));
        assert_eq!(s.state, SessionState::Exchanging);

        assert!(s.verify(4000));
        assert_eq!(s.state, SessionState::Verified);

        assert!(s.close(CloseReason::Success, 5000));
        assert_eq!(s.state, SessionState::Closed);
        assert_eq!(s.close_reason, Some(CloseReason::Success));
        assert!(!s.is_active());
    }

    #[test]
    fn invalid_transition_discover_from_exchanging() {
        let mut s = Session::new(1, 1000, SessionConfig::default());
        s.discover(2, 2000);
        s.begin_exchange(3000);
        assert!(!s.discover(3, 4000)); // can't discover while exchanging
    }

    #[test]
    fn invalid_transition_verify_from_idle() {
        let mut s = Session::new(1, 1000, SessionConfig::default());
        assert!(!s.verify(2000)); // can't verify from idle
    }

    #[test]
    fn invalid_transition_exchange_from_idle() {
        let mut s = Session::new(1, 1000, SessionConfig::default());
        assert!(!s.begin_exchange(2000));
    }

    #[test]
    fn double_close_rejected() {
        let mut s = Session::new(1, 1000, SessionConfig::default());
        assert!(s.close(CloseReason::Cancelled, 2000));
        assert!(!s.close(CloseReason::Success, 3000));
        assert_eq!(s.close_reason, Some(CloseReason::Cancelled));
    }

    #[test]
    fn timeout_discovering() {
        let cfg = SessionConfig {
            discovery_timeout_ns: 1000,
            ..Default::default()
        };
        let mut s = Session::new(1, 0, cfg);
        s.discover(2, 100);
        assert!(!s.is_timed_out(500));
        assert!(s.is_timed_out(1200));
    }

    #[test]
    fn timeout_exchanging() {
        let cfg = SessionConfig {
            exchange_timeout_ns: 2000,
            ..Default::default()
        };
        let mut s = Session::new(1, 0, cfg);
        s.discover(2, 100);
        s.begin_exchange(200);
        assert!(!s.is_timed_out(1000));
        assert!(s.is_timed_out(2300));
    }

    #[test]
    fn no_timeout_when_idle_or_closed() {
        let s = Session::new(1, 0, SessionConfig::default());
        assert!(!s.is_timed_out(999_999_999_999));

        let mut s2 = Session::new(1, 0, SessionConfig::default());
        s2.close(CloseReason::Cancelled, 100);
        assert!(!s2.is_timed_out(999_999_999_999));
    }

    #[test]
    fn retry_limit() {
        let cfg = SessionConfig {
            max_retries: 2,
            ..Default::default()
        };
        let mut s = Session::new(1, 0, cfg);
        assert!(s.retry()); // 1
        assert!(s.retry()); // 2
        assert!(!s.retry()); // exceeded
    }

    #[test]
    fn duration_tracking() {
        let s = Session::new(1, 1000, SessionConfig::default());
        assert_eq!(s.state_duration_ns(3000), 2000);
        assert_eq!(s.total_duration_ns(5000), 4000);
    }

    #[test]
    fn content_hash_changes_on_transition() {
        let mut s = Session::new(1, 1000, SessionConfig::default());
        let h1 = s.content_hash;
        s.discover(2, 2000);
        let h2 = s.content_hash;
        assert_ne!(h1, h2);
        s.begin_exchange(3000);
        let h3 = s.content_hash;
        assert_ne!(h2, h3);
    }

    #[test]
    fn content_hash_determinism() {
        let s1 = Session::new(1, 1000, SessionConfig::default());
        let s2 = Session::new(1, 1000, SessionConfig::default());
        assert_eq!(s1.content_hash, s2.content_hash);
        assert_eq!(s1.session_id, s2.session_id);
    }

    #[test]
    fn close_from_any_active_state() {
        // From Discovering
        let mut s1 = Session::new(1, 0, SessionConfig::default());
        s1.discover(2, 100);
        assert!(s1.close(CloseReason::ProximityFailed, 200));

        // From Exchanging
        let mut s2 = Session::new(1, 0, SessionConfig::default());
        s2.discover(2, 100);
        s2.begin_exchange(200);
        assert!(s2.close(CloseReason::VerificationFailed, 300));

        // From Verified
        let mut s3 = Session::new(1, 0, SessionConfig::default());
        s3.discover(2, 100);
        s3.begin_exchange(200);
        s3.verify(300);
        assert!(s3.close(CloseReason::Success, 400));
    }
}
