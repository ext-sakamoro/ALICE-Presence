//! リプレイ防止ガード — タイムスタンプ検証とnonce追跡。
//!
//! crossing record のリプレイ攻撃を防止するため、
//! タイムスタンプの有効期間チェックとnonce重複検出を行う。

use crate::fnv1a;

/// リプレイガード設定。
#[derive(Debug, Clone, Copy)]
pub struct ReplayGuardConfig {
    /// タイムスタンプ有効ウィンドウ (ナノ秒)。デフォルト: 5分。
    pub window_ns: u64,
    /// nonce履歴の最大保持数。デフォルト: 1024。
    pub max_nonces: usize,
}

impl Default for ReplayGuardConfig {
    fn default() -> Self {
        Self {
            window_ns: 5 * 60 * 1_000_000_000, // 5分
            max_nonces: 1024,
        }
    }
}

/// リプレイガード — タイムスタンプとnonce による二重防御。
#[derive(Debug)]
pub struct ReplayGuard {
    /// 設定。
    config: ReplayGuardConfig,
    /// 使用済みnonce のハッシュ履歴。
    seen_nonces: Vec<u64>,
}

/// タイムスタンプ検証結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampResult {
    /// 有効期間内。
    Valid,
    /// 未来すぎる。
    TooFarFuture,
    /// 古すぎる。
    Expired,
}

/// リプレイ検証結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayResult {
    /// 新規（リプレイではない）。
    Fresh,
    /// 重複 nonce（リプレイ疑い）。
    Duplicate,
    /// タイムスタンプ範囲外。
    TimestampInvalid(TimestampResult),
}

impl ReplayGuard {
    /// 指定設定でガードを作成。
    #[must_use]
    pub fn new(config: ReplayGuardConfig) -> Self {
        Self {
            seen_nonces: Vec::with_capacity(config.max_nonces.min(4096)),
            config,
        }
    }

    /// デフォルト設定でガードを作成。
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(ReplayGuardConfig::default())
    }

    /// タイムスタンプが現在時刻 `now_ns` に対して有効か検証。
    #[must_use]
    pub const fn check_timestamp(&self, event_ns: u64, now_ns: u64) -> TimestampResult {
        if event_ns > now_ns + self.config.window_ns {
            return TimestampResult::TooFarFuture;
        }
        if now_ns > event_ns + self.config.window_ns {
            return TimestampResult::Expired;
        }
        TimestampResult::Valid
    }

    /// イベントデータから nonce ハッシュを生成。
    #[must_use]
    pub fn compute_nonce(event_bytes: &[u8]) -> u64 {
        fnv1a(event_bytes)
    }

    /// nonce が未使用か検証し、使用済みとして記録。
    ///
    /// 容量超過時は最古の nonce を破棄。
    pub fn check_and_record_nonce(&mut self, nonce: u64) -> bool {
        if self.seen_nonces.contains(&nonce) {
            return false; // 重複
        }
        if self.seen_nonces.len() >= self.config.max_nonces {
            self.seen_nonces.remove(0);
        }
        self.seen_nonces.push(nonce);
        true
    }

    /// タイムスタンプ + nonce の総合検証。
    pub fn validate(
        &mut self,
        event_bytes: &[u8],
        event_ns: u64,
        now_ns: u64,
    ) -> ReplayResult {
        let ts = self.check_timestamp(event_ns, now_ns);
        if ts != TimestampResult::Valid {
            return ReplayResult::TimestampInvalid(ts);
        }
        let nonce = Self::compute_nonce(event_bytes);
        if self.check_and_record_nonce(nonce) {
            ReplayResult::Fresh
        } else {
            ReplayResult::Duplicate
        }
    }

    /// 記録済み nonce 数。
    #[must_use]
    pub const fn nonce_count(&self) -> usize {
        self.seen_nonces.len()
    }

    /// 全 nonce 履歴をクリア。
    pub fn clear(&mut self) {
        self.seen_nonces.clear();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000_000_000; // 1000秒

    #[test]
    fn default_config() {
        let cfg = ReplayGuardConfig::default();
        assert_eq!(cfg.window_ns, 5 * 60 * 1_000_000_000);
        assert_eq!(cfg.max_nonces, 1024);
    }

    #[test]
    fn timestamp_valid() {
        let guard = ReplayGuard::with_defaults();
        let result = guard.check_timestamp(NOW, NOW);
        assert_eq!(result, TimestampResult::Valid);
    }

    #[test]
    fn timestamp_slightly_past() {
        let guard = ReplayGuard::with_defaults();
        // 1分前 → 有効
        let result = guard.check_timestamp(NOW - 60_000_000_000, NOW);
        assert_eq!(result, TimestampResult::Valid);
    }

    #[test]
    fn timestamp_expired() {
        let guard = ReplayGuard::with_defaults();
        // 10分前 → 期限切れ
        let result = guard.check_timestamp(NOW - 10 * 60 * 1_000_000_000, NOW);
        assert_eq!(result, TimestampResult::Expired);
    }

    #[test]
    fn timestamp_future() {
        let guard = ReplayGuard::with_defaults();
        // 10分後 → 未来すぎ
        let result = guard.check_timestamp(NOW + 10 * 60 * 1_000_000_000, NOW);
        assert_eq!(result, TimestampResult::TooFarFuture);
    }

    #[test]
    fn nonce_fresh() {
        let mut guard = ReplayGuard::with_defaults();
        assert!(guard.check_and_record_nonce(12345));
        assert_eq!(guard.nonce_count(), 1);
    }

    #[test]
    fn nonce_duplicate() {
        let mut guard = ReplayGuard::with_defaults();
        assert!(guard.check_and_record_nonce(12345));
        assert!(!guard.check_and_record_nonce(12345)); // 重複
    }

    #[test]
    fn nonce_eviction() {
        let config = ReplayGuardConfig {
            window_ns: u64::MAX,
            max_nonces: 3,
        };
        let mut guard = ReplayGuard::new(config);
        assert!(guard.check_and_record_nonce(1));
        assert!(guard.check_and_record_nonce(2));
        assert!(guard.check_and_record_nonce(3));
        // 容量超過 → nonce 1 が破棄される
        assert!(guard.check_and_record_nonce(4));
        assert_eq!(guard.nonce_count(), 3);
        // nonce 1 は再利用可能に
        assert!(guard.check_and_record_nonce(1));
    }

    #[test]
    fn validate_fresh() {
        let mut guard = ReplayGuard::with_defaults();
        let result = guard.validate(b"event_data_1", NOW, NOW);
        assert_eq!(result, ReplayResult::Fresh);
    }

    #[test]
    fn validate_duplicate() {
        let mut guard = ReplayGuard::with_defaults();
        guard.validate(b"event_data_1", NOW, NOW);
        let result = guard.validate(b"event_data_1", NOW, NOW);
        assert_eq!(result, ReplayResult::Duplicate);
    }

    #[test]
    fn validate_expired() {
        let mut guard = ReplayGuard::with_defaults();
        let old = NOW - 10 * 60 * 1_000_000_000;
        let result = guard.validate(b"event_data", old, NOW);
        assert_eq!(
            result,
            ReplayResult::TimestampInvalid(TimestampResult::Expired)
        );
    }

    #[test]
    fn clear_nonces() {
        let mut guard = ReplayGuard::with_defaults();
        guard.check_and_record_nonce(1);
        guard.check_and_record_nonce(2);
        guard.clear();
        assert_eq!(guard.nonce_count(), 0);
        // クリア後は同じ nonce が再利用可能
        assert!(guard.check_and_record_nonce(1));
    }

    #[test]
    fn compute_nonce_deterministic() {
        let n1 = ReplayGuard::compute_nonce(b"test");
        let n2 = ReplayGuard::compute_nonce(b"test");
        assert_eq!(n1, n2);
    }

    #[test]
    fn compute_nonce_different_data() {
        let n1 = ReplayGuard::compute_nonce(b"aaa");
        let n2 = ReplayGuard::compute_nonce(b"bbb");
        assert_ne!(n1, n2);
    }
}
