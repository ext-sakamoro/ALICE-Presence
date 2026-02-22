//! Vivaldi network coordinates
//!
//! 2D coordinates with height term for network distance estimation.
//! Distance model: sqrt((x1-x2)^2 + (y1-y2)^2) + h1 + h2
//!
//! Author: Moroya Sakamoto

use crate::fnv1a;

/// Vivaldi network coordinate (2D + height for error estimation).
///
/// Distance model: sqrt((x1-x2)^2 + (y1-y2)^2) + h1 + h2
/// The height term is always >= 0 and represents estimation error.
#[derive(Debug, Clone, Copy)]
pub struct VivaldiCoord {
    pub x: f64,
    pub y: f64,
    /// Error term (always >= 0).
    pub height: f64,
}

impl VivaldiCoord {
    /// Create a coordinate with height = 0.
    pub fn new(x: f64, y: f64) -> Self {
        Self { x, y, height: 0.0 }
    }

    /// Create a coordinate with an explicit height (error) term.
    pub fn with_height(x: f64, y: f64, height: f64) -> Self {
        Self {
            x,
            y,
            height: if height < 0.0 { 0.0 } else { height },
        }
    }

    /// Vivaldi distance: sqrt((x1-x2)^2 + (y1-y2)^2) + h1 + h2
    pub fn distance(&self, other: &VivaldiCoord) -> f64 {
        let dx = self.x - other.x;
        let dy = self.y - other.y;
        (dx * dx + dy * dy).sqrt() + self.height + other.height
    }

    /// Hash the coordinate for privacy-preserving proofs.
    pub fn hash(&self) -> u64 {
        let mut buf = [0u8; 24];
        buf[..8].copy_from_slice(&self.x.to_le_bytes());
        buf[8..16].copy_from_slice(&self.y.to_le_bytes());
        buf[16..24].copy_from_slice(&self.height.to_le_bytes());
        fnv1a(&buf)
    }

    /// Update coordinate toward measured RTT using Vivaldi spring model.
    ///
    /// `rtt` is the measured round-trip time (distance), `cc` is the
    /// adaptive timestep (typically 0.01..0.25).
    pub fn update(&mut self, other: &VivaldiCoord, rtt: f64, cc: f64) {
        let predicted = self.distance(other);
        let error = rtt - predicted;
        if predicted < 1e-15 {
            // Avoid division by zero; nudge randomly via hash
            self.x += cc * error * 0.5;
            self.y += cc * error * 0.5;
        } else {
            let dx = self.x - other.x;
            let dy = self.y - other.y;
            let euclidean = (dx * dx + dy * dy).sqrt();
            if euclidean < 1e-15 {
                self.x += cc * error * 0.5;
                self.y += cc * error * 0.5;
            } else {
                let scale = cc * error / euclidean;
                self.x += scale * dx;
                self.y += scale * dy;
            }
        }
        // Update height: move toward zero but absorb residual error
        self.height += cc * (error - self.height);
        if self.height < 0.0 {
            self.height = 0.0;
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_point_zero_height() {
        let a = VivaldiCoord::new(3.0, 4.0);
        let b = VivaldiCoord::new(3.0, 4.0);
        assert!((a.distance(&b) - 0.0).abs() < 1e-12);
    }

    #[test]
    fn same_point_with_heights() {
        let a = VivaldiCoord::with_height(0.0, 0.0, 1.5);
        let b = VivaldiCoord::with_height(0.0, 0.0, 2.5);
        assert!((a.distance(&b) - 4.0).abs() < 1e-12);
    }

    #[test]
    fn known_distance() {
        let a = VivaldiCoord::new(0.0, 0.0);
        let b = VivaldiCoord::new(3.0, 4.0);
        assert!((a.distance(&b) - 5.0).abs() < 1e-12);
    }

    #[test]
    fn distance_with_height() {
        let a = VivaldiCoord::with_height(0.0, 0.0, 1.0);
        let b = VivaldiCoord::with_height(3.0, 4.0, 2.0);
        assert!((a.distance(&b) - 8.0).abs() < 1e-12);
    }

    #[test]
    fn distance_symmetry() {
        let a = VivaldiCoord::with_height(1.0, 2.0, 0.5);
        let b = VivaldiCoord::with_height(4.0, 6.0, 1.0);
        assert!((a.distance(&b) - b.distance(&a)).abs() < 1e-12);
    }

    #[test]
    fn hash_determinism() {
        let c = VivaldiCoord::with_height(1.23, 4.56, 0.78);
        assert_eq!(c.hash(), c.hash());
    }

    #[test]
    fn hash_differs_for_different_coords() {
        let a = VivaldiCoord::new(1.0, 2.0);
        let b = VivaldiCoord::new(2.0, 1.0);
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn negative_height_clamped() {
        let c = VivaldiCoord::with_height(0.0, 0.0, -5.0);
        assert_eq!(c.height, 0.0);
    }

    #[test]
    fn zero_coord() {
        let a = VivaldiCoord::new(0.0, 0.0);
        let b = VivaldiCoord::new(0.0, 0.0);
        assert!((a.distance(&b)).abs() < 1e-12);
    }

    #[test]
    fn update_moves_toward_rtt() {
        let mut a = VivaldiCoord::new(0.0, 0.0);
        let b = VivaldiCoord::new(10.0, 0.0);
        // True distance = 10.0, RTT measured = 20.0 → a should move away from b
        let dist_before = a.distance(&b);
        a.update(&b, 20.0, 0.1);
        let dist_after = a.distance(&b);
        // After update, predicted distance should be closer to 20.0
        assert!((dist_after - 20.0).abs() < (dist_before - 20.0).abs());
    }

    #[test]
    fn update_converges() {
        let mut a = VivaldiCoord::new(0.0, 0.0);
        let b = VivaldiCoord::new(5.0, 0.0);
        let target_rtt = 8.0;
        for _ in 0..200 {
            a.update(&b, target_rtt, 0.05);
        }
        let final_dist = a.distance(&b);
        assert!((final_dist - target_rtt).abs() < 1.0);
    }

    #[test]
    fn update_same_point() {
        let mut a = VivaldiCoord::new(0.0, 0.0);
        let b = VivaldiCoord::new(0.0, 0.0);
        // Should not panic even when both at origin
        a.update(&b, 5.0, 0.1);
        assert!(a.x.is_finite());
        assert!(a.y.is_finite());
    }
}
