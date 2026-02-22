//! Group membership and proximity
//!
//! Manages groups of parties, computes group-level proximity
//! (all members within threshold), and generates group proofs.
//!
//! Author: Moroya Sakamoto

use crate::fnv1a;
use crate::vivaldi::VivaldiCoord;

/// Maximum group size (prevents O(n^2) blowup in proximity checks).
pub const MAX_GROUP_SIZE: usize = 64;

/// A member in a presence group.
#[derive(Debug, Clone, Copy)]
pub struct GroupMember {
    /// Compact party identifier.
    pub id: u32,
    /// Vivaldi coordinate.
    pub coord: VivaldiCoord,
    /// Timestamp (ns) when member joined the group.
    pub joined_ns: u64,
}

/// Group proximity proof — evidence that all members are within threshold.
#[derive(Debug, Clone)]
pub struct GroupProximityProof {
    /// Group identifier (hash of sorted member IDs).
    pub group_id: u64,
    /// Number of members in the group.
    pub member_count: usize,
    /// Maximum pairwise distance among all members.
    pub max_distance: f64,
    /// Proximity threshold used.
    pub threshold: f64,
    /// True if max_distance <= threshold (all pairs proximate).
    pub all_proximate: bool,
    /// Deterministic content hash.
    pub content_hash: u64,
}

/// Group configuration.
#[derive(Debug, Clone, Copy)]
pub struct GroupConfig {
    /// Maximum Vivaldi distance for "group proximity".
    pub proximity_threshold: f64,
    /// Minimum members for a valid group proof.
    pub min_members: usize,
}

impl Default for GroupConfig {
    fn default() -> Self {
        Self {
            proximity_threshold: 10.0,
            min_members: 2,
        }
    }
}

/// Presence group — manages members and proximity checks.
#[derive(Debug, Clone)]
pub struct PresenceGroup {
    members: Vec<GroupMember>,
    config: GroupConfig,
}

impl PresenceGroup {
    /// Create a new empty group.
    pub fn new(config: GroupConfig) -> Self {
        Self {
            members: Vec::new(),
            config,
        }
    }

    /// Add a member. Returns false if group is full or ID already present.
    pub fn add_member(&mut self, id: u32, coord: VivaldiCoord, timestamp_ns: u64) -> bool {
        if self.members.len() >= MAX_GROUP_SIZE {
            return false;
        }
        if self.members.iter().any(|m| m.id == id) {
            return false;
        }
        self.members.push(GroupMember {
            id,
            coord,
            joined_ns: timestamp_ns,
        });
        true
    }

    /// Remove a member by ID. Returns true if found and removed.
    pub fn remove_member(&mut self, id: u32) -> bool {
        let before = self.members.len();
        self.members.retain(|m| m.id != id);
        self.members.len() < before
    }

    /// Current member count.
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Check if a member with the given ID exists.
    pub fn contains(&self, id: u32) -> bool {
        self.members.iter().any(|m| m.id == id)
    }

    /// Get member IDs (sorted).
    pub fn member_ids(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self.members.iter().map(|m| m.id).collect();
        ids.sort_unstable();
        ids
    }

    /// Compute the maximum pairwise distance among all members.
    /// Returns 0.0 for 0 or 1 members.
    pub fn max_pairwise_distance(&self) -> f64 {
        let n = self.members.len();
        if n < 2 {
            return 0.0;
        }
        let mut max_d: f64 = 0.0;
        for i in 0..n {
            for j in (i + 1)..n {
                let d = self.members[i].coord.distance(&self.members[j].coord);
                // Branchless max
                let gt = (d > max_d) as u64;
                max_d = f64::from_bits(gt * d.to_bits() + (1 - gt) * max_d.to_bits());
            }
        }
        max_d
    }

    /// Check if all members are within the group proximity threshold.
    pub fn is_all_proximate(&self) -> bool {
        self.max_pairwise_distance() <= self.config.proximity_threshold
    }

    /// Generate a group proximity proof.
    /// Returns `None` if fewer than `min_members` members.
    pub fn prove_proximity(&self) -> Option<GroupProximityProof> {
        if self.members.len() < self.config.min_members {
            return None;
        }

        let max_distance = self.max_pairwise_distance();
        let all_proximate = max_distance <= self.config.proximity_threshold;
        let group_id = self.compute_group_id();

        // Content hash
        let mut buf = [0u8; 33];
        buf[..8].copy_from_slice(&group_id.to_le_bytes());
        buf[8..16].copy_from_slice(&max_distance.to_le_bytes());
        buf[16..24].copy_from_slice(&self.config.proximity_threshold.to_le_bytes());
        buf[24] = self.members.len() as u8;
        buf[25..33].copy_from_slice(&(all_proximate as u64).to_le_bytes());
        let content_hash = fnv1a(&buf);

        Some(GroupProximityProof {
            group_id,
            member_count: self.members.len(),
            max_distance,
            threshold: self.config.proximity_threshold,
            all_proximate,
            content_hash,
        })
    }

    /// Compute group ID as hash of sorted member IDs.
    fn compute_group_id(&self) -> u64 {
        let ids = self.member_ids();
        let mut buf = Vec::with_capacity(ids.len() * 4);
        for id in &ids {
            buf.extend_from_slice(&id.to_le_bytes());
        }
        fnv1a(&buf)
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_coord(x: f64, y: f64) -> VivaldiCoord {
        VivaldiCoord::new(x, y)
    }

    #[test]
    fn empty_group() {
        let g = PresenceGroup::new(GroupConfig::default());
        assert_eq!(g.member_count(), 0);
        assert!(g.prove_proximity().is_none());
    }

    #[test]
    fn add_and_remove_member() {
        let mut g = PresenceGroup::new(GroupConfig::default());
        assert!(g.add_member(1, make_coord(0.0, 0.0), 100));
        assert!(g.add_member(2, make_coord(1.0, 0.0), 200));
        assert_eq!(g.member_count(), 2);
        assert!(g.contains(1));
        assert!(g.contains(2));

        assert!(g.remove_member(1));
        assert_eq!(g.member_count(), 1);
        assert!(!g.contains(1));
    }

    #[test]
    fn duplicate_id_rejected() {
        let mut g = PresenceGroup::new(GroupConfig::default());
        assert!(g.add_member(1, make_coord(0.0, 0.0), 100));
        assert!(!g.add_member(1, make_coord(5.0, 5.0), 200));
        assert_eq!(g.member_count(), 1);
    }

    #[test]
    fn max_group_size_enforced() {
        let mut g = PresenceGroup::new(GroupConfig::default());
        for i in 0..MAX_GROUP_SIZE {
            assert!(g.add_member(i as u32, make_coord(0.0, 0.0), 0));
        }
        assert!(!g.add_member(999, make_coord(0.0, 0.0), 0));
    }

    #[test]
    fn remove_nonexistent_returns_false() {
        let mut g = PresenceGroup::new(GroupConfig::default());
        assert!(!g.remove_member(42));
    }

    #[test]
    fn member_ids_sorted() {
        let mut g = PresenceGroup::new(GroupConfig::default());
        g.add_member(5, make_coord(0.0, 0.0), 0);
        g.add_member(2, make_coord(0.0, 0.0), 0);
        g.add_member(8, make_coord(0.0, 0.0), 0);
        assert_eq!(g.member_ids(), vec![2, 5, 8]);
    }

    #[test]
    fn max_pairwise_distance_single_member() {
        let mut g = PresenceGroup::new(GroupConfig::default());
        g.add_member(1, make_coord(0.0, 0.0), 0);
        assert!((g.max_pairwise_distance() - 0.0).abs() < 1e-12);
    }

    #[test]
    fn max_pairwise_distance_two_members() {
        let mut g = PresenceGroup::new(GroupConfig::default());
        g.add_member(1, make_coord(0.0, 0.0), 0);
        g.add_member(2, make_coord(3.0, 4.0), 0);
        assert!((g.max_pairwise_distance() - 5.0).abs() < 1e-12);
    }

    #[test]
    fn max_pairwise_distance_triangle() {
        let mut g = PresenceGroup::new(GroupConfig::default());
        g.add_member(1, make_coord(0.0, 0.0), 0);
        g.add_member(2, make_coord(3.0, 0.0), 0);
        g.add_member(3, make_coord(0.0, 4.0), 0);
        // Max distance = sqrt(9+16) = 5.0 (between 2 and 3)
        assert!((g.max_pairwise_distance() - 5.0).abs() < 1e-12);
    }

    #[test]
    fn all_proximate_within_threshold() {
        let cfg = GroupConfig {
            proximity_threshold: 10.0,
            min_members: 2,
        };
        let mut g = PresenceGroup::new(cfg);
        g.add_member(1, make_coord(0.0, 0.0), 0);
        g.add_member(2, make_coord(1.0, 0.0), 0);
        g.add_member(3, make_coord(0.0, 1.0), 0);
        assert!(g.is_all_proximate());
    }

    #[test]
    fn not_all_proximate() {
        let cfg = GroupConfig {
            proximity_threshold: 3.0,
            min_members: 2,
        };
        let mut g = PresenceGroup::new(cfg);
        g.add_member(1, make_coord(0.0, 0.0), 0);
        g.add_member(2, make_coord(100.0, 0.0), 0);
        assert!(!g.is_all_proximate());
    }

    #[test]
    fn prove_proximity_success() {
        let cfg = GroupConfig {
            proximity_threshold: 10.0,
            min_members: 2,
        };
        let mut g = PresenceGroup::new(cfg);
        g.add_member(1, make_coord(0.0, 0.0), 0);
        g.add_member(2, make_coord(1.0, 0.0), 0);
        let proof = g.prove_proximity().unwrap();
        assert!(proof.all_proximate);
        assert_eq!(proof.member_count, 2);
        assert!((proof.max_distance - 1.0).abs() < 1e-12);
        assert_ne!(proof.content_hash, 0);
        assert_ne!(proof.group_id, 0);
    }

    #[test]
    fn prove_proximity_too_few() {
        let cfg = GroupConfig {
            proximity_threshold: 10.0,
            min_members: 3,
        };
        let mut g = PresenceGroup::new(cfg);
        g.add_member(1, make_coord(0.0, 0.0), 0);
        g.add_member(2, make_coord(1.0, 0.0), 0);
        assert!(g.prove_proximity().is_none());
    }

    #[test]
    fn group_id_deterministic() {
        let cfg = GroupConfig::default();
        let mut g1 = PresenceGroup::new(cfg);
        g1.add_member(1, make_coord(0.0, 0.0), 0);
        g1.add_member(2, make_coord(1.0, 0.0), 0);

        let mut g2 = PresenceGroup::new(cfg);
        // Add in different order
        g2.add_member(2, make_coord(1.0, 0.0), 0);
        g2.add_member(1, make_coord(0.0, 0.0), 0);

        let p1 = g1.prove_proximity().unwrap();
        let p2 = g2.prove_proximity().unwrap();
        assert_eq!(p1.group_id, p2.group_id);
    }

    #[test]
    fn group_id_differs_for_different_members() {
        let cfg = GroupConfig::default();
        let mut g1 = PresenceGroup::new(cfg);
        g1.add_member(1, make_coord(0.0, 0.0), 0);
        g1.add_member(2, make_coord(1.0, 0.0), 0);

        let mut g2 = PresenceGroup::new(cfg);
        g2.add_member(1, make_coord(0.0, 0.0), 0);
        g2.add_member(3, make_coord(1.0, 0.0), 0);

        let p1 = g1.prove_proximity().unwrap();
        let p2 = g2.prove_proximity().unwrap();
        assert_ne!(p1.group_id, p2.group_id);
    }
}
