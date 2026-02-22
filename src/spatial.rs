//! k-d tree spatial index for proximity queries
//!
//! 2D k-d tree over Vivaldi coordinates for O(log N) nearest-neighbor
//! and range queries. Used for efficient batch proximity checks.
//!
//! Author: Moroya Sakamoto

use crate::vivaldi::VivaldiCoord;

/// An entry in the spatial index: party ID + coordinate.
#[derive(Debug, Clone, Copy)]
pub struct SpatialEntry {
    pub id: u32,
    pub coord: VivaldiCoord,
}

/// k-d tree node (stored in a flat Vec for cache-friendly traversal).
#[derive(Debug, Clone)]
struct KdNode {
    entry: SpatialEntry,
    /// 0 = split on x, 1 = split on y
    split_axis: u8,
    left: Option<usize>,
    right: Option<usize>,
}

/// 2D k-d tree over Vivaldi coordinates.
#[derive(Debug, Clone)]
pub struct KdTree {
    nodes: Vec<KdNode>,
    root: Option<usize>,
}

impl KdTree {
    /// Build a k-d tree from a list of entries.
    /// O(N log N) construction.
    pub fn build(entries: &[SpatialEntry]) -> Self {
        if entries.is_empty() {
            return Self {
                nodes: Vec::new(),
                root: None,
            };
        }

        let mut sorted: Vec<SpatialEntry> = entries.to_vec();
        let mut nodes = Vec::with_capacity(entries.len());
        let root = Self::build_recursive(&mut sorted, 0, entries.len(), 0, &mut nodes);

        Self {
            nodes,
            root: Some(root),
        }
    }

    fn build_recursive(
        entries: &mut [SpatialEntry],
        start: usize,
        end: usize,
        depth: usize,
        nodes: &mut Vec<KdNode>,
    ) -> usize {
        let len = end - start;
        let axis = (depth % 2) as u8;

        // Sort by current axis
        let slice = &mut entries[start..end];
        if axis == 0 {
            slice.sort_unstable_by(|a, b| a.coord.x.partial_cmp(&b.coord.x).unwrap());
        } else {
            slice.sort_unstable_by(|a, b| a.coord.y.partial_cmp(&b.coord.y).unwrap());
        }

        let mid = start + len / 2;
        let entry = entries[mid];

        let node_idx = nodes.len();
        nodes.push(KdNode {
            entry,
            split_axis: axis,
            left: None,
            right: None,
        });

        if mid > start {
            let left_idx = Self::build_recursive(entries, start, mid, depth + 1, nodes);
            nodes[node_idx].left = Some(left_idx);
        }

        if mid + 1 < end {
            let right_idx = Self::build_recursive(entries, mid + 1, end, depth + 1, nodes);
            nodes[node_idx].right = Some(right_idx);
        }

        node_idx
    }

    /// Number of entries in the tree.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Is the tree empty?
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Find the nearest neighbor to a query point.
    /// Returns `(id, distance)` or `None` if tree is empty.
    pub fn nearest(&self, query: &VivaldiCoord) -> Option<(u32, f64)> {
        let root = self.root?;
        let mut best_id = self.nodes[root].entry.id;
        let mut best_dist = self.vivaldi_dist(query, &self.nodes[root].entry.coord);
        self.nearest_recursive(root, query, &mut best_id, &mut best_dist);
        Some((best_id, best_dist))
    }

    fn nearest_recursive(
        &self,
        node_idx: usize,
        query: &VivaldiCoord,
        best_id: &mut u32,
        best_dist: &mut f64,
    ) {
        let node = &self.nodes[node_idx];
        let d = self.vivaldi_dist(query, &node.entry.coord);
        if d < *best_dist {
            *best_dist = d;
            *best_id = node.entry.id;
        }

        // Determine which side of the split plane the query falls on
        let (query_val, split_val) = if node.split_axis == 0 {
            (query.x, node.entry.coord.x)
        } else {
            (query.y, node.entry.coord.y)
        };

        let diff = query_val - split_val;
        let (first, second) = if diff < 0.0 {
            (node.left, node.right)
        } else {
            (node.right, node.left)
        };

        // Search the nearer side first
        if let Some(first_idx) = first {
            self.nearest_recursive(first_idx, query, best_id, best_dist);
        }

        // Check if we need to search the other side
        // The split plane distance is a lower bound (ignoring height)
        if diff.abs() < *best_dist {
            if let Some(second_idx) = second {
                self.nearest_recursive(second_idx, query, best_id, best_dist);
            }
        }
    }

    /// Find all entries within `radius` Vivaldi distance of the query point.
    /// Returns a Vec of `(id, distance)`.
    pub fn range_query(&self, query: &VivaldiCoord, radius: f64) -> Vec<(u32, f64)> {
        let mut results = Vec::new();
        if let Some(root) = self.root {
            self.range_recursive(root, query, radius, &mut results);
        }
        results
    }

    fn range_recursive(
        &self,
        node_idx: usize,
        query: &VivaldiCoord,
        radius: f64,
        results: &mut Vec<(u32, f64)>,
    ) {
        let node = &self.nodes[node_idx];
        let d = self.vivaldi_dist(query, &node.entry.coord);
        if d <= radius {
            results.push((node.entry.id, d));
        }

        let (query_val, split_val) = if node.split_axis == 0 {
            (query.x, node.entry.coord.x)
        } else {
            (query.y, node.entry.coord.y)
        };

        let diff = query_val - split_val;

        // Always check the side the query is on
        let (near, far) = if diff < 0.0 {
            (node.left, node.right)
        } else {
            (node.right, node.left)
        };

        if let Some(near_idx) = near {
            self.range_recursive(near_idx, query, radius, results);
        }

        // Check the far side only if the split plane is within radius
        if diff.abs() <= radius {
            if let Some(far_idx) = far {
                self.range_recursive(far_idx, query, radius, results);
            }
        }
    }

    /// Find k nearest neighbors. Returns sorted by distance (ascending).
    pub fn k_nearest(&self, query: &VivaldiCoord, k: usize) -> Vec<(u32, f64)> {
        if k == 0 || self.is_empty() {
            return Vec::new();
        }

        // Collect all entries via range query with infinity, then sort and truncate.
        // For small k and large N, a proper k-NN with max-heap would be better,
        // but this is simpler and correct for moderate sizes.
        let mut all: Vec<(u32, f64)> = self
            .nodes
            .iter()
            .map(|n| (n.entry.id, self.vivaldi_dist(query, &n.entry.coord)))
            .collect();
        all.sort_unstable_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        all.truncate(k);
        all
    }

    /// Vivaldi distance (includes height terms).
    fn vivaldi_dist(&self, a: &VivaldiCoord, b: &VivaldiCoord) -> f64 {
        a.distance(b)
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u32, x: f64, y: f64) -> SpatialEntry {
        SpatialEntry {
            id,
            coord: VivaldiCoord::new(x, y),
        }
    }

    #[test]
    fn empty_tree() {
        let tree = KdTree::build(&[]);
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
        assert!(tree.nearest(&VivaldiCoord::new(0.0, 0.0)).is_none());
        assert!(tree
            .range_query(&VivaldiCoord::new(0.0, 0.0), 10.0)
            .is_empty());
    }

    #[test]
    fn single_entry() {
        let tree = KdTree::build(&[entry(1, 5.0, 5.0)]);
        assert_eq!(tree.len(), 1);
        let (id, dist) = tree.nearest(&VivaldiCoord::new(0.0, 0.0)).unwrap();
        assert_eq!(id, 1);
        assert!((dist - (50.0_f64).sqrt()).abs() < 1e-10);
    }

    #[test]
    fn nearest_basic() {
        let entries = vec![entry(1, 0.0, 0.0), entry(2, 10.0, 0.0), entry(3, 5.0, 5.0)];
        let tree = KdTree::build(&entries);
        let (id, _dist) = tree.nearest(&VivaldiCoord::new(1.0, 0.0)).unwrap();
        assert_eq!(id, 1); // closest to (0,0)
    }

    #[test]
    fn nearest_exact_match() {
        let entries = vec![entry(1, 0.0, 0.0), entry(2, 5.0, 5.0), entry(3, 10.0, 10.0)];
        let tree = KdTree::build(&entries);
        let (id, dist) = tree.nearest(&VivaldiCoord::new(5.0, 5.0)).unwrap();
        assert_eq!(id, 2);
        assert!(dist < 1e-10);
    }

    #[test]
    fn range_query_basic() {
        let entries = vec![
            entry(1, 0.0, 0.0),
            entry(2, 1.0, 0.0),
            entry(3, 100.0, 100.0),
        ];
        let tree = KdTree::build(&entries);
        let results = tree.range_query(&VivaldiCoord::new(0.5, 0.0), 2.0);
        let ids: Vec<u32> = results.iter().map(|r| r.0).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&2));
        assert!(!ids.contains(&3));
    }

    #[test]
    fn range_query_empty_result() {
        let entries = vec![entry(1, 100.0, 100.0), entry(2, 200.0, 200.0)];
        let tree = KdTree::build(&entries);
        let results = tree.range_query(&VivaldiCoord::new(0.0, 0.0), 5.0);
        assert!(results.is_empty());
    }

    #[test]
    fn range_query_all_in_range() {
        let entries = vec![entry(1, 0.0, 0.0), entry(2, 1.0, 0.0), entry(3, 0.0, 1.0)];
        let tree = KdTree::build(&entries);
        let results = tree.range_query(&VivaldiCoord::new(0.5, 0.5), 100.0);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn k_nearest_basic() {
        let entries = vec![
            entry(1, 0.0, 0.0),
            entry(2, 1.0, 0.0),
            entry(3, 2.0, 0.0),
            entry(4, 10.0, 0.0),
        ];
        let tree = KdTree::build(&entries);
        let knn = tree.k_nearest(&VivaldiCoord::new(0.0, 0.0), 2);
        assert_eq!(knn.len(), 2);
        assert_eq!(knn[0].0, 1); // closest
        assert_eq!(knn[1].0, 2); // second closest
    }

    #[test]
    fn k_nearest_k_larger_than_n() {
        let entries = vec![entry(1, 0.0, 0.0), entry(2, 1.0, 0.0)];
        let tree = KdTree::build(&entries);
        let knn = tree.k_nearest(&VivaldiCoord::new(0.0, 0.0), 10);
        assert_eq!(knn.len(), 2);
    }

    #[test]
    fn k_nearest_zero() {
        let entries = vec![entry(1, 0.0, 0.0)];
        let tree = KdTree::build(&entries);
        let knn = tree.k_nearest(&VivaldiCoord::new(0.0, 0.0), 0);
        assert!(knn.is_empty());
    }

    #[test]
    fn many_entries_nearest() {
        // 100 entries on a grid
        let mut entries = Vec::new();
        for i in 0..10 {
            for j in 0..10 {
                entries.push(entry((i * 10 + j) as u32, i as f64 * 10.0, j as f64 * 10.0));
            }
        }
        let tree = KdTree::build(&entries);
        assert_eq!(tree.len(), 100);

        // Query at (15, 15) — nearest should be (10, 10) or (20, 10) or (10, 20) or (20, 20)
        let (id, dist) = tree.nearest(&VivaldiCoord::new(15.0, 15.0)).unwrap();
        // One of the 4 corners of the cell (distance ~7.07)
        assert!(dist < 8.0);
        assert!(id < 100);
    }

    #[test]
    fn range_query_with_height() {
        let entries = vec![
            SpatialEntry {
                id: 1,
                coord: VivaldiCoord::with_height(0.0, 0.0, 5.0),
            },
            SpatialEntry {
                id: 2,
                coord: VivaldiCoord::with_height(1.0, 0.0, 0.0),
            },
        ];
        let tree = KdTree::build(&entries);
        // Query from origin with height=0. Distance to id=1 is 0 + 5.0 + 0 = 5.0
        // Distance to id=2 is 1.0 + 0.0 + 0.0 = 1.0
        let results = tree.range_query(&VivaldiCoord::new(0.0, 0.0), 3.0);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 2);
    }

    #[test]
    fn nearest_with_collinear_points() {
        let entries = vec![
            entry(1, 0.0, 0.0),
            entry(2, 5.0, 0.0),
            entry(3, 10.0, 0.0),
            entry(4, 15.0, 0.0),
        ];
        let tree = KdTree::build(&entries);
        let (id, _) = tree.nearest(&VivaldiCoord::new(12.0, 0.0)).unwrap();
        assert_eq!(id, 3); // closest to x=10
    }
}
