//! Certificate-Transparency-style Merkle tree (RFC 9162 §2.1) over BLAKE3.
//!
//! Leaves and interior nodes are domain-separated with the 0x00 / 0x01
//! prefixes from the RFC, so a leaf can never be passed off as a subtree.
//! The functions that build proofs from a list of *leaf hashes* are O(n) per
//! proof; [`MerkleCache`] keeps every complete subtree's hash so a running
//! node answers proofs in O(log n).

use crate::Digest;

pub fn leaf_hash(data: &[u8]) -> Digest {
    let mut h = blake3::Hasher::new();
    h.update(&[0x00]);
    h.update(data);
    Digest(*h.finalize().as_bytes())
}

pub fn node_hash(left: &Digest, right: &Digest) -> Digest {
    let mut h = blake3::Hasher::new();
    h.update(&[0x01]);
    h.update(left.as_bytes());
    h.update(right.as_bytes());
    Digest(*h.finalize().as_bytes())
}

/// Largest power of two strictly less than `n` (n >= 2).
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// Merkle tree hash of a list of leaf hashes. The empty tree hashes to
/// BLAKE3 of the empty string.
pub fn root(leaves: &[Digest]) -> Digest {
    match leaves.len() {
        0 => Digest::of(b""),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// Audit path for leaf `index` in the tree of all `leaves`.
pub fn inclusion_proof(leaves: &[Digest], index: usize) -> Option<Vec<Digest>> {
    if index >= leaves.len() {
        return None;
    }
    let mut out = Vec::new();
    path(index, leaves, &mut out);
    Some(out)
}

fn path(m: usize, d: &[Digest], out: &mut Vec<Digest>) {
    let n = d.len();
    if n <= 1 {
        return;
    }
    let k = split(n);
    if m < k {
        path(m, &d[..k], out);
        out.push(root(&d[k..]));
    } else {
        path(m - k, &d[k..], out);
        out.push(root(&d[..k]));
    }
}

/// Proof that the first `old_size` leaves are a prefix of `leaves`.
pub fn consistency_proof(leaves: &[Digest], old_size: usize) -> Option<Vec<Digest>> {
    if old_size > leaves.len() {
        return None;
    }
    let mut out = Vec::new();
    if old_size > 0 && old_size < leaves.len() {
        subproof(old_size, leaves, true, &mut out);
    }
    Some(out)
}

fn subproof(m: usize, d: &[Digest], complete: bool, out: &mut Vec<Digest>) {
    let n = d.len();
    if m == n {
        if !complete {
            out.push(root(d));
        }
        return;
    }
    let k = split(n);
    if m <= k {
        subproof(m, &d[..k], complete, out);
        out.push(root(&d[k..]));
    } else {
        subproof(m - k, &d[k..], false, out);
        out.push(root(&d[..k]));
    }
}

/// RFC 9162 §2.1.3.2.
pub fn verify_inclusion(
    leaf: &Digest,
    index: u64,
    tree_size: u64,
    proof: &[Digest],
    root: &Digest,
) -> bool {
    if index >= tree_size {
        return false;
    }
    let (mut f, mut s) = (index, tree_size - 1);
    let mut r = *leaf;
    for p in proof {
        if s == 0 {
            return false;
        }
        if f & 1 == 1 || f == s {
            r = node_hash(p, &r);
            if f & 1 == 0 {
                while f & 1 == 0 && f != 0 {
                    f >>= 1;
                    s >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    s == 0 && r == *root
}

/// RFC 9162 §2.1.4.2.
pub fn verify_consistency(
    old_size: u64,
    new_size: u64,
    old_root: &Digest,
    new_root: &Digest,
    proof: &[Digest],
) -> bool {
    if old_size > new_size {
        return false;
    }
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }
    if old_size == 0 {
        // The empty tree is a prefix of every tree.
        return proof.is_empty();
    }
    let mut path: Vec<Digest> = Vec::with_capacity(proof.len() + 1);
    if old_size.is_power_of_two() {
        path.push(*old_root);
    }
    path.extend_from_slice(proof);
    let Some((first, rest)) = path.split_first() else {
        return false;
    };

    let (mut f, mut s) = (old_size - 1, new_size - 1);
    while f & 1 == 1 {
        f >>= 1;
        s >>= 1;
    }
    let (mut fr, mut sr) = (*first, *first);
    for c in rest {
        if s == 0 {
            return false;
        }
        if f & 1 == 1 || f == s {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if f & 1 == 0 {
                while f & 1 == 0 && f != 0 {
                    f >>= 1;
                    s >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        f >>= 1;
        s >>= 1;
    }
    fr == *old_root && sr == *new_root && s == 0
}

/// Hashes of every complete, aligned subtree of an append-only log, so
/// roots and proofs cost O(log n) instead of O(n). `levels[h][i]` is the
/// hash of leaves `i * 2^h .. (i + 1) * 2^h`. Memory: about two digests per
/// leaf.
#[derive(Clone, Debug, Default)]
pub struct MerkleCache {
    levels: Vec<Vec<Digest>>,
}

impl MerkleCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of leaves.
    pub fn len(&self) -> usize {
        self.levels.first().map_or(0, Vec::len)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Append a leaf hash.
    pub fn push(&mut self, leaf: Digest) {
        let mut h = 0;
        let mut d = leaf;
        loop {
            if self.levels.len() == h {
                self.levels.push(Vec::new());
            }
            self.levels[h].push(d);
            let n = self.levels[h].len();
            if n % 2 == 1 {
                break;
            }
            d = node_hash(&self.levels[h][n - 2], &self.levels[h][n - 1]);
            h += 1;
        }
    }

    /// Drop every leaf from `n` on.
    pub fn truncate(&mut self, n: usize) {
        for (h, level) in self.levels.iter_mut().enumerate() {
            level.truncate(n >> h);
        }
        while self.levels.last().is_some_and(Vec::is_empty) {
            self.levels.pop();
        }
    }

    /// Merkle tree hash of leaves `start .. start + n`, where every call
    /// comes from the RFC 9162 recursion: `start` is a multiple of the
    /// largest power of two not above `n`.
    fn hash(&self, start: usize, n: usize) -> Digest {
        match n {
            0 => Digest::of(b""),
            n if n.is_power_of_two() => {
                let h = n.trailing_zeros() as usize;
                self.levels[h][start >> h]
            }
            n => {
                let k = split(n);
                node_hash(&self.hash(start, k), &self.hash(start + k, n - k))
            }
        }
    }

    /// Root of the tree of the first `size` leaves.
    pub fn root(&self, size: usize) -> Option<Digest> {
        (size <= self.len()).then(|| self.hash(0, size))
    }

    /// Audit path for leaf `index` in the tree of the first `size` leaves;
    /// the same as [`inclusion_proof`] over those leaves.
    pub fn inclusion_proof(&self, size: usize, index: usize) -> Option<Vec<Digest>> {
        if size > self.len() || index >= size {
            return None;
        }
        let mut out = Vec::new();
        self.path(index, 0, size, &mut out);
        Some(out)
    }

    fn path(&self, m: usize, start: usize, n: usize, out: &mut Vec<Digest>) {
        if n <= 1 {
            return;
        }
        let k = split(n);
        if m < k {
            self.path(m, start, k, out);
            out.push(self.hash(start + k, n - k));
        } else {
            self.path(m - k, start + k, n - k, out);
            out.push(self.hash(start, k));
        }
    }

    /// Proof that the first `old` leaves are a prefix of the first `new`;
    /// the same as [`consistency_proof`] over those leaves.
    pub fn consistency_proof(&self, old: usize, new: usize) -> Option<Vec<Digest>> {
        if new > self.len() || old > new {
            return None;
        }
        let mut out = Vec::new();
        if old > 0 && old < new {
            self.subproof(old, 0, new, true, &mut out);
        }
        Some(out)
    }

    fn subproof(&self, m: usize, start: usize, n: usize, complete: bool, out: &mut Vec<Digest>) {
        if m == n {
            if !complete {
                out.push(self.hash(start, n));
            }
            return;
        }
        let k = split(n);
        if m <= k {
            self.subproof(m, start, k, complete, out);
            out.push(self.hash(start + k, n - k));
        } else {
            self.subproof(m - k, start + k, n - k, false, out);
            out.push(self.hash(start, k));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Digest> {
        (0..n)
            .map(|i| leaf_hash(&(i as u64).to_be_bytes()))
            .collect()
    }

    #[test]
    fn small_roots() {
        let l = leaves(3);
        assert_eq!(root(&l[..1]), l[0]);
        assert_eq!(root(&l[..2]), node_hash(&l[0], &l[1]));
        assert_eq!(root(&l), node_hash(&node_hash(&l[0], &l[1]), &l[2]));
    }

    #[test]
    fn inclusion_all_sizes() {
        for n in 1..=40 {
            let l = leaves(n);
            let r = root(&l);
            for i in 0..n {
                let p = inclusion_proof(&l, i).unwrap();
                assert!(
                    verify_inclusion(&l[i], i as u64, n as u64, &p, &r),
                    "n={n} i={i}"
                );
                // Wrong index, wrong leaf, wrong size and truncated proofs fail.
                if n > 1 {
                    let j = (i + 1) % n;
                    assert!(!verify_inclusion(&l[i], j as u64, n as u64, &p, &r));
                    assert!(!verify_inclusion(&l[j], i as u64, n as u64, &p, &r));
                    assert!(!verify_inclusion(
                        &l[i],
                        i as u64,
                        n as u64,
                        &p[..p.len() - 1],
                        &r
                    ));
                }
            }
            assert!(inclusion_proof(&l, n).is_none());
        }
    }

    #[test]
    fn consistency_all_sizes() {
        let all = leaves(40);
        for n in 1..=40 {
            let l = &all[..n];
            let rn = root(l);
            for m in 0..=n {
                let rm = root(&l[..m]);
                let p = consistency_proof(l, m).unwrap();
                assert!(
                    verify_consistency(m as u64, n as u64, &rm, &rn, &p),
                    "m={m} n={n}"
                );
                if m > 0 && m < n {
                    // A forked history (different old root) must not verify.
                    let forged = leaf_hash(b"forged");
                    assert!(!verify_consistency(m as u64, n as u64, &forged, &rn, &p));
                    assert!(!verify_consistency(m as u64, n as u64, &rm, &forged, &p));
                }
            }
        }
    }

    #[test]
    fn rewritten_history_is_detected() {
        let mut l = leaves(10);
        let old_root = root(&l[..6]);
        l[3] = leaf_hash(b"rewritten");
        let p = consistency_proof(&l, 6).unwrap();
        assert!(!verify_consistency(6, 10, &old_root, &root(&l), &p));
    }

    #[test]
    fn cache_matches_the_slice_functions() {
        let leaves: Vec<Digest> = (0..70u32).map(|i| leaf_hash(&i.to_be_bytes())).collect();
        let mut c = MerkleCache::new();
        assert_eq!(c.root(0), Some(root(&[])));
        for (i, l) in leaves.iter().enumerate() {
            c.push(*l);
            let size = i + 1;
            assert_eq!(c.len(), size);
            for n in 0..=size {
                assert_eq!(c.root(n), Some(root(&leaves[..n])), "root {n}");
                for m in 0..n {
                    assert_eq!(
                        c.inclusion_proof(n, m),
                        inclusion_proof(&leaves[..n], m),
                        "inclusion {m} of {n}"
                    );
                }
                for old in 0..=n {
                    assert_eq!(
                        c.consistency_proof(old, n),
                        consistency_proof(&leaves[..n], old),
                        "consistency {old} -> {n}"
                    );
                }
            }
        }
        assert_eq!(c.root(71), None);
        let mut t = c.clone();
        t.truncate(37);
        let mut fresh = MerkleCache::new();
        for l in &leaves[..37] {
            fresh.push(*l);
        }
        assert_eq!(t.levels, fresh.levels);
        assert_eq!(c.inclusion_proof(70, 70), None);
        assert_eq!(c.consistency_proof(3, 71), None);
    }
}
