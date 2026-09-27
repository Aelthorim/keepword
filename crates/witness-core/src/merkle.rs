//! Certificate-Transparency-style Merkle tree (RFC 9162 §2.1) over BLAKE3.
//!
//! Leaves and interior nodes are domain-separated with the 0x00 / 0x01
//! prefixes from the RFC, so a leaf can never be passed off as a subtree.
//! Functions that build proofs take the full list of *leaf hashes*; this is
//! O(n) per proof, which is fine for a single node. A tiled log replaces it
//! once logs get large (see docs/DESIGN.md).

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
}
