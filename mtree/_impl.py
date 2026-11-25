"""Merkle audit tree implementation.

Security invariants (the ten audit fixes, in the reported order):

1. Leaves and internal nodes use distinct, full-length domain prefixes so an
   internal node cannot be replayed as a leaf (second pre-image resistance
   via domain separation).
2. Internal hashes bind child order: H(NODE_DOMAIN || left || right).
3. An unpaired odd node is *promoted unchanged* (never hashed with a copy of
   itself), closing the duplicate-leaf attack.  A missing sibling is encoded
   as the empty placeholder ``b""``.
4. The empty tree has a fixed non-empty root constant, distinct from every
   single-leaf root.
5. Inclusion verification is bound to the claimed tree ``size`` (the expected
   proof length/structure is derived from it), so proofs cannot be replayed
   across different tree sizes.
6. The index is consumed least-significant bit first ("from the right").
7. Consistency proofs are real RFC-6962/9162-style prefix proofs; the
   verifier reconstructs and compares *both* the old and the new root
   instead of merely comparing two supplied endpoints.
8. ``build`` keeps all layer state in locals; there is no shared layer cache
   that a second tree could inherit.
9. Both verifiers return ``False`` for any malformed/oversized input instead
   of raising.
10. Domain constants are used verbatim (never truncated/sliced).
"""

import hashlib

LEAF_DOMAIN = b"GSB-MERKLE-AUDIT-LEAF-V1"
NODE_DOMAIN = b"GSB-MERKLE-AUDIT-NODE-V1"
EMPTY_ROOT = hashlib.sha256(b"GSB-MERKLE-AUDIT-EMPTY-TREE-V1").digest()

_DIGEST_LEN = 32
# Placeholder used in inclusion proofs for an odd-last node that was promoted
# without a sibling.  Real hashes are always 32 bytes, so this can never be a
# valid sibling digest.
_NO_SIBLING = b""


def _digest(value):
    return hashlib.sha256(value).digest()


def _is_digest(value):
    return isinstance(value, (bytes, bytearray)) and len(value) == _DIGEST_LEN


def leaf_hash(data, domain):
    """Hash a leaf, keeping the supplied *full* domain label in front."""
    # Fix 10: use the complete domain constant -- no ``domain[:16]`` slice.
    return _digest(bytes(domain) + bytes(data))


def node_hash(left, right):
    """Hash an internal node; child order is bound into the pre-image."""
    # Fix 1 (distinct NODE prefix vs LEAF prefix) + fix 2 (ordered concat).
    return _digest(NODE_DOMAIN + bytes(left) + bytes(right))


def _merge_level(level):
    """Pair adjacent nodes; promote an odd final node unchanged (fix 3)."""
    next_level = []
    i = 0
    n = len(level)
    while i < n:
        if i + 1 < n:
            next_level.append(node_hash(level[i], level[i + 1]))
            i += 2
        else:
            # Odd last element: promote as-is, never node_hash(x, x).
            next_level.append(level[i])
            i += 1
    return next_level


def build(leaves):
    """Build the level table for a batch of leaves.

    The returned dictionary contains the leaf-to-root ``levels`` (each entry
    a list of digests), the ``root`` and the leaf ``size``.  Every call builds
    fresh local state -- no layer table is cached between trees (fix 8).
    """
    leaves = list(leaves)
    size = len(leaves)

    # Fix 4: the empty tree gets a dedicated, non-empty constant root.
    if size == 0:
        return {"levels": [], "root": EMPTY_ROOT, "size": 0}

    level = [leaf_hash(item, LEAF_DOMAIN) for item in leaves]
    levels = [level]
    while len(level) > 1:
        level = _merge_level(level)
        levels.append(level)

    return {"levels": levels, "root": level[0], "size": size}


def root(tree):
    """Return the root stored in a tree dictionary."""
    return tree["root"]


def inclusion_proof(tree, index):
    """Return sibling hashes from the leaf level upward.

    A level where the indexed node is an unpaired odd-last promotion contributes
    an empty placeholder (``b""``) so the verifier can keep level alignment.
    """
    levels = tree["levels"]
    size = tree["size"]
    if not isinstance(index, int) or isinstance(index, bool):
        raise IndexError("leaf index must be an integer")
    if index < 0 or index >= size:
        raise IndexError("leaf index %r out of range for size %r" % (index, size))

    proof = []
    idx = index
    for level in levels[:-1]:
        n = len(level)
        if n % 2 == 1 and idx == n - 1:
            # Promoted odd-last node: no sibling at this level.
            proof.append(_NO_SIBLING)
        elif idx % 2 == 0:
            proof.append(level[idx + 1])
        else:
            proof.append(level[idx - 1])
        idx //= 2
    return proof


def _expected_inclusion_length(size):
    # Number of level transitions: ceil(log2(size)) == (size - 1).bit_length().
    return (size - 1).bit_length()


def _level_length(size, level_index):
    # Level ``l`` holds ceil(size / 2**l) nodes under odd-last promotion.
    shift = level_index
    return (size + (1 << shift) - 1) >> shift


def verify_inclusion(root_value, leaf, index, size, proof):
    """Check an inclusion proof against a claimed tree size.

    Never raises for malformed input: any structural/length/type problem
    yields ``False`` (fix 9).  The claimed ``size`` determines the exact proof
    shape, which blocks cross-size proof replay (fix 5).
    """
    try:
        if isinstance(size, bool) or not isinstance(size, int):
            return False
        if isinstance(index, bool) or not isinstance(index, int):
            return False
        if size <= 0 or index < 0 or index >= size:
            return False
        if not _is_digest(root_value) or not _is_digest(leaf):
            return False

        proof = list(proof)
        if len(proof) != _expected_inclusion_length(size):
            return False

        current = bytes(leaf)
        idx = index

        for level_index, sibling in enumerate(proof):
            level_len = _level_length(size, level_index)
            odd_last_slot = (
                level_len % 2 == 1 and idx == level_len - 1
            )

            if odd_last_slot:
                # The only legal empty placeholder is a genuine promotion.
                if sibling != _NO_SIBLING:
                    return False
                # Promoted unchanged: ``current`` carries to the next level.
            else:
                if not _is_digest(sibling):
                    return False
                sibling = bytes(sibling)
                # Fix 6: consume index bits least-significant bit first.
                if idx & 1:
                    # Current node is the right child: H(sibling || current).
                    current = node_hash(sibling, current)
                else:
                    # Current node is the left child: H(current || sibling).
                    current = node_hash(current, sibling)

            idx >>= 1

        if idx != 0:
            return False
        return current == bytes(root_value)
    except Exception:
        # Fix 9: callers can branch on a boolean instead of handling raises.
        return False


# ---------------------------------------------------------------------------
# Consistency proofs (RFC 6962 SUBPROOF generation + RFC 9162 verification)
# ---------------------------------------------------------------------------


def _largest_power_of_two_less_than(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _merkle_root(hashes):
    """MTH over an existing ordered list of leaf digests."""
    hashes = list(hashes)
    if not hashes:
        return EMPTY_ROOT
    level = hashes
    while len(level) > 1:
        level = _merge_level(level)
    return level[0]


def _subproof(m, segment, b):
    """RFC 6962 ``SUBPROOF(m, D[n], b)`` over a segment of leaf digests."""
    n = len(segment)
    if m == n:
        return [] if b else [_merkle_root(segment)]

    k = _largest_power_of_two_less_than(n)
    if m <= k:
        return _subproof(m, segment[:k], b) + [_merkle_root(segment[k:])]
    return (
        _subproof(m - k, segment[k:], False)
        + [_merkle_root(segment[:k])]
    )


def consistency_proof(old_root, new_root, old_size, new_size, tree):
    """Return an RFC-style prefix consistency proof.

    The returned list contains the subtree digests a verifier needs to
    reconstruct both ``old_root`` (the MTH of the first ``old_size`` leaves)
    and ``new_root`` (the MTH of all ``new_size`` leaves).
    """
    leaf_level = tree["levels"][0]
    m = old_size
    n = new_size if new_size is not None else tree["size"]

    if not isinstance(m, int) or not isinstance(n, int):
        return []
    if m < 0 or m > n or len(leaf_level) < n:
        return []
    if m == 0 or m == n:
        return []

    return _subproof(m, list(leaf_level[:n]), True)


def _is_power_of_two(x):
    return x > 0 and (x & (x - 1)) == 0


def verify_consistency(old_root, new_root, old_size, new_size, proof):
    """Verify that ``old_root`` is a prefix of the tree named by ``new_root``.

    Reconstructs both roots from the proof and the size-derived bit path and
    only accepts when both match (fix 7).  Returns ``False`` -- never raises
    -- for malformed proofs (fix 9).
    """
    try:
        if isinstance(old_size, bool) or isinstance(new_size, bool):
            return False
        if not isinstance(old_size, int) or not isinstance(new_size, int):
            return False
        if old_size < 0 or new_size <= 0 or old_size > new_size:
            return False
        if not _is_digest(old_root) or not _is_digest(new_root):
            return False

        path = list(proof)
        # Every real consistency node is a fixed-width digest; a short or
        # otherwise malformed entry is rejected uniformly here.
        if not all(_is_digest(item) for item in path):
            return False

        old_root = bytes(old_root)
        new_root = bytes(new_root)

        # The empty tree is consistent only with the canonical empty root and
        # an empty proof (the malformed-length case is already rejected above).
        if old_size == 0:
            return len(path) == 0 and old_root == EMPTY_ROOT

        if old_size == new_size:
            return len(path) == 0 and old_root == new_root

        if len(path) == 0:
            return False

        path = [bytes(item) for item in path]

        # RFC 9162: when old_size is an exact power of two the trusted old
        # root itself seeds both accumulators, so prepend it to the path.
        if _is_power_of_two(old_size):
            path.insert(0, old_root)

        fn = old_size - 1
        sn = new_size - 1

        # Align past the shared trailing one-bits.
        while fn & 1:
            fn >>= 1
            sn >>= 1

        fr = sr = path[0]

        for c in path[1:]:
            if sn == 0:
                return False

            if (fn & 1) or (fn == sn):
                # Companion ``c`` is on the left of both accumulators.
                fr = node_hash(c, fr)
                sr = node_hash(c, sr)

                # Equality-entry alignment: skip even low bits of ``fn``.
                if not (fn & 1):
                    while fn != 0 and not (fn & 1):
                        fn >>= 1
                        sn >>= 1
            else:
                # Companion ``c`` is on the right of the new accumulator only.
                sr = node_hash(sr, c)

            fn >>= 1
            sn >>= 1

        return bool(
            fr == old_root and sr == new_root and sn == 0
        )
    except Exception:
        return False
