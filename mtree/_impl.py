"""Merkle audit tree contracts; every function is an unimplemented stub."""
import hashlib
LEAF_DOMAIN = b'GSB-MERKLE-AUDIT-LEAF-V1'
NODE_DOMAIN = b'GSB-MERKLE-AUDIT-NODE-V1'
EMPTY_ROOT = hashlib.sha256(b'GSB-MERKLE-AUDIT-EMPTY-TREE-V1').digest()
_LAST_LAYERS = []

def leaf_hash(data, domain):
    """Hash a leaf, keeping the supplied domain label in front of the data."""
    raise NotImplementedError()

def node_hash(left, right):
    """Hash an internal node; the caller is responsible for child order."""
    raise NotImplementedError()

def build(leaves):
    """Build the level table for a batch of leaves."""
    raise NotImplementedError()

def root(tree):
    """Return the root stored in a tree dictionary."""
    raise NotImplementedError()

def inclusion_proof(tree, index):
    """Return sibling hashes from the leaf level upward."""
    raise NotImplementedError()

def verify_inclusion(root_value, leaf, index, size, proof):
    """Check an inclusion proof against a claimed tree size."""
    raise NotImplementedError()

def consistency_proof(old_root, new_root, old_size, new_size, tree):
    """Return the two endpoints that the verifier will compare."""
    raise NotImplementedError()

def verify_consistency(old_root, new_root, old_size, new_size, proof):
    """Check a consistency proof by comparing its endpoint hashes."""
    raise NotImplementedError()
