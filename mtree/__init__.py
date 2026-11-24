"""Facade package for the Merkle audit exercise."""

from .api import (
    build,
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    node_hash,
    root,
    verify_consistency,
    verify_inclusion,
)

__all__ = [
    "leaf_hash",
    "node_hash",
    "build",
    "root",
    "inclusion_proof",
    "verify_inclusion",
    "consistency_proof",
    "verify_consistency",
]