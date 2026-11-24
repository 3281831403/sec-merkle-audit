import hashlib

from mtree import (
    build,
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    node_hash,
    root,
    verify_consistency,
    verify_inclusion,
)


LEAF_DOMAIN = b"GSB-MERKLE-AUDIT-LEAF-V1"
NODE_DOMAIN = b"GSB-MERKLE-AUDIT-NODE-V1"
EMPTY_ROOT = hashlib.sha256(b"GSB-MERKLE-AUDIT-EMPTY-TREE-V1").digest()


def _leaf(data):
    return hashlib.sha256(LEAF_DOMAIN + data).digest()


def _node(left, right):
    return hashlib.sha256(NODE_DOMAIN + left + right).digest()


def _reference_root(leaves):
    if not leaves:
        return EMPTY_ROOT
    level = [_leaf(item) for item in leaves]
    while len(level) > 1:
        next_level = []
        for offset in range(0, len(level) - 1, 2):
            next_level.append(_node(level[offset], level[offset + 1]))
        if len(level) % 2:
            next_level.append(level[-1])
        level = next_level
    return level[0]


def test_domain_separation_blocks_internal_node_reuse():
    left = b"\x11" * 32
    right = b"\x22" * 32
    internal = node_hash(left, right)

    assert leaf_hash(left + right, LEAF_DOMAIN) != internal
    assert leaf_hash(b"record", LEAF_DOMAIN) != leaf_hash(b"record", NODE_DOMAIN)


def test_build_binds_child_order():
    alpha = b"alpha"
    beta = b"beta"
    h_alpha = _leaf(alpha)
    h_beta = _leaf(beta)

    ab = build([alpha, beta])
    ba = build([beta, alpha])

    assert ab["levels"][0] == [h_alpha, h_beta]
    assert ab["root"] == _node(h_alpha, h_beta)
    assert ab["root"] != ba["root"]


def test_odd_layer_promotion_does_not_duplicate():
    a, b, c = b"a", b"b", b"c"
    h_a, h_b, h_c = _leaf(a), _leaf(b), _leaf(c)
    parent_ab = _node(h_a, h_b)

    tree = build([a, b, c])

    assert [len(level) for level in tree["levels"]] == [3, 2, 1]
    assert tree["levels"][0] == [h_a, h_b, h_c]
    assert tree["levels"][1] == [parent_ab, h_c]
    assert root(tree) == _node(parent_ab, h_c)
    assert tree["levels"][1][1] != _node(h_c, h_c)

    proof = inclusion_proof(tree, 2)
    assert proof == [b"", parent_ab]
    assert verify_inclusion(root(tree), h_c, 2, 3, proof) is True


def test_empty_tree_root_is_constant():
    tree = build([])

    assert tree["size"] == 0
    assert root(tree) == EMPTY_ROOT
    assert tree["root"] == EMPTY_ROOT
    assert EMPTY_ROOT != b""


def test_inclusion_rejects_foreign_tree_size():
    leaf = b"\x33" * 32
    sibling_one = b"\x11" * 32
    sibling_two = b"\x22" * 32
    root_value = node_hash(node_hash(leaf, sibling_one), sibling_two)
    proof = [sibling_one, sibling_two]

    assert verify_inclusion(root_value, leaf, 0, 4, proof) is True
    assert verify_inclusion(root_value, leaf, 0, 5, proof) is False


def test_inclusion_uses_index_bits_from_right():
    h0 = _leaf(b"zero")
    h1 = _leaf(b"one")
    h2 = _leaf(b"two")
    h3 = _leaf(b"three")
    parent_01 = _node(h0, h1)
    parent_23 = _node(h2, h3)
    root_value = _node(parent_01, parent_23)

    proof = [h3, parent_01]

    assert verify_inclusion(root_value, h2, 2, 4, proof) is True


def test_consistency_rejects_non_prefix_old_root():
    leaves = [("record-%d" % index).encode() for index in range(8)]
    tree = build(leaves)
    new_root = root(tree)
    valid_old_root = _reference_root(leaves[:4])
    valid_proof = consistency_proof(valid_old_root, new_root, 4, 8, tree)

    forged_old_root = b"\x99" * 32
    forged_proof = [forged_old_root, new_root]

    assert verify_consistency(valid_old_root, new_root, 4, 8, valid_proof) is True
    assert verify_consistency(forged_old_root, new_root, 4, 8, forged_proof) is False


def test_build_does_not_reuse_cached_layers():
    first_leaves = [("first-%d" % index).encode() for index in range(8)]
    second_leaves = [("second-%d" % index).encode() for index in range(8)]

    first = build(first_leaves)
    second = build(second_leaves)

    assert second["levels"][1] != first["levels"][1]
    assert root(second) == _reference_root(second_leaves)


def test_verifiers_return_false_for_malformed_lengths():
    short = b"short"
    some_root = b"\x00" * 32
    some_leaf = b"\x01" * 32

    assert verify_inclusion(some_root, some_leaf, 0, 4, [short]) is False
    assert verify_consistency(some_root, some_leaf, 0, 4, [short]) is False


def test_domain_constants_are_not_truncated():
    data = b"audit-record"
    left = b"\x41" * 32
    right = b"\x42" * 32

    assert leaf_hash(data, LEAF_DOMAIN) == hashlib.sha256(LEAF_DOMAIN + data).digest()
    assert leaf_hash(data, NODE_DOMAIN) == hashlib.sha256(NODE_DOMAIN + data).digest()
    assert leaf_hash(data, LEAF_DOMAIN) != leaf_hash(data, NODE_DOMAIN)
    assert node_hash(left, right) == _node(left, right)


def test_single_leaf_root_equals_domain_separated_leaf():
    data = b"only-record"
    expected = _leaf(data)

    tree = build([data])

    assert root(tree) == leaf_hash(data, LEAF_DOMAIN)
    assert leaf_hash(data, LEAF_DOMAIN) == expected
    assert tree["levels"] == [[expected]]
    assert tree["size"] == 1


def test_empty_root_distinct_from_single_leaf():
    empty_tree = build([])
    single_tree = build([b"one-record"])

    assert root(empty_tree) == EMPTY_ROOT
    assert root(empty_tree) != root(single_tree)
    assert root(single_tree) == _leaf(b"one-record")


def test_proof_lengths_for_eight_and_nine_leaves():
    leaves_eight = [("eight-%d" % index).encode() for index in range(8)]
    leaves_nine = [("nine-%d" % index).encode() for index in range(9)]

    tree_eight = build(leaves_eight)
    tree_nine = build(leaves_nine)

    proof_eight = inclusion_proof(tree_eight, 5)
    proof_nine = inclusion_proof(tree_nine, 6)

    assert [len(level) for level in tree_eight["levels"]] == [8, 4, 2, 1]
    assert [len(level) for level in tree_nine["levels"]] == [9, 5, 3, 2, 1]
    assert len(proof_eight) == 3
    assert len(proof_nine) == 4
    assert root(tree_eight) == _reference_root(leaves_eight)
    assert root(tree_nine) == _reference_root(leaves_nine)
    assert verify_inclusion(root(tree_eight), tree_eight["levels"][0][5], 5, 8, proof_eight) is True
    assert verify_inclusion(root(tree_nine), tree_nine["levels"][0][6], 6, 9, proof_nine) is True


def test_build_is_idempotent_for_same_leaves():
    leaves = [("same-%d" % index).encode() for index in range(8)]

    first = build(leaves)
    second = build(leaves)

    assert first["root"] == second["root"]
    assert first["levels"] == second["levels"]
    assert first["root"] == _reference_root(leaves)


def test_independent_trees_match_isolated_builds():
    leaves_a = [("alpha-%d" % index).encode() for index in range(8)]
    leaves_b = [("beta-%d" % index).encode() for index in range(8)]

    tree_a = build(leaves_a)
    tree_b = build(leaves_b)

    assert root(tree_a) == _reference_root(leaves_a)
    assert root(tree_b) == _reference_root(leaves_b)
    assert tree_a["levels"][1] != tree_b["levels"][1]
    assert tree_b["size"] == 8