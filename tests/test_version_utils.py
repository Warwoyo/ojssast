from ojs_sast.helpers.version_utils import (
    is_version_affected,
    parse_version,
    parse_version_raw,
    version_branch,
)


def test_version_branch_pads_to_three_components():
    assert version_branch((3,)) == (3, 0, 0)
    assert version_branch((3, 4)) == (3, 4, 0)
    assert version_branch((3, 4, 0, 7)) == (3, 4, 0)


def test_parse_version_supported_detected_formats():
    assert parse_version("3.3.0-13") == (3, 3, 0, 13)
    assert parse_version("3.3.0.13") == (3, 3, 0, 13)
    assert parse_version("3.4.0") == (3, 4, 0, 0)
    assert parse_version("v3.4.0-7") == (3, 4, 0, 7)
    assert parse_version_raw("3.3.0-13") == (3, 3, 0, 13)


def test_branch_aware_patched_versions():
    affected = ["<=3.3.0-21", "<=3.4.0-9", "<=3.5.0-1"]
    patched = ["3.3.0-22", "3.4.0-10", "3.5.0-2"]

    assert is_version_affected("3.3.0-21", affected, patched)[0] is True
    assert is_version_affected("3.3.0-22", affected, patched)[0] is False

    assert is_version_affected("3.4.0-7", affected, patched)[0] is True
    assert is_version_affected("3.4.0.7", affected, patched)[0] is True
    assert is_version_affected("3.4.0-10", affected, patched)[0] is False

    assert is_version_affected("3.5.0-1", affected, patched)[0] is True
    assert is_version_affected("3.5.0-2", affected, patched)[0] is False


def test_non_operator_prefix_matches_branch():
    assert is_version_affected("3.3.0-13", ["3.3.0"], None)[0] is True
    assert is_version_affected("3.4.0-1", ["3.3.0"], None)[0] is False


def test_unknown_version_conservative():
    assert is_version_affected(None, ["3.3.0"], None)[0] is True
    assert is_version_affected("", ["3.3.0"], None)[0] is True


def test_reason_string():
    affected = ["<=3.3.0-21", "<=3.4.0-9", "<=3.5.0-1"]
    patched = ["3.3.0-22", "3.4.0-10", "3.5.0-2"]

    is_aff, reason = is_version_affected("3.4.0-7", affected, patched)
    assert is_aff is True
    assert "below patched 3.4.0-10" in reason
    assert "ignored patched specs from other branches: 3.3.0-22, 3.5.0-2" in reason


def test_below_same_branch_patch_is_not_automatically_affected():
    # detected is 3.4.0-7, which is below same-branch patch 3.4.0-10.
    # But affected range is <=3.3.0-21 (not covering 3.4 branch).
    # It must return False (not affected / safe).
    is_aff, reason = is_version_affected("3.4.0-7", ["<=3.3.0-21"], ["3.4.0-10"])
    assert is_aff is False
    assert "not in affected ranges" in reason

