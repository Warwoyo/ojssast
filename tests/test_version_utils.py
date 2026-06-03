import pytest
from ojs_sast.helpers.version_utils import is_version_affected, parse_version_raw, parse_version


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
