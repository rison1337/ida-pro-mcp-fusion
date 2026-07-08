"""Tests for api_cache: cache build/status and consistent regex validation.

These exercise the persistent SQLite cache layer. The regex tests pin down the
contract that every regex-accepting cache tool reports a malformed pattern as an
``error`` (instead of silently returning an empty list, which is
indistinguishable from a genuine "no matches" result).
"""

from ..framework import (
    test,
    assert_ok,
    assert_error,
    assert_has_keys,
    assert_is_list,
)
from ..api_cache import (
    refresh_cache,
    cache_status,
    cache_list_funcs,
    cache_entity_query,
    cache_callgraph,
    cache_find_regex,
)

# A syntactically invalid regex (unterminated character set / group).
BAD_REGEX = "([unterminated"

_CACHE_BUILT = False


def _ensure_cache() -> None:
    """Build the SQLite cache for the current IDB once per test run."""
    global _CACHE_BUILT
    if not _CACHE_BUILT:
        result = refresh_cache(include_xrefs=True)
        assert result.get("ok"), f"refresh_cache failed: {result!r}"
        _CACHE_BUILT = True


# ============================================================================
# Cache build / status
# ============================================================================


@test()
def test_cache_refresh_and_status():
    """refresh_cache builds a cache that cache_status then reports as ready."""
    _ensure_cache()
    status = cache_status()
    assert_has_keys(status, "exists", "ready", "status", "counts")
    assert status["exists"] is True, f"cache should exist: {status!r}"
    assert status["ready"] is True, f"cache should be ready: {status!r}"
    assert status["counts"]["functions"] >= 1


@test()
def test_cache_status_freshness_fields():
    """cache_status exposes freshness fields; a freshly built cache is not stale."""
    _ensure_cache()
    status = cache_status()  # default max_age_sec=0 -> age check disabled
    assert status["exists"] is True
    assert status["stale"] is False, f"freshly built cache should be fresh: {status!r}"
    assert isinstance(status["schema_stale"], bool)


# ============================================================================
# Valid regex still works
# ============================================================================


@test()
def test_cache_list_funcs_valid_pattern():
    """cache_list_funcs with a valid regex returns a well-formed result."""
    _ensure_cache()
    result = cache_list_funcs(name_pattern=".*", limit=5)
    assert_ok(result, "items", "total")
    assert_is_list(result["items"])
    assert result["total"] >= 1


@test()
def test_cache_entity_query_valid_pattern():
    """cache_entity_query with a valid regex returns a well-formed result."""
    _ensure_cache()
    result = cache_entity_query(kind="functions", pattern=".*", limit=5)
    assert_ok(result, "items", "total")
    assert_is_list(result["items"])


# ============================================================================
# Malformed regex is reported as an error (the fix)
# ============================================================================


@test()
def test_cache_list_funcs_bad_regex_reports_error():
    """cache_list_funcs surfaces a malformed regex as an error, not silent empty."""
    _ensure_cache()
    result = cache_list_funcs(name_pattern=BAD_REGEX)
    assert_error(result)
    assert result["items"] == []


@test()
def test_cache_entity_query_bad_pattern_reports_error():
    """cache_entity_query surfaces a malformed pattern regex as an error."""
    _ensure_cache()
    result = cache_entity_query(kind="functions", pattern=BAD_REGEX)
    assert_error(result)


@test()
def test_cache_entity_query_bad_segment_reports_error():
    """cache_entity_query validates the segment regex too."""
    _ensure_cache()
    result = cache_entity_query(kind="functions", segment=BAD_REGEX)
    assert_error(result)


@test()
def test_cache_callgraph_bad_name_pattern_reports_error():
    """cache_callgraph surfaces a malformed name_pattern as an error."""
    _ensure_cache()
    result = cache_callgraph(name_pattern=BAD_REGEX)
    assert_error(result)
    assert result["edges"] == []


@test()
def test_cache_entity_query_invalid_kind_reports_error():
    """cache_entity_query rejects an unknown kind with an error."""
    _ensure_cache()
    result = cache_entity_query(kind="not_a_kind")
    assert_error(result, contains="kind")


# ============================================================================
# Consistency: every regex-taking cache tool agrees on a bad pattern
# ============================================================================


@test()
def test_cache_regex_error_consistency_across_tools():
    """All regex-accepting cache tools report a bad pattern as an error."""
    _ensure_cache()
    assert_error(cache_list_funcs(name_pattern=BAD_REGEX))
    assert_error(cache_entity_query(kind="functions", pattern=BAD_REGEX))
    assert_error(cache_callgraph(name_pattern=BAD_REGEX))
    assert_error(cache_find_regex(pattern=BAD_REGEX))
