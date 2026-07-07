"""Persistent SQLite cache tools for headless IDA sessions.

This is a small supervisor-friendly adaptation of the cache idea from
ida-pro-mcp-enhancement. The cache lives next to the current IDB and can be
queried repeatedly without walking IDA data structures every time.
"""

from __future__ import annotations

import os
import re
import sqlite3
import time
from typing import Annotated, Any, TypedDict

import ida_auto
import ida_loader
import ida_nalt
import ida_typeinf
import idaapi
import ida_funcs
import idautils
import idc

from .rpc import tool
from .sync import idasync, tool_timeout


SCHEMA_VERSION = 2

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS strings (
    addr TEXT PRIMARY KEY,
    ea INTEGER NOT NULL,
    text TEXT NOT NULL,
    length INTEGER NOT NULL,
    segment TEXT
);
CREATE INDEX IF NOT EXISTS idx_strings_text ON strings(text);
CREATE INDEX IF NOT EXISTS idx_strings_segment ON strings(segment);

CREATE TABLE IF NOT EXISTS string_xrefs (
    str_addr TEXT NOT NULL,
    xref_addr TEXT NOT NULL,
    xref_ea INTEGER NOT NULL,
    type TEXT NOT NULL,
    PRIMARY KEY (str_addr, xref_addr)
);
CREATE INDEX IF NOT EXISTS idx_string_xrefs_str ON string_xrefs(str_addr);

CREATE TABLE IF NOT EXISTS functions (
    addr TEXT PRIMARY KEY,
    ea INTEGER NOT NULL,
    name TEXT NOT NULL,
    size INTEGER NOT NULL,
    segment TEXT,
    has_type INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name);
CREATE INDEX IF NOT EXISTS idx_functions_segment ON functions(segment);

CREATE TABLE IF NOT EXISTS function_xrefs (
    func_addr TEXT NOT NULL,
    xref_addr TEXT NOT NULL,
    xref_ea INTEGER NOT NULL,
    direction TEXT NOT NULL,
    type TEXT NOT NULL,
    PRIMARY KEY (func_addr, xref_addr, direction)
);
CREATE INDEX IF NOT EXISTS idx_function_xrefs_func ON function_xrefs(func_addr);

CREATE TABLE IF NOT EXISTS function_calls (
    caller_addr TEXT NOT NULL,
    caller_ea INTEGER NOT NULL,
    caller_name TEXT NOT NULL,
    callee_addr TEXT NOT NULL,
    callee_ea INTEGER NOT NULL,
    callee_name TEXT NOT NULL,
    call_addr TEXT NOT NULL,
    call_ea INTEGER NOT NULL,
    type TEXT NOT NULL,
    PRIMARY KEY (caller_addr, callee_addr, call_addr)
);
CREATE INDEX IF NOT EXISTS idx_function_calls_caller ON function_calls(caller_addr);
CREATE INDEX IF NOT EXISTS idx_function_calls_callee ON function_calls(callee_addr);
CREATE INDEX IF NOT EXISTS idx_function_calls_call_ea ON function_calls(call_ea);

CREATE TABLE IF NOT EXISTS globals (
    addr TEXT PRIMARY KEY,
    ea INTEGER NOT NULL,
    name TEXT NOT NULL,
    size INTEGER,
    segment TEXT
);
CREATE INDEX IF NOT EXISTS idx_globals_name ON globals(name);
CREATE INDEX IF NOT EXISTS idx_globals_segment ON globals(segment);

CREATE TABLE IF NOT EXISTS imports (
    addr TEXT PRIMARY KEY,
    ea INTEGER NOT NULL,
    name TEXT NOT NULL,
    module TEXT
);
CREATE INDEX IF NOT EXISTS idx_imports_name ON imports(name);
CREATE INDEX IF NOT EXISTS idx_imports_module ON imports(module);
"""


class CachePathResult(TypedDict):
    idb_path: str
    cache_path: str


class CacheStats(TypedDict):
    strings: int
    string_xrefs: int
    functions: int
    function_xrefs: int
    function_calls: int
    globals: int
    imports: int


class CacheStatus(TypedDict, total=False):
    exists: bool
    ready: bool
    status: str
    idb_path: str
    cache_path: str
    schema_version: str
    last_updated: int | None
    last_updated_iso: str | None
    last_elapsed_ms: float | None
    stale: bool
    stale_reason: str
    schema_stale: bool
    cache_age_sec: float | None
    idb_mtime: float | None
    cache_mtime: float | None
    size_bytes: int
    counts: CacheStats
    error: str


def _current_paths() -> CachePathResult:
    idb_path = ""
    try:
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""
    except Exception:
        idb_path = ""
    if not idb_path:
        try:
            idb_path = idc.get_idb_path() or ""
        except Exception:
            idb_path = ""
    if not idb_path:
        raise RuntimeError("Could not resolve current IDB path")
    return {"idb_path": idb_path, "cache_path": idb_path + ".mcp.sqlite"}


def _connect_rw(cache_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(cache_path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    conn.executescript(SCHEMA_SQL)
    return conn


def _regexp(expr: str, item: str | None) -> int:
    if item is None:
        return 0
    try:
        return 1 if re.search(expr, item, re.IGNORECASE) else 0
    except re.error:
        return 0


def _connect_ro(cache_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{cache_path}?mode=ro", uri=True, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.create_function("REGEXP", 2, _regexp, deterministic=True)
    return conn


def _set_meta(conn: sqlite3.Connection, key: str, value: Any) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
        (key, str(value)),
    )


def _get_meta(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return str(row[0]) if row else default


def _segment_name(ea: int) -> str:
    try:
        seg = idaapi.getseg(ea)
        if not seg:
            return ""
        return idaapi.get_segm_name(seg) or ""
    except Exception:
        return ""


def _xref_type(xref) -> str:
    return "code" if getattr(xref, "iscode", False) else "data"


def _empty_counts() -> CacheStats:
    return {
        "strings": 0,
        "string_xrefs": 0,
        "functions": 0,
        "function_xrefs": 0,
        "function_calls": 0,
        "globals": 0,
        "imports": 0,
    }


def _table_counts(conn: sqlite3.Connection) -> CacheStats:
    counts = _empty_counts()
    for key, table in (
        ("strings", "strings"),
        ("string_xrefs", "string_xrefs"),
        ("functions", "functions"),
        ("function_xrefs", "function_xrefs"),
        ("function_calls", "function_calls"),
        ("globals", "globals"),
        ("imports", "imports"),
    ):
        try:
            row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            counts[key] = int(row[0]) if row else 0
        except sqlite3.Error:
            counts[key] = 0
    return counts


def _collect_import_rows() -> list[tuple[str, int, str, str]]:
    rows: list[tuple[str, int, str, str]] = []
    try:
        nimps = ida_nalt.get_import_module_qty()
    except Exception:
        return rows

    for i in range(nimps):
        module = ida_nalt.get_import_module_name(i) or "<unnamed>"

        def imp_cb(ea, symbol_name, ordinal):
            name = symbol_name or f"#{ordinal}"
            rows.append((hex(ea), int(ea), name, module))
            return True

        try:
            ida_nalt.enum_import_names(i, imp_cb)
        except Exception:
            continue
    return rows


def _collect_cache_data(include_xrefs: bool) -> dict[str, list[tuple]]:
    data: dict[str, list[tuple]] = {
        "strings": [],
        "string_xrefs": [],
        "functions": [],
        "function_xrefs": [],
        "function_calls": [],
        "globals": [],
        "imports": [],
    }

    for s in idautils.Strings():
        if s is None:
            continue
        try:
            ea = int(s.ea)
            text = str(s)
            addr = hex(ea)
            data["strings"].append((addr, ea, text, len(text), _segment_name(ea)))
            if include_xrefs:
                for xref in idautils.XrefsTo(ea, 0):
                    data["string_xrefs"].append(
                        (addr, hex(xref.frm), int(xref.frm), _xref_type(xref))
                    )
        except Exception:
            continue

    for fea in idautils.Functions():
        try:
            fn = idaapi.get_func(fea)
            if not fn:
                continue
            addr = hex(fn.start_ea)
            name = ida_funcs.get_func_name(fn.start_ea) or "<unnamed>"
            size = int(fn.end_ea - fn.start_ea)
            has_type = 1 if ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), fn.start_ea) else 0
            data["functions"].append(
                (addr, int(fn.start_ea), name, size, _segment_name(fn.start_ea), has_type)
            )
            if include_xrefs:
                for xref in idautils.XrefsTo(fn.start_ea, 0):
                    data["function_xrefs"].append(
                        (addr, hex(xref.frm), int(xref.frm), "to", _xref_type(xref))
                    )
                for item_ea in idautils.FuncItems(fn.start_ea):
                    for xref in idautils.XrefsFrom(item_ea, 0):
                        if not getattr(xref, "iscode", False):
                            continue
                        callee = idaapi.get_func(xref.to)
                        if not callee or callee.start_ea == fn.start_ea:
                            continue
                        callee_addr = hex(callee.start_ea)
                        callee_name = ida_funcs.get_func_name(callee.start_ea) or "<unnamed>"
                        data["function_calls"].append(
                            (
                                addr,
                                int(fn.start_ea),
                                name,
                                callee_addr,
                                int(callee.start_ea),
                                callee_name,
                                hex(item_ea),
                                int(item_ea),
                                _xref_type(xref),
                            )
                        )
        except Exception:
            continue

    for ea, name in idautils.Names():
        try:
            if not name or idaapi.get_func(ea):
                continue
            data["globals"].append(
                (hex(ea), int(ea), name, int(idc.get_item_size(ea) or 0), _segment_name(ea))
            )
        except Exception:
            continue

    data["imports"] = _collect_import_rows()
    return data


def _write_cache(cache_path: str, data: dict[str, list[tuple]], elapsed_ms: float) -> CacheStats:
    conn = _connect_rw(cache_path)
    try:
        with conn:
            _set_meta(conn, "status", "building")
            _set_meta(conn, "schema_version", SCHEMA_VERSION)

            for table in (
                "strings",
                "string_xrefs",
                "functions",
                "function_xrefs",
                "function_calls",
                "globals",
                "imports",
            ):
                conn.execute(f"DELETE FROM {table}")

            conn.executemany(
                "INSERT OR REPLACE INTO strings(addr, ea, text, length, segment) VALUES(?,?,?,?,?)",
                data["strings"],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO string_xrefs(str_addr, xref_addr, xref_ea, type) VALUES(?,?,?,?)",
                data["string_xrefs"],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO functions(addr, ea, name, size, segment, has_type) VALUES(?,?,?,?,?,?)",
                data["functions"],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO function_xrefs(func_addr, xref_addr, xref_ea, direction, type) VALUES(?,?,?,?,?)",
                data["function_xrefs"],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO function_calls(caller_addr, caller_ea, caller_name, callee_addr, callee_ea, callee_name, call_addr, call_ea, type) VALUES(?,?,?,?,?,?,?,?,?)",
                data["function_calls"],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO globals(addr, ea, name, size, segment) VALUES(?,?,?,?,?)",
                data["globals"],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO imports(addr, ea, name, module) VALUES(?,?,?,?)",
                data["imports"],
            )

            _set_meta(conn, "status", "ready")
            _set_meta(conn, "last_updated", int(time.time()))
            _set_meta(conn, "last_elapsed_ms", round(elapsed_ms, 2))

        return _table_counts(conn)
    finally:
        conn.close()


def _safe_mtime(path: str) -> float | None:
    try:
        return os.path.getmtime(path)
    except OSError:
        return None


def _parse_schema_version(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _cache_status_for_paths(paths: CachePathResult, max_age_sec: int = 0) -> CacheStatus:
    cache_path = paths["cache_path"]
    idb_mtime = _safe_mtime(paths["idb_path"])
    cache_mtime = _safe_mtime(cache_path)
    now = time.time()
    result: CacheStatus = {
        "exists": os.path.exists(cache_path),
        "ready": False,
        "status": "missing",
        "idb_path": paths["idb_path"],
        "cache_path": cache_path,
        "schema_version": "",
        "last_updated": None,
        "last_updated_iso": None,
        "last_elapsed_ms": None,
        "stale": True,
        "stale_reason": "missing",
        "schema_stale": True,
        "cache_age_sec": None,
        "idb_mtime": idb_mtime,
        "cache_mtime": cache_mtime,
        "size_bytes": os.path.getsize(cache_path) if os.path.exists(cache_path) else 0,
        "counts": _empty_counts(),
    }

    if not result["exists"]:
        return result

    try:
        conn = _connect_ro(cache_path)
        try:
            status = _get_meta(conn, "status", "")
            schema_text = _get_meta(conn, "schema_version", "")
            schema_version = _parse_schema_version(schema_text)
            last_updated_text = _get_meta(conn, "last_updated", "")
            last_elapsed_text = _get_meta(conn, "last_elapsed_ms", "")

            result["status"] = status
            result["ready"] = status == "ready"
            result["schema_version"] = schema_text
            result["schema_stale"] = schema_version != SCHEMA_VERSION
            result["counts"] = _table_counts(conn)

            last_updated = None
            if last_updated_text:
                last_updated = int(float(last_updated_text))
                result["last_updated"] = last_updated
                result["last_updated_iso"] = time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(last_updated)
                )
                result["cache_age_sec"] = round(max(0.0, now - last_updated), 3)
            if last_elapsed_text:
                result["last_elapsed_ms"] = float(last_elapsed_text)

            stale_reason = ""
            if status != "ready":
                stale_reason = f"status:{status or 'unknown'}"
            elif schema_version != SCHEMA_VERSION:
                stale_reason = f"schema:{schema_text or 'missing'}"
            elif idb_mtime is not None and last_updated is not None and idb_mtime > last_updated + 1:
                stale_reason = "idb_newer"
            elif max_age_sec > 0 and last_updated is not None and now - last_updated > max_age_sec:
                stale_reason = "age"

            result["stale"] = bool(stale_reason)
            result["stale_reason"] = stale_reason
        finally:
            conn.close()
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        result["stale"] = True
        result["stale_reason"] = "error"
    return result


def _cache_not_ready(cache_path: str) -> str | None:
    if not os.path.exists(cache_path):
        return f"Cache does not exist: {cache_path}. Run refresh_cache first."
    conn = _connect_ro(cache_path)
    try:
        status = _get_meta(conn, "status")
        if status != "ready":
            return f"Cache is not ready: status={status!r}. Run refresh_cache again."
        schema_version = _parse_schema_version(_get_meta(conn, "schema_version"))
        if schema_version != SCHEMA_VERSION:
            return (
                f"Cache schema is stale: version={schema_version!r}, "
                f"expected={SCHEMA_VERSION}. Run refresh_cache again."
            )
    finally:
        conn.close()
    return None


def _row_to_item(kind: str, row: sqlite3.Row) -> dict[str, Any]:
    if kind == "strings":
        return {
            "kind": "strings",
            "addr": str(row["addr"]),
            "text": str(row["text"]),
            "length": int(row["length"]),
            "segment": str(row["segment"] or ""),
        }
    if kind == "functions":
        return {
            "kind": "functions",
            "addr": str(row["addr"]),
            "name": str(row["name"]),
            "size": int(row["size"]),
            "segment": str(row["segment"] or ""),
            "has_type": bool(row["has_type"]),
        }
    if kind == "globals":
        return {
            "kind": "globals",
            "addr": str(row["addr"]),
            "name": str(row["name"]),
            "size": int(row["size"] or 0),
            "segment": str(row["segment"] or ""),
        }
    return {
        "kind": "imports",
        "addr": str(row["addr"]),
        "name": str(row["name"]),
        "module": str(row["module"] or ""),
    }


def _xrefs_for_string(conn: sqlite3.Connection, addr: str) -> list[dict[str, str]]:
    rows = conn.execute(
        "SELECT xref_addr, type FROM string_xrefs WHERE str_addr=? ORDER BY xref_ea",
        (addr,),
    ).fetchall()
    return [{"addr": str(row["xref_addr"]), "type": str(row["type"])} for row in rows]


def _xrefs_for_function(conn: sqlite3.Connection, addr: str) -> list[dict[str, str]]:
    rows = conn.execute(
        "SELECT xref_addr, type FROM function_xrefs "
        "WHERE func_addr=? AND direction='to' ORDER BY xref_ea",
        (addr,),
    ).fetchall()
    return [{"addr": str(row["xref_addr"]), "type": str(row["type"])} for row in rows]


def _attach_xrefs(
    conn: sqlite3.Connection,
    item: dict[str, Any],
    include_xrefs: bool,
) -> dict[str, Any]:
    if not include_xrefs:
        return item
    if item["kind"] == "strings":
        item["xrefs"] = _xrefs_for_string(conn, item["addr"])
    elif item["kind"] == "functions":
        item["xrefs_to"] = _xrefs_for_function(conn, item["addr"])
    return item


def _parse_addr_text(value: str) -> int | None:
    try:
        return int(value, 0)
    except (TypeError, ValueError):
        return None


def _function_containing_ea(conn: sqlite3.Connection, ea: int) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT addr, name, size, segment, has_type FROM functions "
        "WHERE ea <= ? AND ? < ea + size ORDER BY ea DESC LIMIT 1",
        (ea, ea),
    ).fetchone()
    return _row_to_item("functions", row) if row else None


def _resolve_cache_functions(
    conn: sqlite3.Connection,
    target: str = "",
    name_pattern: str = "",
    limit: int = 50,
) -> list[dict[str, Any]]:
    limit = _clamp_limit(limit, default=50)
    target = (target or "").strip()
    name_pattern = (name_pattern or "").strip()
    rows: list[sqlite3.Row] = []

    if target:
        ea = _parse_addr_text(target)
        if ea is not None:
            row = conn.execute(
                "SELECT addr, name, size, segment, has_type FROM functions "
                "WHERE ea=? OR addr=? LIMIT 1",
                (ea, hex(ea)),
            ).fetchone()
            if row is None:
                fn = _function_containing_ea(conn, ea)
                return [fn] if fn else []
            return [_row_to_item("functions", row)]

        rows = conn.execute(
            "SELECT addr, name, size, segment, has_type FROM functions "
            "WHERE name=? ORDER BY ea LIMIT ?",
            (target, limit),
        ).fetchall()
        if not rows:
            rows = conn.execute(
                "SELECT addr, name, size, segment, has_type FROM functions "
                "WHERE name REGEXP ? ORDER BY ea LIMIT ?",
                (target, limit),
            ).fetchall()
    elif name_pattern:
        rows = conn.execute(
            "SELECT addr, name, size, segment, has_type FROM functions "
            "WHERE name REGEXP ? ORDER BY ea LIMIT ?",
            (name_pattern, limit),
        ).fetchall()

    return [_row_to_item("functions", row) for row in rows]


def _resolve_cache_strings(
    conn: sqlite3.Connection,
    target: str,
    limit: int = 50,
) -> list[dict[str, Any]]:
    limit = _clamp_limit(limit, default=50)
    target = (target or "").strip()
    if not target:
        return []
    ea = _parse_addr_text(target)
    if ea is not None:
        row = conn.execute(
            "SELECT addr, text, length, segment FROM strings WHERE ea=? OR addr=? LIMIT 1",
            (ea, hex(ea)),
        ).fetchone()
        return [_row_to_item("strings", row)] if row else []
    rows = conn.execute(
        "SELECT addr, text, length, segment FROM strings "
        "WHERE text REGEXP ? ORDER BY ea LIMIT ?",
        (target, limit),
    ).fetchall()
    return [_row_to_item("strings", row) for row in rows]


def _edge_from_row(row: sqlite3.Row, depth: int | None = None) -> dict[str, Any]:
    item: dict[str, Any] = {
        "caller": {
            "addr": str(row["caller_addr"]),
            "name": str(row["caller_name"]),
        },
        "callee": {
            "addr": str(row["callee_addr"]),
            "name": str(row["callee_name"]),
        },
        "call_addr": str(row["call_addr"]),
        "type": str(row["type"]),
    }
    if depth is not None:
        item["depth"] = depth
    return item


def _clamp_limit(limit: int, default: int = 100, max_value: int = 1000) -> int:
    if limit <= 0:
        return default
    return min(limit, max_value)


@tool
@idasync
def cache_status(
    max_age_sec: Annotated[
        int,
        "Optional freshness window; >0 marks cache stale when older than this many seconds",
    ] = 0,
) -> CacheStatus:
    """Return status, freshness, and row counts for the current IDB's SQLite cache."""
    try:
        paths = _current_paths()
    except Exception as exc:
        return {"exists": False, "ready": False, "status": "error", "error": str(exc)}

    return _cache_status_for_paths(paths, max_age_sec=max(0, int(max_age_sec)))


@tool
@idasync
@tool_timeout(300.0)
def refresh_cache(
    wait_auto_analysis: Annotated[
        bool,
        "Wait for IDA auto-analysis before collecting cache data",
    ] = True,
    include_xrefs: Annotated[
        bool,
        "Include string/function xrefs in the cache (slower, richer)",
    ] = True,
) -> dict[str, Any]:
    """Rebuild the current IDB's persistent SQLite cache."""
    paths = _current_paths()
    if wait_auto_analysis:
        ida_auto.auto_wait()

    t0 = time.perf_counter()
    data = _collect_cache_data(include_xrefs=include_xrefs)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    counts = _write_cache(paths["cache_path"], data, elapsed_ms)

    return {
        "ok": True,
        "idb_path": paths["idb_path"],
        "cache_path": paths["cache_path"],
        "elapsed_ms": round(elapsed_ms, 2),
        "include_xrefs": include_xrefs,
        "counts": counts,
    }


@tool
@idasync
@tool_timeout(300.0)
def cache_refresh_if_stale(
    max_age_sec: Annotated[
        int,
        "Refresh when cache is older than this many seconds; 0 disables age-based refresh",
    ] = 1800,
    wait_auto_analysis: Annotated[
        bool,
        "Wait for IDA auto-analysis before rebuilding stale cache",
    ] = True,
    include_xrefs: Annotated[
        bool,
        "Include xrefs/callgraph edges when rebuilding stale cache",
    ] = True,
    force: Annotated[bool, "Refresh even when cache is already fresh"] = False,
) -> dict[str, Any]:
    """Refresh the persistent cache only when missing, stale, old, or forced."""
    paths = _current_paths()
    before = _cache_status_for_paths(paths, max_age_sec=max(0, int(max_age_sec)))
    if not force and not before.get("stale", True):
        return {
            "ok": True,
            "refreshed": False,
            "reason": "",
            "status": before,
        }

    if wait_auto_analysis:
        ida_auto.auto_wait()

    t0 = time.perf_counter()
    data = _collect_cache_data(include_xrefs=include_xrefs)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    counts = _write_cache(paths["cache_path"], data, elapsed_ms)
    after = _cache_status_for_paths(paths, max_age_sec=max(0, int(max_age_sec)))
    return {
        "ok": True,
        "refreshed": True,
        "reason": "force" if force else before.get("stale_reason", ""),
        "idb_path": paths["idb_path"],
        "cache_path": paths["cache_path"],
        "elapsed_ms": round(elapsed_ms, 2),
        "include_xrefs": include_xrefs,
        "counts": counts,
        "status": after,
    }


@tool
@idasync
def cache_list_funcs(
    name_pattern: Annotated[
        str,
        "Optional case-insensitive regex over function names",
    ] = "",
    limit: Annotated[int, "Maximum rows to return (max 1000)"] = 200,
    offset: Annotated[int, "Pagination offset"] = 0,
    include_xrefs: Annotated[bool, "Include callers/xrefs_to for each function"] = False,
) -> dict[str, Any]:
    """List functions from the persistent SQLite cache."""
    paths = _current_paths()
    error = _cache_not_ready(paths["cache_path"])
    if error:
        return {"items": [], "total": 0, "offset": offset, "limit": limit, "error": error}

    limit = _clamp_limit(limit, default=200)
    offset = max(0, int(offset))
    conn = _connect_ro(paths["cache_path"])
    try:
        where = ""
        params: tuple[Any, ...] = ()
        if name_pattern:
            where = " WHERE name REGEXP ?"
            params = (name_pattern,)
        total_row = conn.execute(f"SELECT COUNT(*) FROM functions{where}", params).fetchone()
        total = int(total_row[0]) if total_row else 0
        rows = conn.execute(
            f"SELECT addr, name, size, segment, has_type FROM functions{where} "
            "ORDER BY ea LIMIT ? OFFSET ?",
            params + (limit, offset),
        ).fetchall()
        items = [
            _attach_xrefs(conn, _row_to_item("functions", row), include_xrefs)
            for row in rows
        ]
        return {
            "items": items,
            "total": total,
            "offset": offset,
            "limit": limit,
            "source": "sqlite_cache",
        }
    finally:
        conn.close()


@tool
@idasync
def cache_entity_query(
    kind: Annotated[
        str,
        "Entity kind: strings, functions, globals, or imports",
    ],
    pattern: Annotated[
        str,
        "Optional case-insensitive regex over text/name/import module",
    ] = "",
    segment: Annotated[str, "Optional case-insensitive regex over segment"] = "",
    module_pattern: Annotated[str, "Optional regex over import module"] = "",
    limit: Annotated[int, "Maximum rows to return (max 1000)"] = 200,
    offset: Annotated[int, "Pagination offset"] = 0,
    include_xrefs: Annotated[bool, "Include cached xrefs where available"] = False,
) -> dict[str, Any]:
    """Query one entity table from the persistent SQLite cache."""
    kind = (kind or "").strip().lower()
    if kind not in {"strings", "functions", "globals", "imports"}:
        return {
            "items": [],
            "total": 0,
            "offset": offset,
            "limit": limit,
            "error": f"Unsupported kind: {kind!r}",
        }

    paths = _current_paths()
    error = _cache_not_ready(paths["cache_path"])
    if error:
        return {"items": [], "total": 0, "offset": offset, "limit": limit, "error": error}

    table = kind
    text_column = "text" if kind == "strings" else "name"
    select_columns = {
        "strings": "addr, text, length, segment",
        "functions": "addr, name, size, segment, has_type",
        "globals": "addr, name, size, segment",
        "imports": "addr, name, module",
    }[kind]

    clauses: list[str] = []
    params: list[Any] = []
    if pattern:
        if kind == "imports":
            clauses.append("(name REGEXP ? OR module REGEXP ?)")
            params.extend([pattern, pattern])
        else:
            clauses.append(f"{text_column} REGEXP ?")
            params.append(pattern)
    if segment and kind in {"strings", "functions", "globals"}:
        clauses.append("segment REGEXP ?")
        params.append(segment)
    if module_pattern and kind == "imports":
        clauses.append("module REGEXP ?")
        params.append(module_pattern)

    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    limit = _clamp_limit(limit, default=200)
    offset = max(0, int(offset))

    conn = _connect_ro(paths["cache_path"])
    try:
        total_row = conn.execute(
            f"SELECT COUNT(*) FROM {table}{where}",
            tuple(params),
        ).fetchone()
        total = int(total_row[0]) if total_row else 0
        rows = conn.execute(
            f"SELECT {select_columns} FROM {table}{where} ORDER BY ea LIMIT ? OFFSET ?",
            tuple(params) + (limit, offset),
        ).fetchall()
        items = [
            _attach_xrefs(conn, _row_to_item(kind, row), include_xrefs)
            for row in rows
        ]
        return {
            "kind": kind,
            "items": items,
            "total": total,
            "offset": offset,
            "limit": limit,
            "source": "sqlite_cache",
        }
    finally:
        conn.close()


@tool
@idasync
def cache_xrefs(
    target: Annotated[
        str,
        "Function/string address or function name/string regex to resolve inside the cache",
    ],
    kind: Annotated[str, "Target kind: function or string"] = "function",
    direction: Annotated[
        str,
        "For functions: to, from, or both. Strings only support to.",
    ] = "to",
    limit: Annotated[int, "Maximum xrefs to return (max 1000)"] = 200,
    offset: Annotated[int, "Pagination offset across resolved xrefs"] = 0,
) -> dict[str, Any]:
    """Return cached xrefs for a function or string without walking IDA again."""
    kind = (kind or "function").strip().lower()
    direction = (direction or "to").strip().lower()
    if kind not in {"function", "string"}:
        return {"items": [], "total": 0, "error": f"Unsupported kind: {kind!r}"}
    if direction not in {"to", "from", "both"}:
        return {"items": [], "total": 0, "error": f"Unsupported direction: {direction!r}"}

    paths = _current_paths()
    error = _cache_not_ready(paths["cache_path"])
    if error:
        return {"items": [], "total": 0, "offset": offset, "limit": limit, "error": error}

    limit = _clamp_limit(limit, default=200)
    offset = max(0, int(offset))
    conn = _connect_ro(paths["cache_path"])
    try:
        targets = (
            _resolve_cache_functions(conn, target, limit=50)
            if kind == "function"
            else _resolve_cache_strings(conn, target, limit=50)
        )
        items: list[dict[str, Any]] = []

        for resolved in targets:
            if kind == "string":
                rows = conn.execute(
                    "SELECT xref_addr, xref_ea, type FROM string_xrefs "
                    "WHERE str_addr=? ORDER BY xref_ea",
                    (resolved["addr"],),
                ).fetchall()
                for row in rows:
                    caller = _function_containing_ea(conn, int(row["xref_ea"]))
                    items.append(
                        {
                            "kind": "string",
                            "target": resolved,
                            "direction": "to",
                            "xref_addr": str(row["xref_addr"]),
                            "type": str(row["type"]),
                            "function": caller,
                        }
                    )
                continue

            if direction in {"to", "both"}:
                rows = conn.execute(
                    "SELECT xref_addr, xref_ea, type FROM function_xrefs "
                    "WHERE func_addr=? AND direction='to' ORDER BY xref_ea",
                    (resolved["addr"],),
                ).fetchall()
                for row in rows:
                    caller = _function_containing_ea(conn, int(row["xref_ea"]))
                    items.append(
                        {
                            "kind": "function",
                            "target": resolved,
                            "direction": "to",
                            "xref_addr": str(row["xref_addr"]),
                            "type": str(row["type"]),
                            "function": caller,
                        }
                    )

            if direction in {"from", "both"}:
                rows = conn.execute(
                    "SELECT caller_addr, caller_name, callee_addr, callee_name, call_addr, type "
                    "FROM function_calls WHERE caller_addr=? ORDER BY call_ea",
                    (resolved["addr"],),
                ).fetchall()
                for row in rows:
                    items.append(
                        {
                            "kind": "function",
                            "target": resolved,
                            "direction": "from",
                            "callee": {
                                "addr": str(row["callee_addr"]),
                                "name": str(row["callee_name"]),
                            },
                            "call_addr": str(row["call_addr"]),
                            "type": str(row["type"]),
                        }
                    )

        total = len(items)
        return {
            "targets": targets,
            "items": items[offset : offset + limit],
            "total": total,
            "offset": offset,
            "limit": limit,
            "source": "sqlite_cache",
        }
    finally:
        conn.close()


@tool
@idasync
def cache_callgraph(
    target: Annotated[
        str,
        "Optional function address/name. Empty returns cached edges globally.",
    ] = "",
    name_pattern: Annotated[
        str,
        "Optional regex to choose root functions when target is empty",
    ] = "",
    direction: Annotated[str, "calls, callers, or both"] = "both",
    depth: Annotated[int, "Traversal depth from resolved roots (1-5)"] = 1,
    limit: Annotated[int, "Maximum edges to return (max 1000)"] = 200,
    offset: Annotated[int, "Pagination offset"] = 0,
) -> dict[str, Any]:
    """Query cached function callgraph edges with optional bounded traversal."""
    direction = (direction or "both").strip().lower()
    if direction not in {"calls", "callers", "both"}:
        return {"edges": [], "total": 0, "error": f"Unsupported direction: {direction!r}"}

    paths = _current_paths()
    error = _cache_not_ready(paths["cache_path"])
    if error:
        return {"edges": [], "total": 0, "offset": offset, "limit": limit, "error": error}

    limit = _clamp_limit(limit, default=200)
    offset = max(0, int(offset))
    depth = min(5, max(1, int(depth)))
    conn = _connect_ro(paths["cache_path"])
    try:
        roots = _resolve_cache_functions(conn, target, name_pattern=name_pattern, limit=100)
        if not roots and not target and not name_pattern:
            total_row = conn.execute("SELECT COUNT(*) FROM function_calls").fetchone()
            total = int(total_row[0]) if total_row else 0
            rows = conn.execute(
                "SELECT caller_addr, caller_name, callee_addr, callee_name, call_addr, type "
                "FROM function_calls ORDER BY call_ea LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return {
                "roots": [],
                "edges": [_edge_from_row(row) for row in rows],
                "total": total,
                "offset": offset,
                "limit": limit,
                "source": "sqlite_cache",
            }

        frontier = {root["addr"] for root in roots}
        visited_nodes = set(frontier)
        edges_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}

        for level in range(1, depth + 1):
            if not frontier:
                break
            next_frontier: set[str] = set()
            for addr in sorted(frontier):
                if direction in {"calls", "both"}:
                    rows = conn.execute(
                        "SELECT caller_addr, caller_name, callee_addr, callee_name, call_addr, type "
                        "FROM function_calls WHERE caller_addr=? ORDER BY call_ea",
                        (addr,),
                    ).fetchall()
                    for row in rows:
                        key = (str(row["caller_addr"]), str(row["callee_addr"]), str(row["call_addr"]))
                        edges_by_key.setdefault(key, _edge_from_row(row, level))
                        callee_addr = str(row["callee_addr"])
                        if callee_addr not in visited_nodes:
                            next_frontier.add(callee_addr)

                if direction in {"callers", "both"}:
                    rows = conn.execute(
                        "SELECT caller_addr, caller_name, callee_addr, callee_name, call_addr, type "
                        "FROM function_calls WHERE callee_addr=? ORDER BY call_ea",
                        (addr,),
                    ).fetchall()
                    for row in rows:
                        key = (str(row["caller_addr"]), str(row["callee_addr"]), str(row["call_addr"]))
                        edges_by_key.setdefault(key, _edge_from_row(row, level))
                        caller_addr = str(row["caller_addr"])
                        if caller_addr not in visited_nodes:
                            next_frontier.add(caller_addr)

                if len(edges_by_key) >= offset + limit:
                    break
            visited_nodes.update(next_frontier)
            frontier = next_frontier
            if len(edges_by_key) >= offset + limit:
                break

        edges = list(edges_by_key.values())
        return {
            "roots": roots,
            "edges": edges[offset : offset + limit],
            "total": len(edges),
            "offset": offset,
            "limit": limit,
            "depth": depth,
            "direction": direction,
            "truncated": len(edges) >= offset + limit,
            "source": "sqlite_cache",
        }
    finally:
        conn.close()


@tool
@idasync
def cache_callgraph_hotspots(
    sort_by: Annotated[str, "incoming, outgoing, degree, or size"] = "degree",
    name_pattern: Annotated[str, "Optional regex over function names"] = "",
    limit: Annotated[int, "Maximum functions to return (max 1000)"] = 50,
    offset: Annotated[int, "Pagination offset"] = 0,
) -> dict[str, Any]:
    """Rank cached functions by callgraph degree for fast triage."""
    sort_by = (sort_by or "degree").strip().lower()
    if sort_by not in {"incoming", "outgoing", "degree", "size"}:
        sort_by = "degree"

    paths = _current_paths()
    error = _cache_not_ready(paths["cache_path"])
    if error:
        return {"items": [], "total": 0, "offset": offset, "limit": limit, "error": error}

    limit = _clamp_limit(limit, default=50)
    offset = max(0, int(offset))
    where = "WHERE f.name REGEXP ?" if name_pattern else ""
    params: tuple[Any, ...] = (name_pattern,) if name_pattern else ()
    order_expr = {
        "incoming": "incoming DESC, outgoing DESC, f.ea",
        "outgoing": "outgoing DESC, incoming DESC, f.ea",
        "degree": "degree DESC, f.ea",
        "size": "f.size DESC, degree DESC, f.ea",
    }[sort_by]

    conn = _connect_ro(paths["cache_path"])
    try:
        total_row = conn.execute(
            f"SELECT COUNT(*) FROM functions f {where}",
            params,
        ).fetchone()
        total = int(total_row[0]) if total_row else 0
        rows = conn.execute(
            f"""
            WITH incoming AS (
                SELECT callee_addr AS addr, COUNT(*) AS incoming
                FROM function_calls GROUP BY callee_addr
            ),
            outgoing AS (
                SELECT caller_addr AS addr, COUNT(*) AS outgoing
                FROM function_calls GROUP BY caller_addr
            )
            SELECT
                f.addr, f.name, f.size, f.segment, f.has_type,
                COALESCE(incoming.incoming, 0) AS incoming,
                COALESCE(outgoing.outgoing, 0) AS outgoing,
                COALESCE(incoming.incoming, 0) + COALESCE(outgoing.outgoing, 0) AS degree
            FROM functions f
            LEFT JOIN incoming ON incoming.addr = f.addr
            LEFT JOIN outgoing ON outgoing.addr = f.addr
            {where}
            ORDER BY {order_expr}
            LIMIT ? OFFSET ?
            """,
            params + (limit, offset),
        ).fetchall()
        items = [
            {
                **_row_to_item("functions", row),
                "incoming": int(row["incoming"]),
                "outgoing": int(row["outgoing"]),
                "degree": int(row["degree"]),
            }
            for row in rows
        ]
        return {
            "items": items,
            "total": total,
            "offset": offset,
            "limit": limit,
            "sort_by": sort_by,
            "source": "sqlite_cache",
        }
    finally:
        conn.close()


@tool
@idasync
def cache_find_regex(
    pattern: Annotated[
        str,
        "Case-insensitive regex over cached strings/functions/globals/imports",
    ],
    kinds: Annotated[
        str,
        "Comma-separated kinds to search (default: strings,functions,globals,imports)",
    ] = "strings,functions,globals,imports",
    limit: Annotated[int, "Maximum rows to return (max 1000)"] = 100,
    offset: Annotated[int, "Pagination offset across the combined result set"] = 0,
    include_xrefs: Annotated[bool, "Include cached xrefs where available"] = True,
) -> dict[str, Any]:
    """Search the persistent SQLite cache across several entity kinds."""
    try:
        re.compile(pattern)
    except re.error as exc:
        return {"items": [], "total": 0, "offset": offset, "limit": limit, "error": str(exc)}

    requested = [
        item.strip().lower()
        for item in (kinds or "").split(",")
        if item.strip().lower() in {"strings", "functions", "globals", "imports"}
    ]
    if not requested:
        requested = ["strings", "functions", "globals", "imports"]

    paths = _current_paths()
    error = _cache_not_ready(paths["cache_path"])
    if error:
        return {"items": [], "total": 0, "offset": offset, "limit": limit, "error": error}

    limit = _clamp_limit(limit, default=100)
    offset = max(0, int(offset))
    items: list[dict[str, Any]] = []
    total = 0
    skipped = 0

    queries = {
        "strings": (
            "SELECT COUNT(*) FROM strings WHERE text REGEXP ?",
            "SELECT addr, text, length, segment FROM strings WHERE text REGEXP ? ORDER BY ea LIMIT ? OFFSET ?",
        ),
        "functions": (
            "SELECT COUNT(*) FROM functions WHERE name REGEXP ?",
            "SELECT addr, name, size, segment, has_type FROM functions WHERE name REGEXP ? ORDER BY ea LIMIT ? OFFSET ?",
        ),
        "globals": (
            "SELECT COUNT(*) FROM globals WHERE name REGEXP ?",
            "SELECT addr, name, size, segment FROM globals WHERE name REGEXP ? ORDER BY ea LIMIT ? OFFSET ?",
        ),
        "imports": (
            "SELECT COUNT(*) FROM imports WHERE name REGEXP ? OR module REGEXP ?",
            "SELECT addr, name, module FROM imports WHERE name REGEXP ? OR module REGEXP ? ORDER BY ea LIMIT ? OFFSET ?",
        ),
    }

    conn = _connect_ro(paths["cache_path"])
    try:
        for kind in requested:
            count_sql, select_sql = queries[kind]
            params: tuple[Any, ...] = (pattern, pattern) if kind == "imports" else (pattern,)
            row = conn.execute(count_sql, params).fetchone()
            kind_total = int(row[0]) if row else 0
            total += kind_total

            if len(items) >= limit:
                continue
            if skipped + kind_total <= offset:
                skipped += kind_total
                continue

            local_offset = max(0, offset - skipped)
            remaining = limit - len(items)
            rows = conn.execute(
                select_sql,
                params + (remaining, local_offset),
            ).fetchall()
            items.extend(
                _attach_xrefs(conn, _row_to_item(kind, row), include_xrefs)
                for row in rows
            )
            skipped += kind_total

        return {
            "items": items,
            "total": total,
            "offset": offset,
            "limit": limit,
            "kinds": requested,
            "source": "sqlite_cache",
        }
    finally:
        conn.close()
