<div align="center">
  <img src="assets/readme-banner.svg" width="100%" alt="IDA Pro MCP Fusion — multi-binary reverse engineering through MCP">
</div>

<!-- mcp-name: io.github.rison1337/ida-pro-mcp-fusion -->

<p align="center">
  <a href="https://github.com/rison1337/ida-pro-mcp-fusion/releases/latest"><img src="https://img.shields.io/github/v/release/rison1337/ida-pro-mcp-fusion?style=flat-square&color=5eead4&label=release" alt="Latest release"></a>
  <a href="https://github.com/rison1337/ida-pro-mcp-fusion/actions"><img src="https://img.shields.io/github/actions/workflow/status/rison1337/ida-pro-mcp-fusion/ci.yml?branch=main&style=flat-square&label=tests" alt="Tests"></a>
  <img src="https://img.shields.io/badge/Python-3.11%2B-60a5fa?style=flat-square" alt="Python 3.11 or newer">
  <img src="https://img.shields.io/badge/IDA_Pro-8.3%2B-a78bfa?style=flat-square" alt="IDA Pro 8.3 or newer">
  <img src="https://img.shields.io/badge/MCP-stdio_%7C_HTTP-f59e0b?style=flat-square" alt="MCP over stdio or HTTP">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-e5e7eb?style=flat-square" alt="MIT license"></a>
</p>

<p align="center">
  <strong>One MCP endpoint. Many binaries. Persistent analysis context.</strong>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#why-fusion">Why Fusion</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#tool-surface">Tools</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#development">Development</a>
</p>

## What is Fusion?

**IDA Pro MCP Fusion** connects MCP-compatible coding agents to IDA Pro and turns a single connection into a practical reverse-engineering workspace. It combines live IDA analysis with a persistent SQLite index and a supervisor that can keep several binaries open in isolated headless workers.

Use it to decompile and disassemble functions, trace cross-references, query types, rename symbols, patch data, create signatures, inspect multiple samples, and reuse cached analysis without repeatedly walking IDA's single-threaded APIs.

> [!IMPORTANT]
> This project requires a local, licensed installation of **IDA Pro**. IDA Free is not supported. The server does not provide IDA, Hex-Rays, or a hosted analysis service.

## Why Fusion

| | Capability | What it changes |
|:--:|---|---|
| ⚡ | **Persistent SQLite cache** | Functions, strings, globals, imports, xrefs, and call-graph edges remain queryable across repeated investigations. |
| ◈ | **Multi-binary supervisor** | Open, address, and close several GUI or headless databases through one MCP endpoint. |
| ⛓ | **Persistent workers** | A later supervisor can discover and adopt an existing worker for the same database. |
| ◎ | **Batch-first workflow** | Warm analysis and build caches for a collection of samples with one `idb_batch_open` call. |
| ⛨ | **Controlled surface** | Read-only profiles, opt-in unsafe tools, worker limits, timeouts, and idle cleanup keep automation bounded. |

The cache lives beside the IDB as `<database>.mcp.sqlite`. Freshness is checked against the IDB modification time and cache schema, so stale rows are not silently reused.

## Quick start

### 1. Prerequisites

- [IDA Pro](https://hex-rays.com/ida-pro) 8.3 or newer; IDA 9.x is recommended
- [Python](https://www.python.org/downloads/) 3.11 or newer
- [`uv` / `uvx`](https://docs.astral.sh/uv/)
- Any MCP client that can launch a local stdio server

Install `uv` if it is not available:

```bash
python -m pip install uv
```

Activate IDA's headless Python environment once:

```powershell
# Windows — adjust the IDA version/path if needed
uv run "C:\Program Files\IDA Professional 9.3\idalib\python\py-activate-idalib.py"
```

```bash
# macOS — adjust the IDA version/path if needed
uv run "/Applications/IDA Professional 9.3.app/Contents/MacOS/idalib/python/py-activate-idalib.py"
```

### 2. Add the MCP server

The recommended setup runs the latest code directly from this repository:

```json
{
  "mcpServers": {
    "ida-pro-mcp-fusion": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/rison1337/ida-pro-mcp-fusion",
        "idalib-mcp",
        "--stdio"
      ]
    }
  }
}
```

Claude Code:

```bash
claude mcp add ida-pro-mcp-fusion -- uvx --from git+https://github.com/rison1337/ida-pro-mcp-fusion idalib-mcp --stdio
```

Or download the packaged MCP bundle from the [latest release](https://github.com/rison1337/ida-pro-mcp-fusion/releases/latest).

### 3. Open a database

Ask the connected agent to start with:

```python
idb_open(
    "C:/samples/target.exe",
    preferred_session_id="target",
    build_caches=True,
    init_hexrays=True,
)
```

Every analysis call then names its database explicitly:

```python
survey_binary(database="target")
decompile("main", database="target")
xrefs_to("WinMain", database="target")
cache_callgraph_hotspots(limit=25, database="target")
```

## Architecture

<div align="center">
  <img src="assets/architecture.svg" width="100%" alt="Architecture of IDA Pro MCP Fusion">
</div>

1. Your MCP client starts `idalib-mcp` over stdio or HTTP.
2. The supervisor creates or adopts one worker per binary and enforces the worker limit.
3. Tool calls include a `database` session ID, so requests are routed to the correct IDB.
4. IDA performs live decompilation and mutation work; cache tools serve indexed queries from the sidecar SQLite database.
5. Workers remain discoverable on the host and clean themselves up after their idle TTL.

GUI databases can participate too. `idb_open` supports four routing modes:

| Mode | Behaviour |
|---|---|
| `prefer_headless` | Use or create an idalib worker. This is the default. |
| `force_headless` | Never adopt a running GUI instance. |
| `prefer_gui` | Adopt a matching GUI instance, otherwise create a worker. |
| `force_gui` | Adopt a matching GUI instance or launch IDA GUI. |

## Multi-binary workflow

Open a small collection and keep every session available:

```python
idb_batch_open(
    [
        "C:/samples/loader.exe",
        "C:/samples/payload.dll",
        "C:/samples/helper.dll",
    ],
    session_prefix="case42",
    refresh_cache=True,
    cache_include_xrefs=True,
)
```

For a large corpus, build each cache and release its worker immediately:

```python
idb_batch_open(
    ["C:/corpus/a.exe", "C:/corpus/b.exe", "C:/corpus/c.exe"],
    close_after_cache=True,
    retry_without_auto_analysis_on_timeout=True,
)
```

Useful session controls:

```python
idb_list()
idb_close(database="case42_1_loader")
```

## Tool surface

The codebase registers **75 IDA-facing analysis tools**, plus the supervisor's multi-session controls. The exact number visible to a client intentionally varies: debugger tools are an extension, dangerous operations are disabled unless explicitly enabled, and a profile can expose a smaller allowlist.

| Area | Representative tools |
|---|---|
| Sessions | `idb_open`, `idb_batch_open`, `idb_list`, `idb_close`, `idb_save` |
| Survey & decompilation | `survey_binary`, `decompile`, `disasm`, `analyze_function`, `analyze_component` |
| Search & relationships | `find`, `find_bytes`, `search_text`, `xrefs_to`, `callees`, `callgraph`, `trace_data_flow` |
| Persistent cache | `cache_status`, `refresh_cache`, `cache_entity_query`, `cache_xrefs`, `cache_callgraph_hotspots`, `cache_find_regex` |
| Types & stack | `declare_type`, `type_inspect`, `set_type`, `infer_types`, `stack_frame`, `declare_stack` |
| Database editing | `rename`, `set_comments`, `define_func`, `define_code`, `patch_asm`, `make_data` |
| Signatures | `make_signature`, `make_signature_for_function`, `make_signature_for_range`, `find_xref_signatures` |
| Debugger extension | `dbg_start`, `dbg_bps`, `dbg_regs`, `dbg_stacktrace`, `dbg_read`, `dbg_write` |

The nine cache-specific tools are:

```text
cache_status              refresh_cache
cache_refresh_if_stale    cache_list_funcs
cache_entity_query        cache_xrefs
cache_callgraph           cache_callgraph_hotspots
cache_find_regex
```

## Configuration

### Worker pool

```bash
uvx --from git+https://github.com/rison1337/ida-pro-mcp-fusion \
  idalib-mcp --stdio --max-workers 4
```

| Option / variable | Purpose |
|---|---|
| `--max-workers N` | Maximum simultaneous database workers; `0` means unlimited. Default: `4`. |
| `IDA_MCP_MAX_WORKERS` | Environment default for the worker limit. |
| `IDA_MCP_OPEN_TIMEOUT` | Maximum auto-analysis open time in seconds. Default: `1800`; `0` disables the limit. |
| `IDA_MCP_LOAD_TIMEOUT` | Maximum load-only open time in seconds. Default: `300`; `0` disables the limit. |

### Restricted profiles

Expose only a curated set of tools:

```bash
idalib-mcp --stdio --profile profiles/readonly.txt
```

Two ready-to-use profiles are included:

- [`profiles/readonly.txt`](profiles/readonly.txt) — inspection without mutation tools
- [`profiles/triage.txt`](profiles/triage.txt) — compact first-pass analysis surface

Management tools remain available so sessions can still be opened and inspected.

### HTTP transport

```bash
idalib-mcp --host 127.0.0.1 --port 8745
```

IDA GUI bridge:

```bash
ida-pro-mcp --transport http://127.0.0.1:8744/sse
```

To install the GUI plugin and generate client configuration interactively:

```bash
python -m pip install https://github.com/rison1337/ida-pro-mcp-fusion/archive/refs/heads/main.zip
ida-pro-mcp --install
```

Restart IDA and the MCP client after installation.

## Safety notes

- The server binds to loopback by default. Do not expose it to an untrusted network.
- Mutating and arbitrary-Python tools are marked unsafe and are not enabled by default.
- `py_eval`, `py_exec_file`, debugger controls, and patching operations can execute code or permanently change an IDB. Enable them only for trusted clients and inputs.
- Analyze untrusted binaries inside the same isolation boundary you would use for manual malware analysis.

Enable unsafe worker tools only when the workflow requires them:

```bash
idalib-mcp --stdio --unsafe
```

## Troubleshooting

<details>
<summary><strong><code>uvx</code> is not recognized</strong></summary>

Install `uv` with `python -m pip install uv`, open a new terminal, and confirm with `uvx --version`.
</details>

<details>
<summary><strong>Python / IDA version mismatch</strong></summary>

Run Hex-Rays `idapyswitch`, select a Python 3.11+ installation, then activate idalib again with `py-activate-idalib.py`.
</details>

<details>
<summary><strong>A database call says that <code>database</code> is required</strong></summary>

Call `idb_list()` and pass the returned `session_id` as `database=`. Paths and filenames are not accepted in place of a session ID.
</details>

<details>
<summary><strong>The worker limit has been reached</strong></summary>

Close an unused session with `idb_close`, raise `--max-workers`, or use `close_after_cache=True` for corpus indexing.
</details>

## Development

Clone the repository and run the platform-independent test suite:

```bash
git clone https://github.com/rison1337/ida-pro-mcp-fusion.git
cd ida-pro-mcp-fusion
python -m pip install pytest jsonschema "mcp>=1.0" "tomli-w>=1.0"
python -m pytest -q tests
```

Run the IDA-backed suite in an activated IDA environment:

```bash
uv run ida-mcp-test tests/typed_fixture.elf -q
```

New IDA tools live in `src/ida_pro_mcp/ida_mcp/api_*.py` and register through the `@tool` decorator. Supervisor and worker lifecycle tests live under `tests/`.

## Project identity and credits

**Fusion Edition** is maintained by [rison1337](https://github.com/rison1337).

The project builds on the MIT-licensed [`mrexodia/ida-pro-mcp`](https://github.com/mrexodia/ida-pro-mcp) codebase. Its persistent cache and headless orchestration also incorporate ideas developed in [`QiuChenly/ida-pro-mcp-enhancement`](https://github.com/QiuChenly/ida-pro-mcp-enhancement) and [`winmin/ida-headless-mcp`](https://github.com/winmin/ida-headless-mcp). Attribution is retained here and in the source history; Fusion's packaging, cache tooling, batch workflow, session lifecycle, and public identity are maintained in this repository.

## License

Distributed under the [MIT License](LICENSE). IDA Pro and Hex-Rays are trademarks of Hex-Rays SA and are not included with this project.
