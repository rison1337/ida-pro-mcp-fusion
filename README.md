<a id="english"></a>

<div align="center">
  <img src="assets/readme-banner.svg" width="100%" alt="IDA Pro MCP Fusion — multi-binary reverse engineering through MCP">
</div>

<!-- mcp-name: io.github.rison1337/ida-pro-mcp-fusion -->

<p align="center">
  <a href="#english"><img alt="English — selected" src="assets/language/en-active.svg" height="38"></a>&nbsp;<a href="#русский"><img alt="Открыть русскую версию" src="assets/language/ru-inactive.svg" height="38"></a>
</p>

<p align="center">
  <a href="https://github.com/rison1337/ida-pro-mcp-fusion/releases/latest"><img src="https://img.shields.io/github/v/release/rison1337/ida-pro-mcp-fusion?style=flat-square&color=7c6cf2&label=release" alt="Latest release"></a>
  <a href="https://github.com/rison1337/ida-pro-mcp-fusion/actions"><img src="https://img.shields.io/github/actions/workflow/status/rison1337/ida-pro-mcp-fusion/ci.yml?branch=main&style=flat-square&label=tests" alt="Tests"></a>
  <img src="https://img.shields.io/badge/Python-3.11%2B-45d7ff?style=flat-square" alt="Python 3.11 or newer">
  <img src="https://img.shields.io/badge/IDA_Pro-8.3%2B-8b7cf6?style=flat-square" alt="IDA Pro 8.3 or newer">
  <img src="https://img.shields.io/badge/MCP-stdio_%7C_HTTP-ff6b8a?style=flat-square" alt="MCP over stdio or HTTP">
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

---

<a id="русский"></a>

# Русский

<p align="center">
  <a href="#english"><img alt="Open English version" src="assets/language/en-inactive.svg" height="38"></a>&nbsp;<a href="#русский"><img alt="Русский — выбран" src="assets/language/ru-active.svg" height="38"></a>
</p>

<p align="center">
  <strong>Одна MCP-точка. Много бинарников. Контекст анализа сохраняется.</strong>
</p>

<p align="center">
  <a href="#быстрый-старт">Быстрый старт</a> ·
  <a href="#почему-fusion">Почему Fusion</a> ·
  <a href="#архитектура">Архитектура</a> ·
  <a href="#инструменты">Инструменты</a> ·
  <a href="#настройка">Настройка</a>
</p>

## Что такое Fusion?

**IDA Pro MCP Fusion** подключает MCP-совместимых агентов к IDA Pro и превращает одно соединение в полноценное рабочее место для реверсинга. Живой анализ IDA объединён с постоянным SQLite-индексом и supervisor-процессом, который может держать несколько бинарников в изолированных headless-воркерах.

Можно декомпилировать и дизассемблировать функции, исследовать перекрёстные ссылки, типы и граф вызовов, переименовывать символы, патчить данные, создавать сигнатуры и повторно использовать уже построенный анализ.

> [!IMPORTANT]
> Нужна локальная лицензированная установка **IDA Pro**. IDA Free не поддерживается. Сервер не содержит IDA, Hex-Rays и не отправляет бинарники во внешний сервис.

## Почему Fusion

| | Возможность | Что это даёт |
|:--:|---|---|
| ⚡ | **Постоянный SQLite-кэш** | Функции, строки, глобальные переменные, импорты, xref и call graph доступны между запусками. |
| ◈ | **Мульти-бинарный supervisor** | Несколько GUI- или headless-баз управляются через одну MCP-точку. |
| ⛓ | **Живущие воркеры** | Следующее подключение может найти и принять уже запущенный worker для той же базы. |
| ◎ | **Пакетный анализ** | Открытие образцов и построение кэшей выполняется одним `idb_batch_open`. |
| ⛨ | **Контролируемый интерфейс** | Read-only-профили, лимит воркеров, тайм-ауты и opt-in для опасных инструментов. |

Кэш лежит рядом с IDB в файле `<database>.mcp.sqlite`. Актуальность проверяется по времени изменения IDB и версии схемы, поэтому устаревшие данные не выдаются незаметно.

## Быстрый старт

### 1. Что понадобится

- [IDA Pro](https://hex-rays.com/ida-pro) 8.3 или новее; рекомендуется IDA 9.x
- [Python](https://www.python.org/downloads/) 3.11 или новее
- [`uv` / `uvx`](https://docs.astral.sh/uv/)
- MCP-клиент, который умеет запускать локальный stdio-сервер

Установите `uv`, если его ещё нет:

```bash
python -m pip install uv
```

Один раз активируйте headless Python от IDA:

```powershell
# Windows — при необходимости измените версию и путь к IDA
uv run "C:\Program Files\IDA Professional 9.3\idalib\python\py-activate-idalib.py"
```

```bash
# macOS — при необходимости измените версию и путь к IDA
uv run "/Applications/IDA Professional 9.3.app/Contents/MacOS/idalib/python/py-activate-idalib.py"
```

### 2. Добавьте MCP-сервер

Рекомендуемая конфигурация запускает код напрямую из этого репозитория:

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

Для Claude Code:

```bash
claude mcp add ida-pro-mcp-fusion -- uvx --from git+https://github.com/rison1337/ida-pro-mcp-fusion idalib-mcp --stdio
```

Готовый MCPB-пакет доступен в [последнем релизе](https://github.com/rison1337/ida-pro-mcp-fusion/releases/latest).

### 3. Откройте базу

Попросите подключённого агента начать так:

```python
idb_open(
    "C:/samples/target.exe",
    preferred_session_id="target",
    build_caches=True,
    init_hexrays=True,
)
```

Каждый следующий вызов анализа получает явный ID базы:

```python
survey_binary(database="target")
decompile("main", database="target")
xrefs_to("WinMain", database="target")
cache_callgraph_hotspots(limit=25, database="target")
```

## Архитектура

<div align="center">
  <img src="assets/architecture-ru.svg" width="100%" alt="Архитектура IDA Pro MCP Fusion">
</div>

1. MCP-клиент запускает `idalib-mcp` через stdio или HTTP.
2. Supervisor создаёт или принимает по одному worker-процессу на каждый бинарник.
3. Каждый вызов содержит `database`, поэтому запрос попадает в нужную IDB-сессию.
4. IDA выполняет живой анализ и изменения, а cache-инструменты читают индекс из SQLite.
5. Воркеры остаются обнаруживаемыми на компьютере и завершаются после периода простоя.

`idb_open` поддерживает четыре режима:

| Режим | Поведение |
|---|---|
| `prefer_headless` | Использовать или создать idalib-worker. Режим по умолчанию. |
| `force_headless` | Не принимать запущенный GUI-процесс. |
| `prefer_gui` | Принять подходящий GUI, а если его нет — создать worker. |
| `force_gui` | Принять GUI или запустить новый процесс IDA. |

## Работа с несколькими бинарниками

Открыть несколько образцов и оставить все сессии доступными:

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

Для большого корпуса можно построить кэш и сразу освободить worker:

```python
idb_batch_open(
    ["C:/corpus/a.exe", "C:/corpus/b.exe", "C:/corpus/c.exe"],
    close_after_cache=True,
    retry_without_auto_analysis_on_timeout=True,
)
```

Управление сессиями:

```python
idb_list()
idb_close(database="case42_1_loader")
```

## Инструменты

В кодовой базе зарегистрировано **75 инструментов анализа IDA**, а supervisor добавляет управление мульти-бинарными сессиями. Видимый клиенту список намеренно меняется: debugger-инструменты являются расширением, опасные операции отключены без явного разрешения, а профиль может оставить только выбранные имена.

| Область | Примеры |
|---|---|
| Сессии | `idb_open`, `idb_batch_open`, `idb_list`, `idb_close`, `idb_save` |
| Обзор и декомпиляция | `survey_binary`, `decompile`, `disasm`, `analyze_function`, `analyze_component` |
| Поиск и связи | `find`, `find_bytes`, `search_text`, `xrefs_to`, `callees`, `callgraph`, `trace_data_flow` |
| Постоянный кэш | `cache_status`, `refresh_cache`, `cache_entity_query`, `cache_xrefs`, `cache_callgraph_hotspots`, `cache_find_regex` |
| Типы и стек | `declare_type`, `type_inspect`, `set_type`, `infer_types`, `stack_frame`, `declare_stack` |
| Изменение базы | `rename`, `set_comments`, `define_func`, `define_code`, `patch_asm`, `make_data` |
| Сигнатуры | `make_signature`, `make_signature_for_function`, `make_signature_for_range`, `find_xref_signatures` |
| Debugger-расширение | `dbg_start`, `dbg_bps`, `dbg_regs`, `dbg_stacktrace`, `dbg_read`, `dbg_write` |

## Настройка

### Пул воркеров

```bash
uvx --from git+https://github.com/rison1337/ida-pro-mcp-fusion \
  idalib-mcp --stdio --max-workers 4
```

| Параметр / переменная | Назначение |
|---|---|
| `--max-workers N` | Максимум одновременно работающих баз; `0` — без лимита. По умолчанию `4`. |
| `IDA_MCP_MAX_WORKERS` | Значение лимита по умолчанию из окружения. |
| `IDA_MCP_OPEN_TIMEOUT` | Максимальное время автоанализа при открытии в секундах. По умолчанию `1800`. |
| `IDA_MCP_LOAD_TIMEOUT` | Максимальное время загрузки без автоанализа. По умолчанию `300`. |

### Ограниченные профили

Оставить только выбранные инструменты:

```bash
idalib-mcp --stdio --profile profiles/readonly.txt
```

- [`profiles/readonly.txt`](profiles/readonly.txt) — просмотр без инструментов изменения
- [`profiles/triage.txt`](profiles/triage.txt) — компактный набор для первичного анализа

### HTTP

```bash
idalib-mcp --host 127.0.0.1 --port 8745
```

GUI-мост:

```bash
ida-pro-mcp --transport http://127.0.0.1:8744/sse
```

Для установки GUI-плагина:

```bash
python -m pip install https://github.com/rison1337/ida-pro-mcp-fusion/archive/refs/heads/main.zip
ida-pro-mcp --install
```

После установки перезапустите IDA и MCP-клиент.

## Безопасность

- По умолчанию сервер слушает только loopback. Не открывайте его в недоверенную сеть.
- Изменяющие и произвольные Python-инструменты помечены как unsafe и выключены по умолчанию.
- `py_eval`, `py_exec_file`, debugger-команды и патчинг могут выполнять код или менять IDB.
- Непроверенные бинарники анализируйте в той же изоляции, что и при ручном malware analysis.

Включить unsafe-инструменты можно явно:

```bash
idalib-mcp --stdio --unsafe
```

## Решение проблем

<details>
<summary><strong><code>uvx</code> не найден</strong></summary>

Установите `uv` командой `python -m pip install uv`, откройте новый терминал и проверьте `uvx --version`.
</details>

<details>
<summary><strong>Несовместимая версия Python или IDA</strong></summary>

Запустите `idapyswitch`, выберите Python 3.11+, затем снова выполните `py-activate-idalib.py`.
</details>

<details>
<summary><strong>Ошибка о том, что нужен <code>database</code></strong></summary>

Вызовите `idb_list()` и передайте возвращённый `session_id` как `database=`. Пути и имена файлов вместо ID сессии не принимаются.
</details>

<details>
<summary><strong>Достигнут лимит воркеров</strong></summary>

Закройте неиспользуемую сессию через `idb_close`, увеличьте `--max-workers` или используйте `close_after_cache=True`.
</details>

## Разработка

```bash
git clone https://github.com/rison1337/ida-pro-mcp-fusion.git
cd ida-pro-mcp-fusion
python -m pip install pytest jsonschema "mcp>=1.0" "tomli-w>=1.0"
python -m pytest -q tests
```

Для тестов, которым нужна сама IDA:

```bash
uv run ida-mcp-test tests/typed_fixture.elf -q
```

Новые инструменты находятся в `src/ida_pro_mcp/ida_mcp/api_*.py` и регистрируются через `@tool`. Тесты supervisor и lifecycle — в `tests/`.

## Проект и авторство

**Fusion Edition** поддерживается [rison1337](https://github.com/rison1337).

Проект основан на MIT-кодовой базе [`mrexodia/ida-pro-mcp`](https://github.com/mrexodia/ida-pro-mcp). Постоянный кэш и headless-оркестрация также используют идеи из [`QiuChenly/ida-pro-mcp-enhancement`](https://github.com/QiuChenly/ida-pro-mcp-enhancement) и [`winmin/ida-headless-mcp`](https://github.com/winmin/ida-headless-mcp). Атрибуция сохранена в README и истории исходников; упаковка Fusion, cache-инструменты, batch workflow и lifecycle сессий поддерживаются в этом репозитории.

## Лицензия

Проект распространяется по [MIT License](LICENSE). IDA Pro и Hex-Rays — товарные знаки Hex-Rays SA и не входят в состав проекта.
