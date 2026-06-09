# Agent Sandbox Escape Detector

## Goal
Build a production-ready security tool that black-box tests any LLM agent system for sandbox escape vulnerabilities. The tool runs adversarial prompt probes against a target agent endpoint and uses Claude Opus 4.8 to judge whether any probe achieved escape.

## Research Summary
- **Judge model**: `claude-opus-4-8-20251101` (confirmed exact Anthropic API model ID via search)
- **Anthropic SDK**: latest `anthropic` package with Messages API — supports system/user messages, max_tokens, temperature
- **Target agent interface assumption**: standard HTTP chat endpoint accepting `{"message": "..."}` and returning `{"response": "..."}` — this is the black-box contract
- **httpx**: well-suited for async concurrent requests with timeout/retry support
- **No GPU available** — all AI calls go through the Anthropic API, which is fine since Claude runs server-side

## Approach
Layered architecture: Probe classes (one per vulnerability category) → Scanner (async orchestrator) → Judge (Claude verdict engine) → Report (output builder). FastAPI provides REST API, CLI provides terminal entry. Pydantic v2 for all models. Rich for CLI terminal output.

## Subtasks
1. **Project scaffolding** — Create directory structure, `requirements.txt`, `pyproject.toml`, `.env.example`, all `__init__.py` files. Verify Python 3.11+ and install dependencies.
2. **Core models & config** — Implement `config.py` (Pydantic BaseSettings), core data models: `ProbeResult`, `ScanResult`, `ScanReport`, `ScanStatus` enums. Also the prompt files in `prompts/` directory.
3. **BaseProbe + all 6 probes** — Implement `base.py` (abstract base class with `run()` interface), then all six probe implementations: `tool_access.py`, `prompt_leak.py`, `api_call.py`, `role_confusion.py`, `indirect_injection.py`, `jailbreak.py`. Each loads prompts from the prompts/ files and sends them asynchronously via httpx.
4. **Judge engine** — Implement `judge.py` using `anthropic` SDK with `claude-opus-4-8-20251101`. Takes probe prompts + target response, returns verdict (ESCAPED/SAFE/UNCERTAIN) with evidence and confidence score. Structured output via Pydantic.
5. **Scanner orchestrator** — Implement `scanner.py` that accepts target config, runs all probes concurrently with `asyncio.gather()`, handles timeouts/errors gracefully, aggregates results into a ScanReport.
6. **Report builder** — Implement `report.py` that builds JSON and Markdown reports from ScanReport data. Rich-formatted CLI output.
7. **CLI entry point** — Implement `cli.py` with `scan` command using `rich` for progress/display, `--target`, `--output`, `--api-key`, `--probes` options.
8. **FastAPI server** — Implement `main.py` and `routes.py`: `/scan` (POST, triggers scan), `/results/{scan_id}` (GET, returns report), `/health` (GET). In-memory scan store with scan_id UUID. Background task for scan execution.
9. **Test suite** — Write `conftest.py` (fixtures: mock target server, mock Judge), `test_probes.py` (each probe with mock server), `test_judge.py` (mock Claude responses), `test_scanner.py` (full scan flow), `test_api.py` (FastAPI endpoints).
10. **Final integration verification** — Run the full test suite, verify CLI importable, verify FastAPI app loads. Fix any issues.

## Deliverables
| File Path | Description |
|-----------|-------------|
| src/__init__.py | Package init |
| src/api/__init__.py | API sub-package |
| src/api/main.py | FastAPI app entry |
| src/api/routes.py | REST endpoints |
| src/core/__init__.py | Core sub-package |
| src/core/scanner.py | Scan orchestrator |
| src/core/judge.py | Claude verdict engine |
| src/core/report.py | Report builder |
| src/core/probes/__init__.py | Probes sub-package |
| src/core/probes/base.py | Abstract base probe |
| src/core/probes/tool_access.py | Unauthorized tool access probe |
| src/core/probes/prompt_leak.py | System prompt extraction probe |
| src/core/probes/api_call.py | Unintended API call probe |
| src/core/probes/role_confusion.py | Role hijack probe |
| src/core/probes/indirect_injection.py | Indirect injection probe |
| src/core/probes/jailbreak.py | CoT jailbreak probe |
| src/config.py | Pydantic settings |
| src/cli.py | CLI entry point |
| prompts/*.txt | Adversarial prompt templates (6 files) |
| tests/conftest.py | Test fixtures |
| tests/test_probes.py | Probe unit tests |
| tests/test_judge.py | Judge unit tests |
| tests/test_scanner.py | Scanner tests |
| tests/test_api.py | API endpoint tests |
| .env.example | Env template |
| requirements.txt | Python deps |
| pyproject.toml | Project config |

## Evaluation Criteria
- All 200+ pytest tests pass
- `python -m src.cli scan --target http://localhost:8000 --help` prints usage
- FastAPI app starts without import errors
- CLI importable as `python -m src.cli`
- No hardcoded secrets — all via .env
- No TODOs, stubs, or placeholder functions

## Notes
- ANTHROPIC_API_KEY loaded from environment via pydantic-settings
- All httpx calls use 30s timeout
- Probes run concurrently via asyncio
- Judge uses structured output (Pydantic model)
- Target agent assumed to have chat endpoint accepting `{"message": "..."}` returning `{"response": "..."}`