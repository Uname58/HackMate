# Migration baseline (M0)

Date: 2026-11-02  
Branch observed: `main`

This is a read-only snapshot of the pre-orchestration implementation. It describes code visible in the working tree; it does not claim browser/runtime behavior unless explicitly stated.

## Working tree protection

The repository already had substantial unstaged changes and untracked files before this baseline was added. No staged changes were present at inspection time. Existing changes touch `AGENTS.md`, `CLAUDE.md`, `DESIGN.md`, eval data, `hackmate/cdp.py`, `config.py`, `tools.py`, `web/index.html`, `webui.py`, `memory_project.md`, system prompts, skills, tests, and vendor metadata. Untracked content includes new eval groups, labs, skills, recon memory, and writeups. Do not reset, clean, overwrite, or relocate these as part of migration.

## Current structure and entry points

| Area | Current location | Observed responsibility |
|---|---|---|
| CLI entry | `chat.py`, `hackmate/repl.py` | Conversation loop, slash commands, tool loop, job reporting |
| Web entry | `chat.py web`, `hackmate/webui.py`, `hackmate/web/index.html` | Local UI, session and chat loop; reuses shared tools/context |
| LLM | `hackmate/llm.py` | OpenAI-compatible client |
| Tool boundary | `hackmate/tools.py` | ToolContext, schemas, registry, dispatch, MCP registration |
| Browser | `hackmate/cdp.py` | CDP navigation, page reading, interaction, XSS verification |
| Recon | `hackmate/webui.py` | Same-origin crawling and page/form observations; recon cache in `memorys/recon.json` |
| Background work | `hackmate/jobs.py` | Single worker queue, job status, progress and cooperative cancellation |
| Knowledge | `skills/`, `hackmate/skill.py` | Vulnerability playbooks and skill loading/improvement |
| Evaluation | `evals/`, `hackmate/eval.py`, `grader.py`, `improver.py` | Cases, grader ladder and improvement gate |
| Memory/logging | `memorys/`, `hackmate/memory.py`, `log.py` | Long/project memory and activity logs |
| Vendor tools | `vendor/tools.json`, `hackmate/tools.py` | Tool metadata and shell/MCP integration |

## Reusable / adapter / new work

**Reusable:** existing CDP operations and XSS verification; `enumerate_site` and WebSession recon observations; skill loading; eval/grader and job queue; CLI/Web shared ToolContext and dispatch.

**Needs adapters:** Recon output into a fact-only `ReconResult`; existing tool outputs into typed `ExecutionResult` plus evidence references; existing XSS verification states into the workflow status enum; existing eval data into agent/workflow evals.

**New capabilities required:** contracts and validation; orchestrator/state machine and durable task state; a common scope/permission gate covering built-in, vendor, CDP, recon and MCP paths; raw evidence repository; distinct Analyze/Attacker/Reporter/Commander responsibilities; independent Reporter review; interruption recovery and workflow evals.

## Dependency and configuration notes

`requirements.txt` currently lists only `websocket-client`; the codebase design states other runtime code uses the standard library. Therefore this contract baseline uses JSON Schema documents and does not add Pydantic as a runtime dependency. Configuration is handled in `hackmate/config.py` and environment / `.env` conventions described in `CLAUDE.md`. The inspected code uses JSON/JSONL and files for persistent memory and recon; no existing SQLite task database was identified in the reviewed paths.

## Test baseline

Commands run on 2026-11-02:

- `python tests/test_eval.py` — failed before completing because the Windows GBK console could not encode the test's `✓` output (`UnicodeEncodeError`).
- `PYTHONUTF8=1 python tests/test_eval.py` — passed all grader/eval/gate cases.
- `PYTHONUTF8=1 python tests/test_jobs.py` — passed all job lifecycle/cancellation cases.

These tests cover eval/grader/gate and jobs only. They do not establish Web UI, CDP, recon, MCP, scope enforcement, or browser end-to-end behavior. The baseline is a record of existing test results, not a claim that untested paths work.

## Current architecture gaps

The active chat/tool loop is a single LLM selecting registered tools. Recon exists as a WebSession capability and can also be directed through chat tools, but there is no orchestrated Recon→Analyze→Attacker→Reporter pipeline. ToolContext/dispatch do not provide a central scope/permission decision before each execution. Verify logs and activity logs are not a shared raw evidence repository. There is no durable multi-stage task state or independent Reporter review.

## Migration guardrails

1. Add new contracts/adapters around current code before replacing CLI or Web loops.
2. Keep Reflected XSS as the first vertical slice; do not expand vulnerability scope in M0/M1.
3. Preserve `memorys/`, `skills/`, `tools/`, and `evals/` meanings.
4. Preserve current user changes and avoid unrelated file movement.
5. Treat the current scope gate and evidence repository as absent until implemented and verified.
