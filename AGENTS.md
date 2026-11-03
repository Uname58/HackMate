# HackMate v4 agent instructions

## Project context
- Read `CLAUDE.md` for the project's architecture, design constraints, and established implementation decisions.
- Read `memory_project.md` when you need the latest handoff status or pending work. Treat it as a potentially stale snapshot; verify current behavior and status against the code, Git state, and available evidence.
- Consult `README.md` and `DESIGN.md` for usage and detailed design.

## Working rules
- Preserve the project's human-in-the-loop and evidence-driven approach. Follow the user's stated scope and authorization for any security testing.
- Before editing, inspect `git status` and relevant diffs. Preserve existing user changes; do not overwrite or clean unrelated work.
- Keep implementation consistent with the hard constraints and design decisions in `CLAUDE.md`. If a requested change conflicts with them, explain the conflict and follow the user's request.
- Do not claim a behavior is verified unless supported by actual test or runtime evidence. Distinguish static inspection from execution and browser validation.
- Update `memory_project.md` when meaningful project status or handoff details change, while retaining still-valid context and marking completed or superseded items.

## Formal next-architecture baseline (2026-11-02)
- The project target is the five-role Hybrid Multi-Agent architecture: Recon, Analyze, Attacker, Reporter, Commander, coordinated by a Python Orchestrator and fixed versioned JSON Schema contracts.
- Follow Contract-first → Orchestrator → Reflected XSS vertical slice → Evaluation → expansion. Reflected XSS is the first slice; long-term technical coverage includes SQLi, CMDi, information disclosure and WordPress component vulnerabilities.
- M0 baseline and M1 contract drafts are recorded in `docs/architecture/` and `schemas/`; an initial orchestration, gate, evidence repository, CLI/Web workflow and offline Eval foundation now exist. A controlled localhost fixture completed through real Chrome/CDP with a fake role client; real-model behavior and a user-authorized target remain unverified.
- New architecture modules are grouped under `hackmate/agents/`, `orchestrator/`, `security/`, `evidence/`, and `workflow/`. The active Attacker adapter is Reflected XSS only; SQLi, CMDi, information disclosure and WordPress component/CVE testing remain planned adapters.
- Scope Gate request counts and DNS observations are shared across a task's stages and persisted for recovery. Preserve this invariant when changing task wiring or retry behavior.
- Research candidates must pass source-evidence, same-task raw request/response, browser, CDP or tool validation evidence, Eval, explicit human approval, and the existing Skill Eval gate before promotion; do not wire Research directly to formal `skills/` writes.
- Preserve the existing `memorys/`, `skills/`, `tools/`, and `evals/` responsibilities. Use adapter modules and avoid unrelated moves.
- The current working tree may contain user changes. Never reset, clean, or overwrite unrelated work; inspect status and diffs before editing.
- The workflow tool path passes through a Scope / Permission Gate, and Reporter independently loads referenced original evidence. LLM prompt copies receive best-effort secret redaction; local originals remain raw. Do not claim full security or end-to-end verification from static inspection alone.
- Reporter accepts only sufficiently reviewed, reproducible findings with false-positive checks; accepted findings persist as schema-checked Finding and redacted Writeup evidence.
- Attacker asks for one tool action per round, checks it against both the active adapter and Analyze's named capabilities, and preserves each execution's raw evidence. The current XSS Reporter gate requires raw request and response evidence tied to the same endpoint and input value plus a CDP JavaScript execution event. Reporter feedback can trigger a bounded Analyze/Attacker/Reporter retry; uncertain interrupted attacks are not replayed.
- Workflow XSS verification state is task-scoped. A cached result from another task cannot confirm a finding without that task's raw evidence. Evidence records are validated against `schemas/evidence.schema.json` when stored and loaded.

---

<!-- Project handoff/status lives in memory_project.md — read it directly; do not maintain a duplicate snapshot here. -->
