# HackMate Agent Contracts (M1 draft)

These are role contracts, not five free-running LLM conversations. Python owns stage order and validates each output. Agents receive only the structured task data and evidence references needed for their role. All schemas are drafts under `schemas/`; changes require compatible versioning.

## Vulnerability coverage

The architecture is not XSS-only. Reflected XSS is the first end-to-end slice. Planned technical domains include SQL injection, command injection, information disclosure, and authorized WordPress crack-in through core, plugin, theme, or other component CVEs. Here, WordPress crack-in means scoped vulnerability validation; it does not imply password guessing. Each domain should add its own skills, bounded Attacker adapter, evidence rules, and Eval cases while reusing these shared contracts. The current executable Attacker adapter supports Reflected XSS only; other hypothesis types are blocked until their adapters are implemented and evaluated.

## Shared rules

- Contract envelope: `schema_version`, `task_id`, `agent`, `status`, `started_at`, `completed_at`, `input_refs`, `output`, `errors`.
- Timestamps are RFC 3339 date-time strings. IDs are opaque stable strings.
- `unknown` or an empty collection means unknown/not observed; never turn missing data into a fact.
- Every material observation or conclusion references evidence where available.
- Agent results are proposals/evidence, not authorization. Only the deterministic gate may authorize a tool action.
- Stage states: `pending`, `running`, `completed`, `partial`, `blocked`, `failed`, `cancelled`.

## Recon — fact collection

**Input:** Task, Target, approved Scope, collection policy.  
**Output:** `ReconResult` with target identity; technologies and infrastructure as observations with confidence/evidence; endpoints; parameters with location; authentication state; observations; limitations; evidence refs.  
**Must not:** label a vulnerability confirmed, infer a vulnerability solely from a parameter name, or exceed scope.  
**Handoff:** factual inventory to Analyze.

## Analyze — hypotheses and test plan

**Input:** `ReconResult`, approved scope, applicable skill references and task budget.  
**Output:** `AnalyzeResult` with attack surface, input point, one or more hypotheses, rationale/evidence refs, priority, ordered test steps, expected evidence, constraints and limitations.  
**Must:** distinguish hypotheses from findings; state uncertainty; make steps executable through named tool capabilities.  
**Must not:** execute tools or grant permissions.  
**Handoff:** plan to Commander for policy validation, then Attacker.

## Attacker — bounded execution

**Input:** validated test plan, approved scope/capabilities, budgets, selected skills.  
**Output:** `AttackerResult` with test/hypothesis IDs; execution status; payloads; execution/evidence IDs; observed browser events; result state (`CONFIRMED`, `NOT_CONFIRMED`, `INCONCLUSIVE`, `BLOCKED`, `ERROR`); reason and limitations.  
**Must:** request one tool action per round; the tool must be both allowlisted by the selected adapter and named in Analyze's plan. Execute through the Tool Gateway, preserve each attempt and its raw evidence, and stay within the task's attack-round budget. Apply the selected adapter's evidence rules (for XSS, absence of a browser execution signal is insufficient to disprove execution).  
**Must not:** rescan independently, alter scope, or assert a final finding.  
**Handoff:** result and evidence references to Reporter.

## Reporter — independent evidence review

**Input:** AttackerResult plus direct read access to referenced immutable raw evidence, scope and review rubric.  
**Output:** `ReporterResult` with verdict (`accepted`, `rejected`, `needs_more_evidence`), structured finding details, reproduction steps, evidence reviewed, target/input linkage, reproducibility, impact assessment, false-positive checks, optional CVSS/vector, Finding and Writeup evidence references, and rejection/limitations.  
**Must:** independently inspect raw request/response and relevant browser/CDP evidence; distinguish application behavior from tool behavior. Accept only when required evidence was loaded and reviewed, reproduction is repeatable, and false-positive checks are recorded. For the current Reflected XSS adapter this includes a raw request and response tied to the same endpoint and parameter value, plus a raw CDP JavaScript execution event. Leave CVSS empty when evidence is insufficient. The current text Reporter cannot visually inspect screenshot artifacts and must disclose that limitation. Accepted findings get a schema-checked Finding record and a locally stored Writeup with best-effort redacted evidence excerpts.  
**Must not:** accept solely from Attacker's conclusion.  
**Handoff:** reviewed result to Commander.

## Commander — user-facing task control

Commander is the only user-facing role. In the current vertical slice, deterministic Python owns legal state transitions, scope checks, budgets, persistence, retries, cancellation and the structured Commander summary. Commander policy may select only allowed next actions or ask for intervention; it cannot bypass Reporter or the permission gate. This role does not require a separate LLM instance.

**Input:** user request, task state, stage results, budget and policy decisions.  
**Output:** user updates, constrained scheduling decision, intervention request, or final summary.  
**Must:** keep task status and progress accurate; expose uncertainty and blocked reasons; avoid forwarding unneeded secrets or raw evidence into prompts.

## Handoffs

`Commander creates task → Scope validation → Recon → Analyze → plan/policy validation → Attacker → Reporter → Commander summary`.

Only explicit, validated retry edges may return to a previous stage. All retry edges preserve prior attempts and evidence. No path skips scope validation or Reporter review for a claimed finding. User-approved scope changes create a new recorded scope revision.
