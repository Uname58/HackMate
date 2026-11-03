# Contract and schema conventions (M1)

Schemas use JSON Schema Draft 2020-12. The current implementation uses a fail-closed standard-library validator for the keyword subset in these contracts; it does not add Pydantic or another runtime dependency. Schema validation checks structure only; deterministic policy checks remain separate.

## Envelope

The role result schemas are `recon_result`, `analyze_result`, `attacker_result`, `reporter_result`, and `commander_result`. The current adapters validate each role-specific result directly; task/run IDs and lifecycle metadata are stored alongside it by the Orchestrator. `agent_result.schema.json` records the common envelope for a future transport format. Commander is deterministic Python policy and summary logic, not a fifth free-running LLM.

## Shared models

- `Task`: lifecycle, request metadata and budget references.
- `Target`: canonical target identity, not authorization.
- `Scope`: explicit allowed origins/paths/methods/actions and approval metadata.
- `AgentResult`: versioned stage envelope.
- `Evidence`: immutable artifact index with digest and storage reference.
- `Finding`: Reporter-reviewed finding, keeping hypothesis/verdict separate.
- `Execution`: tool request, gate decision, outcome and evidence references.

Scope Gate re-checks browser requests and redirects and rejects changed DNS answer sets during a task. It does not pin the checked IP at the transport layer, so it is not a complete defense against a DNS change in the interval between the check and connection.

Unknown values should be omitted or represented as `null` where the schema permits; never fill them with guesses. Evidence artifacts remain raw in the local repository for audit. A recursive redaction pass removes common credentials and session values from copies placed in LLM prompts. This is a best-effort filter, not a guarantee that every sensitive value is detected; restrict access to the local evidence directory and review data handling before collection expands.

## Versioning

The schema version is explicit (`1.0.0` for this initial draft). Backward-compatible optional fields may be added in a minor revision. Renaming/removing fields, changing meaning, or tightening accepted values requires a major revision and adapter/migration plan.
