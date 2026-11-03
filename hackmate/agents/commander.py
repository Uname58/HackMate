"""Deterministic Commander summary and user-facing next-step decision."""
import json

from ..schema_validation import SCHEMA_DIR, validate


def summarize_task(task_id, reporter, task_status):
    verdict = reporter.get("verdict") or "missing"
    if verdict not in {"accepted", "rejected", "needs_more_evidence", "missing"}:
        verdict = "missing"
    if task_status in {"BLOCKED", "FAILED", "CANCELLED"}:
        next_action = "none"
        summary = f"任务{ {'BLOCKED': '被权限范围阻止', 'FAILED': '执行失败', 'CANCELLED': '已取消'}[task_status] }。"
    elif task_status == "PARTIAL" or verdict == "missing":
        next_action = "manual_review"
        summary = "任务未完整结束，需人工检查阶段结果和证据。"
    elif verdict == "accepted":
        next_action = "completed"
        summary = "Reporter 已接受发现；请查看复现步骤和证据引用。"
    elif verdict == "rejected":
        next_action = "completed"
        summary = "Reporter 未接受该漏洞假设；本轮测试已完成。"
    else:
        next_action = "request_more_evidence"
        summary = "Reporter 认为证据不足；需要补充测试或证据后再判断。"
    result = {"schema_version": "1.0.0", "task_id": task_id, "agent": "commander",
              "status": task_status, "reporter_verdict": verdict,
              "next_action": next_action, "summary": summary}
    schema = json.loads((SCHEMA_DIR / "commander_result.schema.json").read_text(encoding="utf-8"))
    validate(result, schema)
    return result
