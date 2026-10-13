"""eval 裁判：case 集 → 产 payload → 判分阶梯 → 总分。

验证 skill 改进 / payload 生成有没有用，防黑箱盲改。

分组（evals/<vuln>/<group>.json）：
- smoke:      验证 runner 能跑（最小 case）
- dev:        开发集，模型可看
- regression: 回归集，每次改动都跑，查已知能力没退化（case 少 → trials 消随机性）
- hidden:     隐藏集，跨来源防过拟合（case 多 → 轮换抽样，1 trial）

v2 变化：
- 判分走 grader 阶梯（语义评委对所有分组统一生效，不再是 hidden 专属）。
- case schema v2（context / reference_payload / principle / verify_url / source）。
- 与 skill 解耦：通过 load_content 回调拿当前 skill 文本，不 import skill（避免循环）。
- 支持 Job：score_group 吃一个可选 job，逐 case 报进度 + 协作式取消。
"""

import json
import random
import time
from pathlib import Path

from .config import app_root
from .llm import LLMError
from . import grader

BASE_DIR = app_root()
EVALS_DIR = BASE_DIR / "evals"


# ---- case 存取 ----
def load_cases(path) -> list:
    p = Path(path)
    if not p.exists():
        return []
    data = json.loads(p.read_text(encoding="utf-8"))
    return data if isinstance(data, list) else data.get("cases", [])


def load_group(vuln: str, group: str) -> list:
    return load_cases(EVALS_DIR / vuln / f"{group}.json")


def append_case(vuln: str, group: str, case: dict) -> str:
    """把一个 case 追加到 evals/<vuln>/<group>.json（schema v2）。"""
    p = EVALS_DIR / vuln / f"{group}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    cases = load_cases(p) if p.exists() else []
    cases.append(case)
    p.write_text(json.dumps(cases, ensure_ascii=False, indent=2), encoding="utf-8")
    return f"case 已沉淀进 {group} 集（当前 {len(cases)} 个）"


def record_transcript(vuln: str, case: dict, payload: str, ok: bool, how: str = "") -> None:
    p = EVALS_DIR / vuln / "transcripts" / f"{time.strftime('%Y%m%d')}.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    entry = json.dumps({
        "id": case.get("id", "?"),
        "context": grader.ctx(case),
        "payload": payload,
        "ok": ok,
        "how": how,
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
    }, ensure_ascii=False)
    with open(p, "a", encoding="utf-8") as f:
        f.write(entry + "\n")


def sample_hidden_round(vuln: str, size: int = 10) -> list:
    """从 hidden 集洗牌轮换抽样：每轮取 size 个，size 次调用恰好覆盖一遍，轮完重洗。

    状态持久化到 evals/<vuln>/hidden_round.json（order + round）。case 数量变化自动重洗。
    """
    cases = load_group(vuln, "hidden")
    if len(cases) <= size:
        return cases
    state_path = EVALS_DIR / vuln / "hidden_round.json"
    order, round_idx = [], 0
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            order = state.get("order", [])
            round_idx = state.get("round", 0)
        except (json.JSONDecodeError, OSError):
            order, round_idx = [], 0
    if len(order) != len(cases):
        order = list(range(len(cases)))
        random.shuffle(order)
        round_idx = 0
    n_rounds = (len(cases) + size - 1) // size
    start = round_idx * size
    end = min(start + size, len(cases))
    picked = [cases[order[i]] for i in range(start, end)]
    round_idx = (round_idx + 1) % n_rounds
    if round_idx == 0:
        random.shuffle(order)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps({"order": order, "round": round_idx}), encoding="utf-8")
    return picked


# ---- 判分 ----
_PRODUCE_PROMPT = (
    "你是渗透测试专家。根据以下漏洞知识：\n\n{content}\n\n"
    "针对场景：{context}\n\n"
    "只输出一个 XSS payload，不要任何解释或代码块。"
)


def score_group(cases, content, produce_client, judges, cdp, trials, tag, job=None, vuln=""):
    """跑一组 case，返回 (score, failures)。

    content: 当前 skill 文本（本轮固定）。produce_client: 产 payload 的 LLM（独立上下文）。
    judges: 评委列表。cdp: 浏览器（可为 None）。trials: 每题跑几次取成功率。
    job: 可选，用于报进度 + check_cancel。vuln: 仅用于 transcript 落盘。
    """
    if not cases:
        return None, []
    passed = total = 0
    consecutive_failures = 0
    failures = []
    for i, c in enumerate(cases, 1):
        if job is not None:
            job.check_cancel()
            job.set_progress(f"{tag} {i}/{len(cases)} {c.get('id', '?')}")
        last_payload, last_ok = "", False
        for _ in range(trials):
            prompt = _PRODUCE_PROMPT.format(content=content, context=grader.ctx(c))
            try:
                payload = produce_client.ask(prompt)
                ok, how = grader.grade(c, payload, judges=judges, cdp=cdp)
                consecutive_failures = 0
            except LLMError:
                payload, ok, how = "<llm-error>", False, "error"
                consecutive_failures += 1
            except Exception as e:
                payload, ok, how = f"<error: {e}>", False, "error"
            if vuln:
                record_transcript(vuln, c, payload, ok, how)
            total += 1
            if ok:
                passed += 1
            last_payload, last_ok = payload, ok
            if consecutive_failures >= 3:
                raise LLMError(f"LLM 连续 {consecutive_failures} 次调用失败，eval 中止")
        if not last_ok:
            failures.append({
                "id": c.get("id", "?"),
                "group": tag,
                "context": grader.ctx(c),
                "reference": grader.reference(c),
                "actual": last_payload,
            })
    return (passed / total if total else 0.0), failures


def make_eval_fn(vuln, load_content, produce_client, judges, cdp,
                 regression_cases, hidden_cases, trials=1, job=None):
    """构造 eval_fn()，返回 {regression, hidden, failures}。

    load_content: 无参回调，返回当前 skill 文本（before/after 之间会变，需每次重读）。
    """
    def eval_fn():
        content = load_content()
        reg_score, reg_fails = score_group(
            regression_cases, content, produce_client, judges, cdp, trials, "regression", job, vuln)
        hid_score, hid_fails = score_group(
            hidden_cases, content, produce_client, judges, cdp, 1, "hidden", job, vuln)
        return {
            "regression": reg_score,
            "hidden": hid_score,
            "failures": (reg_fails or []) + (hid_fails or []),
        }
    return eval_fn
