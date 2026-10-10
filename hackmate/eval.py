"""eval 裁判：case 集 → grader → 总分。

这是 HackMate 的「裁判」——验证 skill 更新 / payload 生成有没有用，防止黑箱盲改。

case 格式（JSON 数组）：
[
  {
    "id": "xss-labs-L1",
    "input": "反射点落在 <h2> 文本节点，无过滤",
    "expected": "<script>alert(1)</script>",
    "grader": "contains"
  }
]

grader 类型（从便宜到贵）：
- contains : 输出里必须包含 expected（子串匹配）
- regex    : expected 是正则，输出匹配即对
- browser  : 用 CDP 真跑，验证 alert 弹没弹（需外部注入 grader 回调）
"""

import json
import re
import time
from pathlib import Path

from .config import app_root

BASE_DIR = app_root()  # HackMate 根目录
EVALS_DIR = BASE_DIR / "evals"


def load_cases(path) -> list:
    """加载 JSON case 集。支持裸数组或 {"cases": [...]}。"""
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    return data.get("cases", [])


def load_group(vuln: str, group: str) -> list:
    """按分组加载 case：evals/<vuln>/<group>.json。

    group ∈ {smoke, dev, regression, hidden}：
    - smoke:      验证 runner 能跑（最小 case）
    - dev:        开发集，模型可看，用于改进 skill
    - regression: 回归集，每次改动都跑，检查已知能力没退化
    - hidden:     隐藏集，不向改进模型公开，检查泛化（预留）
    """
    return load_cases(EVALS_DIR / vuln / f"{group}.json")


def grade_case(case: dict, output: str) -> bool:
    """判一题，返回 True/False。"""
    gt = case.get("grader", "contains")
    expected = case.get("expected", "")
    if gt == "contains":
        return expected in (output or "")
    if gt == "regex":
        return re.search(expected, output or "") is not None
    if gt == "browser":
        raise NotImplementedError("browser grader 需通过 run_eval(grader=...) 注入外部 CDP 回调")
    return False


def run_eval(cases: list, produce_output, grader=None):
    """跑全量 case，返回 (通过数, 总数, 详情列表)。

    produce_output: 输入 case["input"]，返回 HackMate 的输出文本。
    grader: 可选，覆盖默认 grade_case（用于 browser grader 注入 CDP）。
    """
    g = grader or grade_case
    passed = 0
    details = []
    for c in cases:
        try:
            out = produce_output(c.get("input", ""))
            ok = g(c, out)
        except Exception as e:  # 单题异常不拖垮整轮
            ok = False
            out = f"<error: {e}>"
        if ok:
            passed += 1
        details.append({"id": c.get("id", "?"), "ok": ok, "output": out})
    return passed, len(cases), details


def format_report(passed: int, total: int, details: list) -> str:
    """把结果格式化成可读报告。"""
    lines = [f"eval 结果：{passed}/{total} 通过"]
    for d in details:
        mark = "✓" if d["ok"] else "✗"
        lines.append(f"  {mark} {d['id']}")
    return "\n".join(lines)


def record_transcript(vuln: str, case: dict, payload: str, ok: bool) -> None:
    """把一次判分追加到 transcript（JSONL），用于失败根因定位。"""
    p = EVALS_DIR / vuln / "transcripts" / f"{time.strftime('%Y%m%d')}.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    entry = json.dumps({
        "id": case.get("id", "?"),
        "input": case.get("input", ""),
        "payload": payload,
        "ok": ok,
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
    }, ensure_ascii=False)
    with open(p, "a", encoding="utf-8") as f:
        f.write(entry + "\n")


def append_case(vuln: str, group: str, case: dict) -> str:
    """把一个 case 追加到 evals/<vuln>/<group>.json，返回状态描述。"""
    p = EVALS_DIR / vuln / f"{group}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    cases = load_cases(p) if p.exists() else []
    cases.append(case)
    p.write_text(json.dumps(cases, ensure_ascii=False, indent=2), encoding="utf-8")
    return f"case 已沉淀进 {group} 集（当前 {len(cases)} 个）"
