"""eval / grader / gate 功能测试（mock LLM，不烧 API）。

跑法：cd HackMate-v2 && python tests/test_eval.py
"""
import sys
import json
import shutil
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hackmate import skill, grader, eval as ev  # noqa: E402

VULN = "evaltest"
VARIANT = "evaltest"


class FakeLLM:
    """mock：ask 返回固定文本。"""
    def __init__(self, reply):
        self.reply = reply
    def ask(self, prompt):
        return self.reply
    def clear(self):
        pass


def _setup():
    for p in (ev.EVALS_DIR / VULN, skill.vuln_dir(VULN)):
        if p.exists():
            shutil.rmtree(p)
    (ev.EVALS_DIR / VULN).mkdir(parents=True, exist_ok=True)


def _teardown():
    shutil.rmtree(ev.EVALS_DIR / VULN, ignore_errors=True)
    shutil.rmtree(skill.vuln_dir(VULN), ignore_errors=True)


def test_grader_ladder():
    case = {"context": "属性内单引号未转义", "reference_payload": "' onclick='alert(1)",
            "principle": "单引号 breakout"}
    # fast：参考解是候选子串 → 直接过，无需评委
    ok, how = grader.grade(case, "x' onclick='alert(1) y", judges=None)
    assert ok and how == "fast", (ok, how)
    # judge：形式不同但语义等价，评委判「是」
    ok, how = grader.grade(case, "' onmouseover='alert(1)", judges=[FakeLLM("是")])
    assert ok and how == "judge", (ok, how)
    # judge：评委判「否」
    ok, how = grader.grade(case, "完全无关", judges=[FakeLLM("否")])
    assert (not ok) and how == "judge", (ok, how)
    # 无评委 + 非子串 → fallback 判错
    ok, how = grader.grade(case, "完全无关", judges=None)
    assert (not ok) and how == "fallback", (ok, how)
    # 空 payload
    ok, how = grader.grade(case, "", judges=[FakeLLM("是")])
    assert (not ok) and how == "empty", (ok, how)
    # 多评委共识：一否即否
    ok, _ = grader.grade(case, "' onmouseover='alert(1)", judges=[FakeLLM("是"), FakeLLM("否")])
    assert not ok
    print("✓ grader 阶梯（fast 捷径 / judge 等价 / 一否判错 / 无评委 fallback / 空 payload）")


def test_v1_schema_compat():
    """迁移期：仍带 v1 字段的 case 也能判（input/expected/keyword 回退）。"""
    v1case = {"input": "文本节点无过滤", "expected": "<script>alert(1)</script>",
              "keyword": "<script>", "grader": "contains"}
    ok, how = grader.grade(v1case, "<script>alert(1)</script>", judges=None)
    assert ok and how == "fast", (ok, how)
    print("✓ v1 schema 向后兼容（input/expected/keyword 字段回退）")


def test_eval_feedback():
    _setup()
    regression = [{"id": "r1", "context": "场景r1", "reference_payload": "AAA", "principle": "p"}]
    hidden = [{"id": "h1", "context": "场景h1", "reference_payload": "H1", "principle": "p"}]
    (ev.EVALS_DIR / VULN / "regression.json").write_text(json.dumps(regression), encoding="utf-8")
    (ev.EVALS_DIR / VULN / "hidden.json").write_text(json.dumps(hidden), encoding="utf-8")
    # 产 payload 固定返回 "AAA"：r1 fast 命中(含 AAA)，h1 不含 H1 且无评委 → fallback 判错，进 failures
    fn = ev.make_eval_fn(VULN, load_content=lambda: "dummy",
                         produce_client=FakeLLM("AAA"), judges=None, cdp=None,
                         regression_cases=regression, hidden_cases=hidden, trials=1)
    r = fn()
    assert r["regression"] == 1.0, r
    assert r["hidden"] == 0.0, r
    assert len(r["failures"]) == 1 and r["failures"][0]["id"] == "h1", r["failures"]
    assert r["failures"][0]["context"] == "场景h1" and r["failures"][0]["reference"] == "H1"
    _teardown()
    print("✓ eval 打分 + 失败反哺（failures 明细正确，regression/hidden 统一判分）")


def test_round_robin():
    _setup()
    cases = [{"id": f"c{i:02d}", "reference_payload": f"kw{i}", "context": "c"} for i in range(40)]
    (ev.EVALS_DIR / VULN / "hidden.json").write_text(json.dumps(cases), encoding="utf-8")
    seen = []
    for _ in range(4):
        picked = ev.sample_hidden_round(VULN, size=10)
        assert len(picked) == 10
        seen.extend(c["id"] for c in picked)
    assert len(seen) == 40 and len(set(seen)) == 40, "4 轮应覆盖 40 个不重不漏"
    _teardown()
    print("✓ 轮换抽样（4 轮覆盖 40 个不重不漏）")


def _make_eval(before, after):
    state = {"n": 0}
    def fn():
        state["n"] += 1
        return before if state["n"] == 1 else after
    return fn


def test_gate_early_stop():
    _setup()
    skill.write_skill(VULN, VARIANT, "dummy", backup=False)
    kept, _, _ = skill.improve_gate(
        VULN, VARIANT, "x", _make_eval({"regression": 1.0, "hidden": 0.5},
                                        {"regression": 1.0, "hidden": 0.51}))
    assert kept is False, "涨幅 0.5% 应早停回滚"
    kept, _, _ = skill.improve_gate(
        VULN, VARIANT, "y", _make_eval({"regression": 1.0, "hidden": 0.5},
                                       {"regression": 1.0, "hidden": 0.7}))
    assert kept is True, "涨幅 10% 应保留"
    _teardown()
    print("✓ gate 早停（<2% 回滚 / >2% 保留）")


def test_gate_overfit():
    _setup()
    skill.write_skill(VULN, VARIANT, "dummy", backup=False)
    kept, _, _ = skill.improve_gate(
        VULN, VARIANT, "z", _make_eval({"regression": 1.0, "hidden": 0.5},
                                       {"regression": 1.0, "hidden": 0.0}))
    assert kept is False, "hidden 跌超容差应回滚"
    _teardown()
    print("✓ gate 防过拟合（hidden 跌超 5% 回滚）")


def test_gate_regression_drop():
    _setup()
    skill.write_skill(VULN, VARIANT, "dummy", backup=False)
    kept, _, _ = skill.improve_gate(
        VULN, VARIANT, "z", _make_eval({"regression": 0.8, "hidden": 0.5},
                                       {"regression": 0.7, "hidden": 0.9}))
    assert kept is False, "regression 退化应回滚（哪怕 hidden 大涨）"
    _teardown()
    print("✓ gate 防退化（regression 严格跌即回滚）")


if __name__ == "__main__":
    test_grader_ladder()
    test_v1_schema_compat()
    test_eval_feedback()
    test_round_robin()
    test_gate_early_stop()
    test_gate_overfit()
    test_gate_regression_drop()
    print("\n✅ 全部 eval/grader/gate 测试通过")
