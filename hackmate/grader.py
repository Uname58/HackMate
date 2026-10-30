"""判分阶梯 —— v2 的「解假回滚」核心。

v1 用 `expected in output` 纯字面匹配，XSS 等价解无数 → regression 假低分 → gate
「regression 跌就回滚」→ 几乎必然假回滚，闭环根本跑不动。而且评委兜底只在 hidden 生效、
regression 被写死只认字面（还被测试当契约）。

v2 把判一题做成一条阶梯，语义优先，对所有分组（regression + hidden）统一生效：

1. browser（金标准，可选）：case 带可注入的 verify_url 且 CDP 可用 → 真跑看 alert 弹没弹。
2. fast（确定性正向捷径，免 LLM）：候选结构上命中参考解 → 直接判过，省一次评委调用。
                                      只作正向捷径，绝不单独用于判负。
3. judge（语义评委，判分权威）：把「场景 + 参考解 + 原理 + 候选」喂独立评委，问是否真能解决。
                                 onmouseover ≡ onclick 在这里被认成等价。
4. fallback（无评委时向后兼容）：参考解子串匹配。

case schema v2 字段（对 v1 字段做了兼容回退，迁移期两种都能判）：
  context / reference_payload / principle / verify_url / source
  （v1: input / expected / keyword / grader）
"""

from urllib.parse import quote


# ---- 字段兼容读取（v2 优先，回退 v1）----
def ctx(case):
    return case.get("context") or case.get("input") or ""


def reference(case):
    return case.get("reference_payload") or case.get("expected") or ""


def principle(case):
    return case.get("principle") or case.get("keyword") or ""


def _norm(s):
    return "".join((s or "").lower().split())


# ---- 阶梯各级 ----
def fast_match(case, payload):
    """正向捷径：参考解（归一化后）是候选的子串 → True；否则 None（交给评委）。

    只返回 True 或 None，绝不返回 False —— 字面不匹配不代表错（等价解）。
    参考解很长 / 含说明文字时此级基本不命中，自然落到评委。
    """
    ref = _norm(reference(case))
    pay = _norm(payload)
    if ref and len(ref) >= 6 and ref in pay:
        return True
    return None


def _ask(judge, prompt):
    """兼容真 LLMClient(.ask) 与测试 FakeLLM(.ask)。"""
    return judge.ask(prompt).strip()


def _is_negative(verdict):
    """判断评委回答是否否定。返回 True / False / None（None=空/无法判断）。

    评委虽被要求只答「是/否」，但实测会返回变体（不能 / 不行 / No / cannot 等），
    子串匹配「否」会漏掉这些 → 假阳性。故用否定词集合覆盖中英文常见变体。
    """
    v = (verdict or "").strip().lower()
    if not v:
        return None
    neg = ("否", "不能", "不行", "不可以", "不对", "无法", "错误", "错", "假",
           "no", "cannot", "can't", "cant", "false", "incorrect", "wrong", "unable")
    return any(k in v for k in neg)


def judge_consensus(case, payload, judges, vuln=""):
    """多评委共识：任一评委判否定 → False；全未否定 → True；评委异常/空答跳过不误杀。

    judges 空 / None → 返回 None（无法判，交给 fallback）。
    """
    if not judges:
        return None
    prompt = (
        "你是渗透测试的独立评审。判断下面的候选 payload 是否真能解决给定场景"
        f"（真正解决该 {vuln} 漏洞，而不是碰巧字符串匹配）。\n\n"
        f"场景：{ctx(case)}\n"
        f"一个已知可行解（参考，非唯一答案）：{reference(case)}\n"
        f"原理：{principle(case)}\n"
        f"候选 payload：{payload}\n\n"
        "只回答「是」或「否」。"
    )
    any_judged = False
    for j in judges:
        try:
            verdict = _ask(j, prompt)
        except Exception:
            continue  # 评委异常，跳过不误杀
        neg = _is_negative(verdict)
        if neg is None:
            continue  # 空答案，跳过不误判
        any_judged = True
        if neg:
            return False
    return True if any_judged else None


def browser_verify(case, payload, cdp, index=0):
    """金标准：case 带含 {payload} 占位的 verify_url 且 cdp 可用 → 真跑看 alert。

    返回 True/False，或 None（无 verify_url / 无占位 / 无 cdp，跳过此级）。
    """
    url = case.get("verify_url")
    if not url or "{payload}" not in url or cdp is None:
        return None
    try:
        full = url.replace("{payload}", quote(payload, safe=""))
        import json
        res = json.loads(cdp.verify_xss(full, index=index, test_tab=True))
        return res.get("status") == "CONFIRMED"
    except Exception:
        return None  # 真验失败不作数，落到评委


def grade(case, payload, judges=None, cdp=None, index=0, vuln=""):
    """判一题，返回 (ok: bool, how: str)。how ∈ {browser, fast, judge, fallback}。"""
    if not payload:
        return False, "empty"

    b = browser_verify(case, payload, cdp, index)
    if b is not None:
        return b, "browser"

    if fast_match(case, payload) is True:
        return True, "fast"

    v = judge_consensus(case, payload, judges, vuln=vuln)
    if v is not None:
        return v, "judge"

    # 无评委：向后兼容的字面回退
    return (_norm(reference(case)) in _norm(payload)), "fallback"
