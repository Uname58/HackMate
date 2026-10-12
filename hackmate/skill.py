"""skill 系统：漏洞知识的加载 / 生成 / 改进。

目录结构：
skills/<vuln>/                # 一个 vuln 大类一个目录（xss / sqli / cmdi ...）
├── <vuln>.md                 # vuln 层总览（是什么、几大类、通用测试框架）
├── <variant>.md              # 类型层（reflection_xss / dom_xss / stored_xss ...）
├── caution.md                # 负向：踩过的坑 / 预警（别踩什么）
└── cases/                    # 案例（yyyy-mm-dd-which-attack.txt）
"""

import time
from pathlib import Path

from .config import app_root
from .llm import LLMError

BASE_DIR = app_root()  # HackMate 根目录
SKILLS_DIR = BASE_DIR / "skills"


def list_vulns() -> list:
    """列出所有 vuln 大类（skills/ 下的目录）。"""
    if not SKILLS_DIR.exists():
        return []
    return sorted(d.name for d in SKILLS_DIR.iterdir() if d.is_dir())


def vuln_dir(vuln: str) -> Path:
    return SKILLS_DIR / vuln


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8") if p.exists() else ""


def load_skill(vuln: str) -> str:
    """读某个 vuln 大类的全部知识（vuln 层 + 各类型层 + caution），拼成上下文。"""
    d = vuln_dir(vuln)
    if not d.exists():
        return ""
    parts = []
    overview = d / f"{vuln}.md"
    if overview.exists():
        parts.append(f"# {vuln.upper()} overview\n{_read(overview)}")
    for f in sorted(d.glob("*.md")):
        if f.name in (f"{vuln}.md", "caution.md"):
            continue
        parts.append(f"# {f.stem}\n{_read(f)}")
    caution = d / "caution.md"
    if caution.exists():
        parts.append(f"# caution（坑 / 预警）\n{_read(caution)}")
    return "\n\n".join(parts)


def get_variant_path(vuln: str, variant: str) -> Path:
    return vuln_dir(vuln) / f"{variant}.md"


def write_skill(vuln: str, variant: str, content: str, backup: bool = True) -> str:
    """写 / 更新某个 skill 文件。默认先备份到 backups/（.bak-时间戳）。"""
    p = get_variant_path(vuln, variant)
    p.parent.mkdir(parents=True, exist_ok=True)
    if backup and p.exists():
        bak_dir = p.parent / "backups"
        bak_dir.mkdir(parents=True, exist_ok=True)
        bak = bak_dir / f"{variant}.md.bak-{time.strftime('%Y%m%d%H%M%S')}"
        bak.write_text(_read(p), encoding="utf-8")
    p.write_text(content, encoding="utf-8")
    return str(p)


def rollback_skill(vuln: str, variant: str) -> bool:
    """回滚到最近一次备份（从 backups/ 目录）。"""
    p = get_variant_path(vuln, variant)
    bak_dir = p.parent / "backups"
    baks = sorted(bak_dir.glob(f"{variant}.md.bak-*")) if bak_dir.exists() else []
    if not baks:
        return False
    latest = baks[-1]
    p.write_text(latest.read_text(encoding="utf-8"), encoding="utf-8")
    latest.unlink()
    return True


def summary() -> str:
    """返回所有 vuln 大类的简短目录摘要（用于拼进 system prompt）。"""
    vulns = list_vulns()
    if not vulns:
        return ""
    lines = ["可用漏洞知识（skills/）："]
    for v in vulns:
        d = vuln_dir(v)
        variants = [f.stem for f in d.glob("*.md") if f.name not in (f"{v}.md", "caution.md")]
        line = f"- {v}: " + ", ".join(sorted(variants)) if variants else f"- {v}"
        if (d / "caution.md").exists():
            line += " + caution"
        lines.append(line)
    return "\n".join(lines)


def make_skill_eval_fn(vuln: str, cases: list, llm_client=None, trials: int = 2):
    """返回 eval_fn，用于 improve_skill 的 eval gate。

    - 思路 B（llm_client 提供）：把 skill 喂给 LLM，针对每个 case 的 input 产 payload，
      再对 expected 判分。每个 case 跑 trials 次取成功率（消除 LLM 随机性）。
    - 思路 A（llm_client=None）：完整性检查（keyword 覆盖）—— 防退化，粗粒度。
    """
    if llm_client is not None:
        from .eval import grade_case, record_transcript

        def eval_fn():
            content = load_skill(vuln)
            if not cases:
                return 0.0
            passed = total = 0
            consecutive_failures = 0
            for i, c in enumerate(cases, 1):
                for _ in range(trials):
                    llm_client.clear()
                    prompt = (
                        "你是渗透测试专家。根据以下漏洞知识：\n\n"
                        f"{content}\n\n"
                        f"针对场景：{c.get('input', '')}\n\n"
                        "只输出一个 XSS payload，不要任何解释或代码块。"
                    )
                    try:
                        payload = llm_client.chat(prompt)["content"].strip()
                        ok = grade_case(c, payload)
                        consecutive_failures = 0
                    except Exception as e:
                        payload = f"<error: {e}>"
                        ok = False
                        consecutive_failures += 1
                    total += 1
                    if ok:
                        passed += 1
                    record_transcript(vuln, c, payload, ok)
                    if consecutive_failures >= 3:
                        raise LLMError(f"LLM 连续 {consecutive_failures} 次调用失败，eval 中止")
                print(f"  [eval] {i}/{len(cases)} {c.get('id', '?')} 判分完成")
            return passed / total if total else 0.0

        return eval_fn

    def eval_fn():
        content = load_skill(vuln)
        if not cases:
            return 0.0
        passed = 0
        for c in cases:
            kw = c.get("keyword") or c.get("expected", "")
            if kw and kw in content:
                passed += 1
        return passed / len(cases)

    return eval_fn


def improve_skill(vuln: str, variant: str, new_content: str, eval_fn):
    """改进 skill，带 eval gate。

    eval_fn: 无参回调，返回当前 skill 的 eval 分数（数值，越高越好）。
    流程：记前分 → 写新内容 → 记后分 → 分数跌则回滚。
    返回 (kept: bool, score_before, score_after)。
    """
    before = eval_fn()
    write_skill(vuln, variant, new_content, backup=True)
    try:
        after = eval_fn()
    except Exception:
        rollback_skill(vuln, variant)
        raise
    if after < before:
        rollback_skill(vuln, variant)
        return False, before, after
    return True, before, after
