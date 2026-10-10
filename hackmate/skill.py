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

BASE_DIR = Path(__file__).resolve().parent.parent  # HackMate 根目录
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
    """写 / 更新某个 skill 文件。默认先备份（.bak-时间戳）。"""
    p = get_variant_path(vuln, variant)
    p.parent.mkdir(parents=True, exist_ok=True)
    if backup and p.exists():
        bak = p.with_suffix(p.suffix + f".bak-{time.strftime('%Y%m%d%H%M%S')}")
        bak.write_text(_read(p), encoding="utf-8")
    p.write_text(content, encoding="utf-8")
    return str(p)


def rollback_skill(vuln: str, variant: str) -> bool:
    """回滚到最近一次备份。"""
    p = get_variant_path(vuln, variant)
    baks = sorted(p.parent.glob(f"{variant}.md.bak-*"))
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


def improve_skill(vuln: str, variant: str, new_content: str, eval_fn):
    """改进 skill，带 eval gate。

    eval_fn: 无参回调，返回当前 skill 的 eval 分数（数值，越高越好）。
    流程：记前分 → 写新内容 → 记后分 → 分数跌则回滚。
    返回 (kept: bool, score_before, score_after)。
    """
    before = eval_fn()
    write_skill(vuln, variant, new_content, backup=True)
    after = eval_fn()
    if after < before:
        rollback_skill(vuln, variant)
        return False, before, after
    return True, before, after
