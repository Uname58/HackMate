"""skill 系统：漏洞知识的加载 / 写入 / 回滚 + eval gate + 改进编排。

目录：
skills/<vuln>/
├── <vuln>.md        # vuln 层总览
├── <variant>.md     # 类型层（reflection_xss / dom_xss / stored_xss ...）
├── caution.md       # 负向：踩过的坑
└── cases/           # 案例

v2 变化：
- 候选生成拆到 improver.py，判分拆到 eval/grader；本模块只管「存取 + gate + 编排」。
- run_improvement() 把完整改进流程（before 判分 → 产候选 → after 判分 → gate）打包成
  一个可作 Job 跑的函数，解决 v1 improve_skill 阻塞主线程的问题。
- skill 内容只能由 improve_skill 沉淀，绝不人工代写（设定约束，不在代码强制）。
"""

import time
from pathlib import Path

from .config import app_root
from . import eval as ev
from . import improver
from . import log

BASE_DIR = app_root()
SKILLS_DIR = BASE_DIR / "skills"


# ---- 存取 ----
def list_vulns() -> list:
    if not SKILLS_DIR.exists():
        return []
    return sorted(d.name for d in SKILLS_DIR.iterdir() if d.is_dir())


def vuln_dir(vuln: str) -> Path:
    return SKILLS_DIR / vuln


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8") if p.exists() else ""


def load_skill(vuln: str, variant: str = "") -> str:
    """读某 vuln 知识。variant 空 读 overview + 全部 variant + caution（全量，eval 判分用）；
    variant 指定则只读 overview + 该 variant + caution（按需，打靶用）。"""
    d = vuln_dir(vuln)
    if not d.exists():
        return ""
    parts = []
    overview = d / f"{vuln}.md"
    if overview.exists():
        parts.append(f"# {vuln.upper()} overview\n{_read(overview)}")
    if variant:
        vf = d / f"{variant}.md"
        if not vf.exists():
            return ""
        parts.append(f"# {variant}\n{_read(vf)}")
    else:
        for f in sorted(d.glob("*.md")):
            if f.name in (f"{vuln}.md", "caution.md"):
                continue
            parts.append(f"# {f.stem}\n{_read(f)}")
    caution = d / "caution.md"
    if caution.exists():
        parts.append(f"# caution（坑 / 预警）\n{_read(caution)}")
    return "\n\n".join(parts)


def load_overview(vuln: str) -> str:
    """只读某 vuln 的 overview（轻量总纲），供程序兜底注入；variant 详细靠 load_skill 按需读。"""
    d = vuln_dir(vuln)
    overview = d / f"{vuln}.md"
    return f"# {vuln.upper()} overview\n{_read(overview)}" if overview.exists() else ""


def get_variant_path(vuln: str, variant: str) -> Path:
    return vuln_dir(vuln) / f"{variant}.md"


def write_skill(vuln: str, variant: str, content: str, backup: bool = True) -> str:
    """写 / 更新 skill 文件。默认先备份到 backups/（.bak-时间戳）。"""
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
    """回滚到最近一次备份。"""
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


# ---- eval gate ----
def improve_gate(vuln, variant, new_content, eval_fn,
                 before=None, hidden_tolerance=0.05, early_stop=0.02):
    """写新内容 → 记后分 → 退化/过拟合/涨幅太小则回滚。返回 (kept, before, after)。

    回滚条件：
    - regression 退化（严格跌）—— 已知能力不能丢
    - hidden 过拟合（跌幅 > hidden_tolerance）—— 容忍 LLM 随机波动
    - 早停（综合分涨幅 < early_stop）—— 边际收益太小不值得改
    """
    if before is None:
        before = eval_fn()
    write_skill(vuln, variant, new_content, backup=True)
    try:
        after = eval_fn()
    except Exception:
        rollback_skill(vuln, variant)
        raise

    reg_drop = (before.get("regression") is not None and after.get("regression") is not None
                and after["regression"] < before["regression"])
    hid_drop = False
    if before.get("hidden") is not None and after.get("hidden") is not None:
        hid_drop = after["hidden"] < before["hidden"] - hidden_tolerance

    def _avg(s):
        vals = [v for v in (s.get("regression"), s.get("hidden")) if v is not None]
        return sum(vals) / len(vals) if vals else None

    bt, at = _avg(before), _avg(after)
    early = (bt is not None and at is not None and (at - bt) < early_stop)

    if reg_drop or hid_drop or early:
        rollback_skill(vuln, variant)
        return False, before, after
    return True, before, after


def _fmt_score(s):
    parts = []
    if s.get("regression") is not None:
        parts.append(f"regression {s['regression']:.0%}")
    if s.get("hidden") is not None:
        parts.append(f"hidden {s['hidden']:.0%}")
    return "[" + ", ".join(parts) + "]" if parts else "N/A"


# ---- 完整改进编排（作为 Job 跑）----
def run_improvement(job, cfg, base_client, vuln, variant, cdp=None,
                    hidden_sample=10, dev_sample=10, trials=1):
    """before 判分 → 产候选 → after 判分 → gate。供 JobManager.submit 调用。

    训练/考试隔离（防背题）：
    - 改进只看 dev 集（可见训练集）的失败来反哺 improver；dev 空则无反哺，纯泛化精炼。
    - gate 的 before/after 只在 regression + hidden（留出考卷）上判分，improver 从不见这两组。
    这样「变强」= 在 improver 没见过的题上真的涨，而非记住喂进去的答案。

    job: Job 实例，用于报进度 + 协作式取消。base_client: 主 LLMClient（clone 出判分/评委/生成器）。
    返回结果字符串（Job.result）。
    """
    vpath = get_variant_path(vuln, variant)
    is_new = not vpath.exists()

    dev = ev.sample_round(vuln, "dev", size=dev_sample)  # 训练集（轮换抽样，improver 可见）
    regression = ev.load_group(vuln, "regression")
    hidden = ev.sample_hidden_round(vuln, size=hidden_sample)
    degraded = False
    if not regression and not hidden:
        # 非 xss vuln 冷启动：没有留出考卷（regression/hidden），降级用 dev 判分。
        # improver 见过 dev，防背题弱、判分偏乐观，但至少能跑 gate 改 skill；留出考卷攒够后自动走正路。
        if not dev:
            return f"{vuln} 没有任何 case，无法 eval 判分"
        regression = dev
        degraded = True

    current = vpath.read_text(encoding="utf-8") if vpath.exists() else ""

    # 产 payload 用快模型（空 system、独立上下文）；评委用快模型（独立评审 system）
    produce_client = base_client.clone(system_prompt="", model=cfg["model"])
    judges = [base_client.clone(
        system_prompt="你是渗透测试的独立评审，客观判断 payload 是否真的解决给定场景。",
        model=cfg["model"])]

    # 留出考卷：gate 只在 regression + hidden 上判分
    eval_fn = ev.make_eval_fn(
        vuln, load_content=lambda: load_skill(vuln),
        produce_client=produce_client, judges=judges, cdp=cdp,
        regression_cases=regression, hidden_cases=hidden, trials=trials, job=job)

    job.set_progress("诊断判分（before，留出集 regression+hidden）...")
    before = eval_fn()
    job.check_cancel()

    # 训练反哺：只从 dev（improver 可见）采失败喂 improver，考卷 case 绝不外泄
    dev_failures = []
    if dev:
        job.set_progress("采集 dev 训练集失败明细...")
        _, dev_failures = ev.score_group(
            dev, load_skill(vuln), produce_client, judges, cdp, trials, "dev", job, vuln)
        job.check_cancel()

    job.set_progress(f"生成候选（针对 {min(len(dev_failures), 3)} 个 dev 失败 case）...")
    candidate = improver.generate_candidate(
        cfg, base_client, vuln, variant, current, dev_failures)
    job.check_cancel()

    job.set_progress("验收判分（after）+ gate ...")
    kept, before, after = improve_gate(vuln, variant, candidate, eval_fn, before=before)

    tag = "发现" if is_new else "优化"
    if kept:
        log.record("skill", action=tag, vuln=vuln, variant=variant)
        verb = "已保留"
    else:
        verb = "已回滚"
    note = "（降级判分：留出考卷不足，用 dev 判分，防背题弱）" if degraded else ""
    return f"{tag} skill '{vuln}/{variant}'：{_fmt_score(before)} → {_fmt_score(after)}，{verb}{note}"
