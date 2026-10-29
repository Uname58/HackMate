"""候选 skill 生成 —— 用慢模型（深度思考）读整份 skill 产改进候选。

从 v1 的 cli.execute_tool 里拆出来独立成模块，便于单测与替换。
硬性要求写进 system prompt：只写可操作知识，不写定义/影响/防御/工具清单/参考链接。
"""

from .llm import LLMError

_IMPROVER_SYS = (
    "你是 HackMate 的 skill 改进器。skill 是给渗透测试副驾驶用的「判断规则」，不是 payload 字典，也不是教科书。"
    "核心要求：把知识写成「什么信号 → 怎么做」的判断规则（判据、决策步骤、什么情况下停/换思路）。"
    "payload 只是规则的附注——每条规则最多配 1 个最小示例，不要堆一列孤立 payload；payload 靠现场按上下文构造，不背。"
    "硬性禁止：定义（XSS 是什么）、影响（Impact）、防御建议（Defense/CSP/HttpOnly）、工具清单、参考链接。"
    "每个 section 必须「能直接拿去判断」，否则删掉；保持精简，宁短勿长。"
    "只输出改进后的完整 skill 内容（markdown），不要任何解释或代码块标记。"
)


def generate_candidate(cfg, base_client, vuln, variant, current, failures):
    """产一个候选 skill 文本。失败明细反哺（只补通用方法，不硬编码单题答案）。

    反哺信号（相比旧版增强，便于学到可泛化方法而非背答案）：
    - 喂全部失败 case（上限 8），不再只给 3 个。
    - 每个 case 同时给「场景 / 一个可行参考解 / 当前 skill 实际产出的失败 payload」，
      让慢模型看到「差距」在哪，从而提炼覆盖这类场景的通用手法/模板。

    base_client: 主 LLMClient，用 clone 出慢模型、独立上下文的生成器。
    """
    gen = base_client.clone(
        system_prompt=_IMPROVER_SYS,
        model=cfg.get("skill_model", "deepseek-v4-pro"),
        timeout=300,
    )
    prompt = f"当前 {vuln}/{variant} 的 skill 内容：\n\n{current}\n\n"
    if failures:
        prompt += (
            "\n以下 case 当前判分失败，说明 skill 在这些场景有判断缺口。"
            "请对比「参考解」与「失败产出」，找出当前判断规则为何没能引导出可行 payload，"
            "补上能覆盖这类上下文的【判定规则/决策步骤】——提炼成「什么信号 → 怎么做」，"
            "不要把参考解原样抄成 payload 模板：\n"
        )
        for f in failures[:8]:
            prompt += (
                f"- 场景：{f.get('context', '')}\n"
                f"  一个可行参考解：{f.get('reference', '')}\n"
                f"  当前产出（判分失败）：{f.get('actual', '')}\n"
            )
    prompt += "\n请输出改进后的完整 skill 内容。"
    try:
        return gen.ask(prompt)
    except LLMError:
        raise
