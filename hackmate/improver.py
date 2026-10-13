"""候选 skill 生成 —— 用慢模型（深度思考）读整份 skill 产改进候选。

从 v1 的 cli.execute_tool 里拆出来独立成模块，便于单测与替换。
硬性要求写进 system prompt：只写可操作知识，不写定义/影响/防御/工具清单/参考链接。
"""

from .llm import LLMError

_IMPROVER_SYS = (
    "你是 HackMate 的 skill 改进器。skill 是给渗透测试副驾驶用的「可操作知识」，不是教科书。"
    "硬性要求：只写可操作的测试方法 / 绕过手法 / payload 模板 / 踩过的坑；"
    "不写定义（XSS 是什么）、影响（Impact）、防御建议（Defense/CSP/HttpOnly）、工具清单、参考链接；"
    "每个 section 必须「能直接拿去用」，否则删掉；保持精简，宁短勿长。"
    "只输出改进后的完整 skill 内容（markdown），不要任何解释或代码块标记。"
)


def generate_candidate(cfg, base_client, vuln, variant, current, failures):
    """产一个候选 skill 文本。失败明细反哺（只补通用方法，不硬编码单题答案）。

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
            "\n以下 case 当前判分失败，说明 skill 在这些场景有缺口，"
            "请针对性补充（只补通用方法，不要硬编码单题答案）：\n"
        )
        for f in failures[:3]:
            prompt += f"- 场景：{f.get('context', '')}\n  参考答案：{f.get('reference', '')}\n"
    prompt += "\n请输出改进后的完整 skill 内容。"
    try:
        return gen.ask(prompt)
    except LLMError:
        raise
