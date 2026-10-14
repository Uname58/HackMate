"""通过 OpenAI 兼容的 Chat Completions API 与另一个 Agent 对话。

Agent 端点单独配置，不会复用 HackMate 主模型的上下文，也不会自动发送消息。
调用方应在用户明确要求时调用 ``AgentLink.ask()``。
"""

import json
import os
import urllib.error
import urllib.request


class AgentLinkError(Exception):
    """连接 Agent 或解析其回复时发生错误。"""


class AgentLink:
    def __init__(self, base_url, api_key, model, timeout=45,
                 system_prompt="你是与 HackMate 协作的 AI Agent。请直接回答收到的问题。"):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.system_prompt = system_prompt

    @classmethod
    def from_env(cls):
        """从 HACKMATE_AGENT_* 环境变量读取独立 Agent 配置。"""
        base_url = os.environ.get("HACKMATE_AGENT_BASE_URL", "").strip()
        model = os.environ.get("HACKMATE_AGENT_MODEL", "").strip()
        api_key = os.environ.get("HACKMATE_AGENT_API_KEY", "").strip()
        if not base_url or not model:
            raise AgentLinkError(
                "缺少 Agent 配置，请设置 HACKMATE_AGENT_BASE_URL 和 HACKMATE_AGENT_MODEL"
            )
        return cls(base_url, api_key, model)

    def ask(self, message, context=None):
        """发送一条消息并返回 Agent 文本回复；不会保留跨调用对话历史。

        context 可选，用于明确传递 HackMate 当前整理出的上下文；调用方应避免
        不加选择地转发私密信息、API key、浏览器数据或完整对话记录。
        """
        if not isinstance(message, str) or not message.strip():
            raise ValueError("message 不能为空")

        messages = [{"role": "system", "content": self.system_prompt}]
        if context:
            messages.append({"role": "user", "content": f"提供的上下文：\n{context}"})
        messages.append({"role": "user", "content": message})

        payload = json.dumps({
            "model": self.model,
            "messages": messages,
            "stream": False,
        }).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=payload,
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            raise AgentLinkError(f"Agent API 返回 HTTP {exc.code}: {detail[:500]}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise AgentLinkError(f"无法连接 Agent: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise AgentLinkError("Agent 返回的内容不是合法 JSON") from exc

        try:
            reply = data["choices"][0]["message"].get("content")
        except (KeyError, IndexError, TypeError) as exc:
            raise AgentLinkError("Agent API 响应缺少 choices[0].message.content") from exc
        if not isinstance(reply, str):
            raise AgentLinkError("Agent 未返回文本回复")
        return reply.strip()
