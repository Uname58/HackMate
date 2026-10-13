"""OpenAI 兼容 LLM 客户端，纯标准库（urllib）。

v2 变化（相对 v1）：
- 用 urlopen(timeout=...) 的 socket 级超时，超时即抛异常、不泄漏线程/连接
  （v1 用 daemon 线程 + join 超时，超时后线程仍在后台跑、socket 不关 → 多次超时泄漏）。
- 新增 clone()：复用连接配置、产出独立上下文的子客户端（给评委 / 产 payload / 候选生成用）。
- function calling（tool_calls），兼容 deepseek / openai / ollama / vllm。
"""

import json
import time
import urllib.request
import urllib.error


class LLMError(Exception):
    """LLM 调用失败。"""


class _RetryableError(LLMError):
    """可重试（网络超时 / 连接失败）。"""


class LLMClient:
    def __init__(self, base_url, api_key, model, system_prompt="", timeout=45, max_retries=2):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries
        self.system_prompt = system_prompt
        self.messages = []
        if system_prompt:
            self.messages.append({"role": "system", "content": system_prompt})

    def clone(self, system_prompt="", model=None, timeout=None):
        """复用连接配置，产一个独立上下文的子客户端（不共享 messages）。"""
        return LLMClient(
            self.base_url, self.api_key, model or self.model,
            system_prompt=system_prompt,
            timeout=self.timeout if timeout is None else timeout,
            max_retries=self.max_retries,
        )

    # ---- 网络 ----
    def _post(self, tools=None):
        url = f"{self.base_url}/chat/completions"
        payload = {"model": self.model, "messages": self.messages, "stream": False}
        if tools:
            payload["tools"] = tools
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        last = None
        for attempt in range(self.max_retries + 1):
            try:
                return self._once(req)
            except _RetryableError as e:
                last = e
                if attempt < self.max_retries:
                    time.sleep(attempt + 1)  # 1s、2s 退避
                    continue
                raise
        raise last  # pragma: no cover

    def _once(self, req):
        """单次请求（socket 超时，无线程）。异常按「可否重试」分类。"""
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")
            raise LLMError(f"HTTP {e.code}: {detail[:500]}")
        except urllib.error.URLError as e:
            # URLError 包装 socket.timeout 时 reason 是 TimeoutError 实例
            if isinstance(getattr(e, "reason", None), TimeoutError):
                raise _RetryableError(f"请求超时（>{self.timeout}s）")
            raise _RetryableError(f"网络错误: {e.reason}")
        except TimeoutError:
            raise _RetryableError(f"请求超时（>{self.timeout}s）")
        except json.JSONDecodeError:
            raise LLMError("响应不是合法 JSON")
        except OSError as e:
            raise _RetryableError(f"网络异常: {e}")
        try:
            return data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError):
            raise LLMError(f"响应格式异常: {json.dumps(data, ensure_ascii=False)[:500]}")

    # ---- 对话 ----
    def _dispatch(self, msg):
        if msg.get("tool_calls"):
            self.messages.append({
                "role": "assistant",
                "content": msg.get("content") or "",
                "tool_calls": msg["tool_calls"],
            })
            return {"type": "tool_calls", "tool_calls": msg["tool_calls"]}
        reply = msg.get("content", "")
        self.messages.append({"role": "assistant", "content": reply})
        return {"type": "text", "content": reply}

    def chat(self, user_text, tools=None):
        """发用户消息，返回 {"type":"text"|"tool_calls", ...}。"""
        self.messages.append({"role": "user", "content": user_text})
        return self._dispatch(self._post(tools))

    def ask(self, prompt):
        """一次性问答便捷方法（用于判分 / 评委：clear → chat → 取文本）。"""
        self.clear()
        self.messages.append({"role": "user", "content": prompt})
        msg = self._post(tools=None)
        return (msg.get("content") or "").strip()

    def submit_tool_results(self, results, tools=None):
        """批量提交工具结果 [(tool_call_id, name, result), ...]，继续对话。

        OpenAI 要求一次 tool_calls 的所有 tool message 必须一次补齐，否则报
        insufficient tool messages，所以收集完所有结果再一次性提交。
        """
        for tool_call_id, name, result in results:
            self.messages.append({
                "role": "tool",
                "tool_call_id": tool_call_id,
                "name": name,
                "content": str(result),
            })
        return self._dispatch(self._post(tools))

    def clear(self):
        """清空上下文，只保留 system prompt。"""
        self.messages = []
        if self.system_prompt:
            self.messages.append({"role": "system", "content": self.system_prompt})

    def compact(self, keep_turns=20):
        """压缩上下文：保留 system + 最近 keep_turns 个 user 轮次（整轮删，保成对结构）。"""
        user_idx = [i for i, m in enumerate(self.messages) if m.get("role") == "user"]
        if len(user_idx) <= keep_turns:
            return False
        first_keep = user_idx[-keep_turns]
        head = [m for m in self.messages[:first_keep] if m.get("role") == "system"]
        self.messages = head + self.messages[first_keep:]
        return True
