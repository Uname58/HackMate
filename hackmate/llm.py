"""OpenAI 兼容 LLM 客户端，纯标准库实现（urllib）。

支持 function calling（tool_calls），兼容 deepseek / openai / ollama / vllm。
"""

import json
import threading
import time
import urllib.request
import urllib.error


class LLMError(Exception):
    """LLM 调用失败时抛出。"""


class _RetryableError(LLMError):
    """可重试的网络错误（超时 / 连接失败 / 网络异常）。"""


class LLMClient:
    def __init__(self, base_url, api_key, model, system_prompt="", timeout=45):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.system_prompt = system_prompt
        self.messages = []
        if system_prompt:
            self.messages.append({"role": "system", "content": system_prompt})

    def _request(self, tools=None):
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
        for attempt in range(3):
            result = {}

            def _do():
                try:
                    result["data"] = self._do_request_once(req)
                except Exception as e:
                    result["err"] = e

            t = threading.Thread(target=_do, daemon=True)
            t.start()
            t.join(timeout=self.timeout)
            if t.is_alive():
                result["err"] = _RetryableError(f"请求总超时（>{self.timeout} 秒）")
            err = result.get("err")
            if err is None:
                return result["data"]
            if isinstance(err, _RetryableError) and attempt < 2:
                time.sleep(attempt + 1)  # 1s、2s 退避后重试
                continue
            raise err

    def _do_request_once(self, req):
        """单次网络请求 + 解析（无重试，异常按「是否可重试」分类）。"""
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")
            raise LLMError(f"HTTP {e.code}: {detail[:500]}")
        except urllib.error.URLError as e:
            raise _RetryableError(f"网络错误: {e.reason}")
        except TimeoutError:
            raise _RetryableError(f"请求超时（>{self.timeout} 秒）")
        except json.JSONDecodeError:
            raise LLMError("响应不是合法 JSON")
        except OSError as e:
            raise _RetryableError(f"网络异常: {e}")
        try:
            return data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError):
            raise LLMError(f"响应格式异常: {json.dumps(data, ensure_ascii=False)[:500]}")

    def _dispatch(self, msg):
        """根据 LLM 返回的 message 判断是文本还是 tool_call。"""
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
        """发送用户消息。

        返回 {"type": "text", "content": ...} 或 {"type": "tool_calls", "tool_calls": [...]}。
        """
        self.messages.append({"role": "user", "content": user_text})
        return self._dispatch(self._request(tools))

    def submit_tool_result(self, tool_call_id, name, result, tools=None):
        """把单个工具执行结果喂回 LLM，继续对话。"""
        return self.submit_tool_results([(tool_call_id, name, result)], tools)

    def submit_tool_results(self, results, tools=None):
        """批量提交工具结果（results = [(tool_call_id, name, result), ...]），继续对话。

        OpenAI 要求一次 tool_calls 的所有 tool message 必须一次性补齐，否则报
        'insufficient tool messages'。所以必须收集完所有结果后一次性提交。
        """
        for tool_call_id, name, result in results:
            self.messages.append({
                "role": "tool",
                "tool_call_id": tool_call_id,
                "name": name,
                "content": str(result),
            })
        return self._dispatch(self._request(tools))

    def clear(self):
        """清空上下文，只保留 system prompt。"""
        self.messages = []
        if self.system_prompt:
            self.messages.append({"role": "system", "content": self.system_prompt})

    def compact(self, keep_turns=20):
        """压缩上下文：保留 system + 最近 keep_turns 个 user 轮次，删更旧的完整轮次。

        按「user 消息」切轮次（一个 user 触发的一组 tool_calls/tool 结果算一轮），
        删整轮不会破坏 OpenAI tool_calls 的成对结构。返回是否发生了压缩。
        """
        user_idx = [i for i, m in enumerate(self.messages) if m.get("role") == "user"]
        if len(user_idx) <= keep_turns:
            return False
        first_keep = user_idx[-keep_turns]
        head = [m for m in self.messages[:first_keep] if m.get("role") == "system"]
        self.messages = head + self.messages[first_keep:]
        return True
