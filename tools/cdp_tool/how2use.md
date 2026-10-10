# CDP Tool — 有什么用 / 怎么用

## 这是什么

`cdp_tool` 是 HackMate 的浏览器执行工具，通过 **CDP（Chrome DevTools Protocol）** 驱动本地 Chrome，让副驾驶能真实地「看页面、找注入点、验证 XSS」。

实现代码：`hackmate/cdp.py`（`CDPClient` 类）。给 LLM 的 function calling 定义在 `schema.json`。

## 前置

1. Chrome 带调试端口启动：`--remote-debugging-port=9222`
   - Windows/WSL：跑 `cdp_tools/cdp_launcher.exe`（会自动拉起，见 `hackmate/cdp.py` 的 `ensure_cdp`）
   - Linux/Mac：`chrome --remote-debugging-port=9222`
2. 读 DOM 需要 `websocket-client`（见 `requirements.txt`）。

## 8 个工具

| 工具 | 用途 | 何时用 |
|---|---|---|
| `list_tabs` | 列出所有页面 tab | 一开始，看现在有什么页面 |
| `open_new_tab` | 开新 tab 并导航 | 要开目标站 |
| `read_page_text` | 读某页可见文本 | 看页面内容 |
| `navigate` | 导航某 tab 到 URL | 带 payload 访问目标 |
| `fill_form` | 填表单字段 | 测表单型 XSS |
| `click` | 点元素 | 触发事件/提交 |
| `find_xss_entries` | 扫注入点候选（输入框/表单/URL参数/带参链接） | 定位突破口 |
| `verify_xss` | 黑盒验证：导航带 payload URL，检测 alert 弹没弹 | **最终确认 XSS 是否成立** |

## 关键：verify_xss 是「真验证」

它导航到带 payload 的完整 URL，监听 CDP 的 `Page.javascriptDialogOpening` 事件——**alert 弹了 = payload 的 JS 真的执行了 = XSS 成立**。这是确定性的 tool-result 验证，不是「我觉得它行」。

## 怎么接 LLM

`schema.json` 里的每个工具定义会被 `hackmate/cli.py` 的 `load_tools()` 读进来，作为 OpenAI function calling 的 `tools` 参数传给 LLM。新增工具 = 在 `schema.json` 加定义 + 在 `cli.py` 的 `execute_tool()` 加分发分支。
