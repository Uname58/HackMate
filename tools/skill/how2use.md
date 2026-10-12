# skill 工具

给 LLM 的 function calling 工具，操作漏洞知识库（`skills/`）。

- `load_skill(vuln)`：读某类漏洞的完整知识（测试方法/绕过/坑），注入上下文。
- `improve_skill(vuln, variant)`：改进某个 skill，走 eval gate（思路 B 判分，涨保留/跌回滚）。
