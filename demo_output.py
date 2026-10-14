"""输出配色 demo：模拟 HackMate 自主打完一关的完整 CLI 输出（工具步骤 + 先未触发后
CONFIRMED + exploit 五段报告 + 后台 skill 优化冒泡），用的就是 repl 真正的渲染函数。

跑法（项目根目录，真终端里颜色才会渲染）：python demo_output.py
"""
import sys
sys.path.insert(0, ".")
from hackmate import repl

repl._enable_ansi()  # Win 控制台开 VT，颜色才渲染

# —— 模拟 HackMate 自主打一关的工具步骤 ——
steps = [
    ("navigate",         {"url": "http://localhost:8080/level2.php"},                                              "已导航"),
    ("find_xss_entries", {"index": 0},                                                                             "{...}"),
    ("read_page_text",   {"index": 0},                                                                             "欢迎来到 level2 ..."),
    ("verify_xss",       {"url": "http://localhost:8080/level2.php?keyword=<script>alert(1)</script>"},            '{"status":"INCONCLUSIVE"}'),
    ("verify_xss",       {"url": 'http://localhost:8080/level2.php?keyword="><script>alert(1)</script>'},          '{"status":"CONFIRMED"}'),
    ("save_case",        {"vuln": "xss"},                                                                          "case 已沉淀进 dev 集（当前 25 个）"),
    ("save_project",     {},                                                                                       "中记忆已保存"),
]

print()
for fn, args, result in steps:
    print(repl._render_tool(fn, args, result))

# —— 成功 exploit 五段报告（字段上色，首行 exploit结果: 无色）——
report = '''exploit结果:
目标URL: http://localhost:8080/level2.php?keyword="><script>alert(1)</script>
测试parameter: keyword
注入payload: `"><script>alert(1)</script>`
原理：keyword 落在 <input value="..."> 的双引号里，先用 "> 闭合属性和标签，再注入自己的 <script> 执行。
流程：枚举反射点 → 发现落在 value 属性 → 用 "> 闭合 → 注入 <script> → verify 观察到弹窗确认
CVSS: 6.1 (Medium)'''
print("\n" + repl._c("HackMate>", "blue") + " " + repl._colorize_report(report) + "\n")

# —— 后台 skill 优化完成冒泡（黄色）——
print(repl._yellow("[后台任务 #1] 优化 skill 'xss/reflection_xss'：[regression 43%, hidden 60%] → [regression 71%, hidden 70%]，已保留"))
