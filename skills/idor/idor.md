# 任意 X 子授权（IDOR 加强版）

## 一句话说清
比 IDOR 更狠的「权限维度」漏洞：IDOR = A 改 ID 访问 B 的资源；任意 X = A 直接执行「批准 / 删除 / 创建管理员」的接口，绕过整个权限模型，无论资源属于谁。529 个真实案例，子类别高危占比 51%–86.4%。

## 子类型路由
单文件 playbook，详细入口 / payload 见 `playbook.md`（load_skill('idor', 'playbook')）。
