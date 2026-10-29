# 竞态条件 (Race Conditions)

> 视角：黑盒，利用并发让 check-then-act 失效。**判断流程优先，payload 靠现场构造，不背。**

## 排他声明

仅当确认目标是 check-then-act 非原子操作时才用本 skill。

- 能串行复现的双花 / 越权 → logic-flaws（并发只是手段，本质是逻辑漏洞）
- 一次请求就能改他人数据 → idor / api-rest（BOLA）

## 一句话说清

竞态 = 程序假设"读 → 改 → 写"是原子的，并发请求让它不是。

## 判断流程（★ 核心）

### Step 1 — 列 check-then-act 候选
先列出目标里有哪些"一次性消耗"：优惠券、余额、限购件数、邀请奖励、验证码、唯一约束（同名/同邮箱注册）。

### Step 2 — 串行确认"一次性消耗"语义
2-3 次串行请求（先不并发）：
- 同一优惠券串行用 2 次 → 第 2 次被拒（"已使用"）→ 有一致性检查，继续
- 串行用 2 次都能成功 → 这是逻辑漏洞，去 logic-flaws，NO 停

### Step 3 — 判并发窗口
判断连接方式：
- 单连接（HTTP/1.1 复用 + 服务端串行处理）→ 竞态窗口小，可能需多连接
- 多连接 / HTTP/2 多路复用 → 并发窗口大，Turbo Intruder 多连接打

### Step 4 — 复现率门槛（防误判）
并发 50 次、跑 5 轮，判成功标准：
- 5 轮中 ≥3 轮、每轮 ≥2 笔 SUCCESS → **竞态确认**
- N=0 或仅 1 笔 → 不算（可能是偶然/网络），NO 停

### Step 5 — 区分竞态 vs 逻辑
关键问题：串行（不并发）能不能双花？
- 串行也能双花 → 逻辑漏洞，去 logic-flaws
- 只有并发才双花 → 真竞态，归本类

## 工具

Burp Turbo Intruder 模板（并发唯一可靠方式；xargs -P / 自写 threading 易写错不背）：

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=30,
                            requestsPerConnection=100,
                            engine=Engine.BURP2)
    for i in range(50):
        engine.queue(target.req, gate='r1')
    engine.openGate('r1')

def handleResponse(req, interesting):
    table.add(req)
```

## 证据 / 不要做的事

- **证据**：攻击前/后账户状态截图（余额/优惠券计数）+ 复现率（5 轮 ≥3 轮 ≥2 笔）。
- **禁**：实际提现真金白银（沙箱/测试账号；生产环境先联系平台约定退还）。
- **禁**：刷别人的优惠券 / 邀请奖励。
- **限**：并发 50 内（1000+ 视为 DoS）；同一漏洞复现 5-10 次。
- **报告**：附"前/中/后"数据证明停手。
