# DoS overview

> 排他：仅当目标是「用最小流量证明放大、让服务不可用」时用本 skill。单次请求目的是读数据（actuator/env 读配置）→ info-disclosure 别按 DoS 报；rate limit 不够但不能放大 → SRC 通常不收直接放弃；缓存投毒能控制响应内容 → 先按 Web cache poisoning。

## 一句话说清
DoS = 让服务消耗资源远超正常请求所需，放大比 ≥ 1:100000 或单包打死 → P2/P1。涵盖 116 份真实 H1 高危案例。

## 判断流程（核心，正文 Step1-4）
Step1 1 次基线请求记 time_total → Step2 二倍递增 n=10→50 每个 n 只发 1 包 → Step3 判据：n 每 +10 时间 ≥4× → 确认 ReDoS 立即停；时间线性 → 转「资源不限速」路径 → Step4 确认后不再加大，按模板写 5 次串行复现；3 个候选端点都无放大 → 判定无应用层 DoS 停止，不再换 payload fuzz。

## 工具
curl -w（time_total 计时）；hyperfine 多次测量；nghttp2 测 HTTP/2 协议层。
