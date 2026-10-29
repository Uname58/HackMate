# Race Conditions overview

> 排他：仅当目标是 check-then-act 非原子操作（优惠券/余额/限购/邀请码/验证码的"一次性消耗"）时才用本 skill。能串行复现的双花/越权 → logic-flaws（并发只是手段，本质是逻辑漏洞）。

## 一句话说清
竞态 = 程序假设"读→改→写"是原子的，并发请求让它不是。优惠券/余额双花 = P1（$500–$5k）。

## 判断流程（核心，正文 Step1-5）
列 check-then-act 候选 → 先 2-3 次串行确认"一次性消耗"语义 → 判并发窗口（单连接 vs 多连接）→ 复现率门槛（并发 50、5 轮 ≥3 轮 ≥2 笔 SUCCESS）→ 区分竞态 vs 逻辑（串行也能双花=logic-flaws）。

## 工具
Burp Turbo Intruder（精确并发，模板见 playbook.md）。
