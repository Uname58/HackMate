# GraphQL overview

> 排他：仅当端点对 `{__typename}` 返回 `{"data":{...}}` 确认是 GraphQL 时用本 skill。非 GraphQL 立刻离开；REST 端点 → api-rest；query 字段值里的 SQL / NoSQL 注入 → sqli。

## 一句话说清
GraphQL = 一个端点（通常 `/graphql`），所有 query/mutation 走它。特有风险：Introspection 暴露 schema、字段级授权缺失、别名爆破绕过限频、深度递归 DoS。

## 判断流程（核心，正文 Step1-5）
发 `{__typename}` 判 GraphQL → introspection 返回 not allowed 判关闭（决定 clairvoyance 推断是否值得）→ 字段级越权（双账号对比同一 query）→ 别名爆破（26 别名返回 26 个不同结果=绕过，rate-limit 错误=被拦）→ 停损（schema 无敏感字段即停）。

## 工具
无专门 CLI；clairvoyance（无 introspection 时 schema 推断）、graphql-cop。
