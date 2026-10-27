# GraphQL

## 一句话说清
GraphQL = 一个端点（通常 `/graphql`），所有 query / mutation 走它。
特有风险：Introspection 暴露 schema、字段级授权缺失、嵌套查询绕过权限、深度递归 DoS。
SRC 价值：嵌套 IDOR + 字段越权 = P1。