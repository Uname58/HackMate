# UNION SQLi 判断规则

## 1. 启动条件
- 信号：参数变化导致响应中数据行/表格内容变化，且页面有固定重复结构。
- 动作：进入列数判断。
- 停：参数只影响布尔/时间/状态码；或注入字符被原样返回/转义且查询结构不变 → 转盲注/报错。
- 示例：`?id=1` 返回一行，`?id=1'` 报错。

## 2. 参数类型与闭合
- 信号：单引号导致报错/行为变化 → 字符型；数字型对单引号不敏感。
- 动作：字符型先闭合引号再拼 UNION；数字型直接拼。
- 示例：`?id=1' AND '1'='1` 正常，`?id=1' AND '1'='2` 空 → 字符型。

## 3. 判列数
- 动作：`ORDER BY n` 递增；响应从正常变为报错/结构变化，临界值减 1 为列数。
- 停：`ORDER BY` 被过滤用 `UNION SELECT NULL` 逐个加；`n>10` 仍正常 → 停止。
- 示例：`?id=1 ORDER BY 5--` 正常，`ORDER BY 6--` 报错 → 5 列。

## 4. 找回复显列
- 动作：令原查询空集，`UNION SELECT` 标记值。
- 判断：页面出现的标记为回显列；全部标记不可见 → 无回显，转报错/盲注。
- 示例：`?id=-1 UNION SELECT 1,2,3--` 页面出现 2 → 第 2 列回显。

## 5. 判断回显列类型
- 动作：回显列放字符串，其余放 NULL。
- 判断：报类型错误 → 回显列非字符串，换数字/函数；回显被截断 → 用 SUBSTR/CONCAT 分段。
- 示例：`?id=-1 UNION SELECT NULL,'x',NULL--` 报 conversion error → 第 2 列非字符串。

## 6. 识别数据库
- 信号：错误信息含 `ORA-` → Oracle；含 `MySQL/MariaDB` → MySQL；含 `PostgreSQL` → PostgreSQL。
- 动作：无错误时试一次版本函数；仍未知靠注释符和连接符判断。
- 示例：`?id=-1 UNION SELECT NULL,@@version,NULL--` 返回版本 → MSSQL/MySQL 类。

## 7. 提取数据
- 动作：回显列替换为目标查询，优先 `information_schema.tables/columns` 或 `all_tables/all_tab_columns`。
- 判断：多行用 `LIMIT/OFFSET` 或 `ROWNUM` 逐行取；长度不足用 `SUBSTR` 分段。
- 示例：`?id=-1 UNION SELECT NULL,table_name,NULL FROM information_schema.tables LIMIT 1--`

## 8. 过滤处理
- 动作：空格或关键字被滤时，先试注释内联一次。
- 停：仍失败不再穷举，转报错/盲注。
- 示例：`?id=-1/**/UN/**/ION/**/SEL/**/ECT NULL,2--`

## 9. 停止/切换
- 信号：无回显；连续两次不同注入载荷响应完全一样；报错与注入字符无关 → 停 UNION。
- 动作：确认参数化或输入被转义且查询结构不变 → 停止该参数。
- 动作：同一参数 UNION 尝试超过 10 次未果 → 换盲注或换参数。