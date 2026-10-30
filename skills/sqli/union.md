# SQLi 判断规则

## 1. 启动与分诊
- 信号：参数变化导致响应内容/状态码/行数变化，或报错，或时间延迟。
- 动作：按响应类型选择技术：
  - 响应有明显数据回显或表格结构变化 → 走 UNION。
  - 响应只有两个稳定状态（如“存在/不存在”“true/false”）→ 走布尔盲注。
  - 响应有数据库错误信息且可控制错误内容 → 走报错注入。
  - 仅时间延迟变化且无其他差异 → 走时间盲注。
- 停：参数对任何注入字符均无行为变化，且错误与注入无关 → 参数不可注入。

## 2. 布尔盲注优先
- 信号：响应仅存在两个稳定状态，且单个请求即可区分真假；POST 需带会话 Cookie 和所有表单字段。
- 动作：先构造最小真假对比，数字型：`AND 1=1` / `AND 1=2`；字符型：闭合后 `AND 'a'='a` / `AND 'a'='b`。
- 判断：两响应不同 → 布尔 oracle 成立，逐字符提取数据（用 SUBSTR/ASCII/LIMIT）。
- 停：两响应相同或响应不稳定 → 不采用布尔，转时间/报错。
- 示例：`id=1 AND 1=1` 返回存在，`id=1 AND 1=2` 返回不存在。

## 3. 参数类型与闭合（含 LIKE）
- 信号：单引号导致报错/行为变化 → 字符型；数字型对单引号不敏感。
- 动作：字符型先闭合引号再拼接；若参数在 `LIKE '%...%'` 内，闭合后注释掉剩余 `%'`，或使用 `OR` 使条件恒真。
- 停：多次尝试闭合与注释仍语法错误 → 转报错/盲注。
- 示例：`search=1' AND '1'='1'-- -` 正常，`search=1' AND '1'='2'-- -` 空 → 字符型。

## 4. UNION 列数判断
- 动作：`ORDER BY n` 递增；响应从正常变为报错/结构变化，临界值减 1 为列数。
- 停：`ORDER BY` 被过滤用 `UNION SELECT NULL` 逐个加；`n>10` 仍正常 → 停止 UNION。
- 示例：`ORDER BY 5` 正常，`ORDER BY 6` 报错 → 5 列。

## 5. 找回复显列
- 动作：令原查询空集，`UNION SELECT` 标记值；非回显列填 NULL，回显列填字符串标记。
- 判断：页面出现的标记为回显列；全部标记不可见 → 无回显，转报错/盲注。
- 示例：`id=-1 UNION SELECT NULL,'x',NULL--` 页面出现 x → 第 2 列回显。

## 6. 回显列类型
- 动作：回显列放字符串，其余放 NULL。
- 判断：报类型错误 → 回显列非字符串，换数字/函数；回显被截断 → 用 SUBSTR/CONCAT 分段。
- 示例：`UNION SELECT NULL,'x',NULL` 报 conversion error → 第 2 列非字符串。

## 7. 识别数据库
- 信号：错误信息含 `ORA-` → Oracle；含 `MySQL/MariaDB` → MySQL；含 `PostgreSQL` → PostgreSQL。
- 动作：无错误时试一次版本函数；仍未知靠注释符和连接符判断。
- 示例：`UNION SELECT NULL,@@version,NULL` 返回版本 → MSSQL/MySQL 类。

## 8. 报错注入路径
- 信号：响应返回数据库错误且可控制错误内容。
- 动作：在回显位置嵌入报错函数，如 `EXTRACTVALUE(1,CONCAT(0x7e,(query)))` 或 `UPDATEXML`，一次取一个值。
- 停：错误被屏蔽或函数不存在 → 换布尔盲注。
- 示例：`AND EXTRACTVALUE(1,CONCAT(0x5c,(SELECT database())))--`

## 9. 提取数据
- 动作：回显列替换为目标查询，优先 `information_schema.tables/columns` 或 `all_tables/all_tab_columns`。
- 判断：多行用 `LIMIT/OFFSET` 或 `ROWNUM` 逐行取；长度不足用 `SUBSTR` 分段。
- 示例：`UNION SELECT NULL,table_name,NULL FROM information_schema.tables LIMIT 1`

## 10. 布尔盲注数据提取
- 信号：布尔 oracle 成立。
- 动作：用 `SUBSTR((query),pos,1)>char` 逐字符二分，或 `ASCII(SUBSTR(...))` 比较；用 LIMIT 逐行。
- 停：单字符请求过多且响应不稳定 → 转报错/UNION。
- 示例：`AND ORD(SUBSTR((SELECT password FROM users LIMIT 1),1,1))>100`

## 11. 过滤处理与切换
- 动作：空格或关键字被滤时，先试注释内联一次。
- 停：仍失败不再穷举，转报错/盲注。
- 动作：同一参数 UNION 尝试超过 10 次未果 → 换盲注或换参数。
- 示例：`1/**/UN/**/ION/**/SEL/**/ECT NULL,2`

## 12. 停止条件
- 信号：无回显；连续两次不同注入载荷响应完全一样；报错与注入字符无关 → 停当前技术。
- 动作：确认参数化或输入被转义且查询结构不变 → 停止该参数。