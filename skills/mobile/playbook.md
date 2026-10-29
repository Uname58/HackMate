# 移动端（Android / iOS）安全

> 视角：黑盒，静态 + 动态。判断流程优先，payload 靠现场构造不背。

## 排他声明
仅当目标是 APK/IPA 客户端本身。APP 抓包抓到内部接口打 IDOR → 转 Web 类 skill；硬编码 key → 按 info-disclosure 报告标准；iOS 逆向 jshook MCP 只覆盖 Android。

## 一句话说清
移动端漏洞 = 客户端做了「不该客户端做」的安全决策。最有价值的工作是抓包打服务端 API（危害大、好报），客户端本身漏洞（导出组件/硬编码）次之。

## 判断流程（★ 核心）

### Step 1 — 反编译看导出组件（1 步）
APK hash + jadx/apktool 反编译看 AndroidManifest.xml → 有 android:exported="true" 组件 → 按类型分支（每类 1 条 adb 命令验证 + 结果判据）：
- Activity：`adb shell am start -n com.victim.app/.admin.XXXActivity` → 直接进入敏感页 = P0
- Service：`adb shell am startservice` / 调导出服务方法 → 触发敏感操作
- Provider：`adb shell content query --uri content://com.victim.app.provider/xxx` → 返回数据 = 数据泄露

### Step 2 — 无导出组件 → 抓包找内部 API（动态）
抓包（装 CA / 绕 pinning）跑 APP 各功能 → 对每个 endpoint：
- 删 token 仍 200 = 鉴权缺失
- 改 user_id / 对象 ID = IDOR
→ 命中即转 Web 类 skill 报告（客户端漏洞不如服务端 API 好报）。

### Step 3 — 静态 3 个 grep（找硬编码凭据）
`grep -rE "(secret|key|token)"` 反编译目录 → 命中 AWS/云 key 时用 sts get-caller-identity 回显 = 硬编码凭据确认。3 个 grep 全空 → 停静态，转动态抓包。

### Step 4 — 优先级决策 + 停损点
能跑 APP → 先抓包（Web API 漏洞优先）；抓不到（pinning 难绕）→ 静态。硬编码 key 只做身份验证，不操作云资源。

## 真实案例指纹（精简）
- Firebase 数据库未授权：URL 末尾 `/.json` 返回数据 → P0/P1
- 硬编码 AWS key：反编译后 grep aws_access_key_id 命中 → P1
- 未授权 deep link：`myapp://transfer?to=attacker&amount=999` → 直接触发操作
- AndroidManifest `android:debuggable="true"` / `allowBackup="true"` → 附加调试/备份读数据

## PoC 模板（保留）
- 导出组件：APK hash + 版本 + AndroidManifest 行号 + adb 命令 + 结果截图
- 硬编码凭据：jadx 文件路径 + 代码行（key 前 4 + 后 4 脱敏）+ sts get-caller-identity 回显

## 证据 / 不要做的事
- 禁：用硬编码凭据操作云资源（建/删/列举），仅 sts get-caller-identity 验证
- 禁：通过导出组件真触发支付/转账/删数据，在自己账号上验证
- 禁：反编译源码传第三方/GitHub；批量调 APP 内部接口
- 限：测试用自己设备
- CVSS：导出组件重置任意密码 8.8 / 硬编码生产 AWS key 9.1–9.8 / 明文存 token 6.5
