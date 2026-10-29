# Mobile overview

> 排他：仅当目标是 Android APK / iOS IPA 客户端本身（导出组件、硬编码凭据、抓包 API）时用本 skill。APP 抓包抓到内部接口要打 IDOR → 转 Web 类 skill（idor 等）；APK 硬编码 key → 按 info-disclosure 报告标准；iOS 逆向注意 jshook MCP 只覆盖 Android。

## 一句话说清
移动端漏洞 = 客户端做了「不该客户端做」的安全决策（鉴权/加密/校验）。SRC 价值：APK 硬编码 secret/API key = P1；导出组件触发账户操作 = P0；中间人读 token = P0–P1。

## 判断流程（核心，正文 Step1-3）
Step1 hash + 反编译看 AndroidManifest → 有 exported 组件按类型分支（Activity 触发敏感页 / Service 调方法 / Provider 读数据，每类 1 条 adb 验证）→ Step2 无导出组件 → 抓包找内部 API（删 token 仍 200=鉴权缺失，改 user_id=IDOR）→ Step3 静态 3 个 grep（secret/key/token）命中 + sts get-caller-identity 回显 = 硬编码凭据确认，全空 → 停静态转动态抓包。优先级：能跑 APP 先抓包（Web API 漏洞比客户端漏洞好报且危害大），抓不到再静态。

## 工具
jshook MCP（Android：adb_apk_analyze / tls_cert_pin_bypass_frida / proxy_setup_adb_device）；jadx / apktool / frida 现场用。
