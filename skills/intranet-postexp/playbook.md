# 内网后渗透判断流程

## 内网侦察（摸地形）

> 视角：黑盒，进了陌生网先摸地形。判断流程优先，基础枚举命令现场查不背。

### 排他声明
仅当已进内网、要搞清「在不在域、有哪些主机、当前身份是什么」。公网 Web 侦察 → Web 漏洞类；net user / netstat / nmap -sn 等基础命令是工具手册内容，不背，现场查。

### 一句话说清
侦察第一目标是回答三个问题：我是谁（身份）、在不在域（domain）、网里还有谁（主机/服务）。

### 判断流程（★ 核心）

#### Step 1 — 定身份 + 定域（2 个命令）
whoami /priv（身份）+ systeminfo / ipconfig /all（是否在域、域名、DC IP）→ 不在域 = 工作组，后续只做主机级（提权/抓凭据），跳过域攻击。

#### Step 2 — 摸主机（1-2 个扫描）
拿当前网段，扫存活主机 + 常见端口（445/135/5985/88）→ 识别 DC（88/389 开 = 域控）、文件服务器（445）、Web（80/443）。

#### Step 3 — 分叉
在域 → 转 domain.md；有凭据 → 转 credentials/lateral；都无 → 停在「摸清地形」这一步，不深入。

### 证据 / 不要做的事
- 判据：能说清「身份 + 是否在域 + DC 是哪台 + 有哪些主机」= 侦察完成
- 扫描限速，避免触发 IDS（内网扫描是高危告警源）
- 禁：BloodHound/SharpHound 全量采集（SRC 多数受限 + 海量 LDAP 查询告警）
- 证据：主机清单 + 端口清单（IP 脱敏）

---

## 凭证窃取（按权限分叉）

> 视角：黑盒，已拿 shell。判断流程优先，命令现场构造不背。

### 排他声明
仅当已拿到目标机 shell、要找系统/浏览器/域凭据。还没拿 shell → 先走 Web 漏洞类；查 mimikatz 具体命令语法 → 工具手册，不是本 skill 判断；SRC 未经授权跳过 LSASS dump 之后的红队动作。

### 一句话说清
抓凭据的先后顺序由「当前权限」决定：admin/SYSTEM 才碰 LSASS，普通用户优先碰不需高权限的 DPAPI / 浏览器 / Unattend / GPP。

### 判断流程（★ 核心）

#### Step 1 — 定身份（1 个命令）
whoami /priv + whoami /groups → 看是否是 admin/SYSTEM 或含 SeDebugPrivilege。

#### Step 2 — 按权限分叉
- **admin/SYSTEM**（含 SeDebug）→ 才碰 LSASS（mimikatz logonpasswords / lsass dump）→ 拿到 NTLM/明文即停，转 lateral
- **普通用户**（无高权限）→ 跳过 LSASS，按「不需高权限」优先：
  1. DPAPI 凭据（Credential Manager）— 当前用户可读
  2. 浏览器保存密码 / Cookie — 当前用户 profile 可读
  3. Unattend.xml / Sysprep（部署残留明文/Base64 密码）
  4. GPP cpassword（SYSVOL 里，普通域用户可读，公开密钥可解密）

#### Step 3 — 确认点 + 放弃点
- 确认：拿到一条可用凭据（回显能登录）即停，转 lateral
- 放弃：4 类不需高权限的路径都试过仍无凭据 → 停，别硬上 LSASS（权限不够也 dump 不出来）

### 证据 / 不要做的事
- 判据：明文密码 / NTLM hash / 可解密的 cpassword = 凭据到手；「读到文件但空」= 没拿到
- 优先碰不需高权限的（DPAPI/浏览器/Unattend/GPP），admin/SYSTEM 才碰 LSASS
- 禁：拿到的凭据离线破解后实际登录后台 / 生产库
- 证据：抓到的凭据脱敏（前 2 + 后 2 + 长度 + hash 指纹）
- GPP cpassword 用公开密钥解密即停，不批量解所有域账号

---

## 横向移动（按端口分叉）

> 视角：黑盒，已有一组凭据要打第二台机。判断流程优先，命令现场构造不背。

### 排他声明
仅当已有一组内网凭据、要横向到第二台机器。还没凭据 → credentials.md；查 PsExec/WMI 命令语法 → 工具手册；SRC 未经授权跳过横向之后的红队动作。

### 一句话说清
横向手段由「目标开哪个端口」决定：445→SMB/PsExec，135→WMI，5985→WinRM，都不通→放弃或 RDP/隧道。

### 判断流程（★ 核心）

#### Step 1 — 判端口（每台 3 个探测）
对目标机探测 445 / 135 / 5985 → 记通哪个。

#### Step 2 — 按端口分叉
- 445 通 → SMB/PsExec/smbexec（PtH 用 NTLM hash 直接打）
- 445 不通但 135 通 → WMI / wmiexec
- 仅 5985 通 → WinRM / evil-winrm
- 都不通 → RDP（3389）或隧道，仍不通 = 放弃这台

#### Step 3 — 确认点 + 放弃点
- 确认：目标回显 whoami = 横向成功（每个通道的成功判据都是回显身份）
- 放弃：3 台机器 445/135/WinRM 全不通 = 停横向，别再换工具硬试

### 证据 / 不要做的事
- 判据：目标回显 whoami = 成功；连接超时 / access denied = 失败
- 按端口选通道，别对所有机器无脑跑 PsExec
- PtH 只打拿到的 hash 对应的用户，不暴力猜密码
- 禁：横向成功后删数据 / 装后门 / 破坏目标
- 证据：每条通道附「源→目标 + 通道 + 回显 whoami」截图（脱敏）

---

## 权限提升（本机提权）

> 视角：黑盒，已拿低权限 shell 要提权。判断流程优先，命令现场查不背。

### 排他声明
仅当已拿到低权限 shell、要在本机提权到 admin/SYSTEM/root。还没 shell → Web 漏洞类；查 Potato/SUID 具体命令 → 工具手册。

### 一句话说清
提权路径由「当前权限特征」决定：有 SeImpersonate/SeAssignPrimaryToken → Potato 系列；有 sudo 免密/SUID → Linux 路径；管理员组成员 → UAC bypass。

### 判断流程（★ 核心）

#### Step 1 — 定系统 + 定权限（2 个命令）
Windows：whoami /priv（看 SeImpersonate/SeAssignPrimaryToken）；Linux：id + sudo -l + find / -perm -4000。

#### Step 2 — 按特征分叉
- Windows + SeImpersonatePrivilege → Potato（GodPotato/PrintSpoofer/JuicyPotato，按系统版本选）
- Windows + 管理员组成员（UAC）→ UAC bypass（fodhelper/eventvwr）
- Windows + 可写服务路径 → 服务路径劫持
- Linux + sudo -l 有免密命令 → GTFOBins 对应利用
- Linux + SUID 文件 → SUID 利用
- 内核漏洞 → 先查版本再找对应 CVE（DirtyPipe/PwnKit 等）

#### Step 3 — 确认点 + 放弃点
- 确认：whoami 回显 SYSTEM/root = 提权成功即停
- 放弃：3 条路径都无特征 → 停，别硬上内核 exploit（不稳 + 容易蓝屏/崩机）

### 证据 / 不要做的事
- 判据：提权后回显 SYSTEM/root = 成功
- 优先稳定路径（Potato/SUID/sudo），内核 exploit 最后才碰
- 禁：提权后删日志 / 装后门
- 证据：提权前后 whoami 对比截图（脱敏）

---

## 域渗透（按权限分叉）

> 视角：黑盒，已进域。判断流程优先，命令现场构造不背。

### 排他声明
仅当已进域、目标是打 DC / 拿域管。普通域用户没拿到域管 → 先 Kerberoast/AS-REP；DCSync/Golden 只在拿到域管（或对应 ACL）后才考虑。还没进域 → 先 recon/credentials。

### 一句话说清
域内攻击按「当前权限」分层：普通域用户先做不需高权限的 Kerberoast / AS-REP，拿到域管后才上 DCSync / Golden / Silver。

### 判断流程（★ 核心）

#### Step 1 — 定权限（1 个命令）
whoami /groups 看是否在 Domain Admins。

#### Step 2 — 普通域用户路径（不需高权限）
- Kerberoast：请求 SPN 服务票据离线破解（GetUserSPNs.py / Rubeus kerberoast）→ 拿到服务账号明文 = 服务账号权限
- AS-REP Roast：找 DoesNotRequirePreAuth 的用户（GetNPUsers.py）→ 拿到该用户 hash 破解

#### Step 3 — 域管路径（拿到域管后才做）
- DCSync：dump 域内 hash（lsadump::dcsync）
- Golden / Silver Ticket：krbtgt / 服务 hash 伪造票据

#### Step 4 — 停损点
普通用户先试 Kerberoast/AS-REP，拿不到就停（没到域管别碰 DCSync/Golden）；拿到域管 hash 即停，不拖整个 NTDS。

### 证据 / 不要做的事
- 判据：GetUserSPNs 返回可离线破解的 TGS = Kerberoast 成立；dcsync 返回 hash = 域管确认
- 顺序：Kerberoast/AS-REP（不需高权限）在前，DCSync/Golden（需域管）在后
- 禁：离线破解后实际登录域管账号操作生产
- 禁：DCSync 全量 dump 所有用户 hash（拿 Administrator 1 条即停）
- 证据：票据/哈希脱敏（前 2 + 后 2 + hash 指纹）

---

## ADCS 证书服务滥用

> 视角：黑盒，域内。判断流程优先，命令现场查不背。

### 排他声明
仅当域内存在 ADCS 证书服务、要判 ESC1-8 模板滥用。还没进域 / 没 ADCS → 先 domain.md；查 certipy 命令语法 → 工具手册。

### 一句话说清
ADCS 攻击 = 证书模板配置错误（ESC1-8）让普通用户能申请到「可冒充域管」的证书 → Pass-the-Cert 拿 TGT。

### 判断流程（★ 核心）

#### Step 1 — 探测 ADCS + 模板（1 个请求）
certipy find 枚举 CA + 模板 → 识别 ESC1（模板允许自定义 SAN）/ ESC4（模板可写）/ ESC8（HTTP 端点 NTLM 中继）等。

#### Step 2 — 按 ESC 类型分叉
- ESC1/ESC6：申请 -alt 指定 SAN 为域管的证书
- ESC4：改模板为 ESC1 配置 → 申请 → 恢复原配置
- ESC8：NTLM 中继到证书端点

#### Step 3 — 确认点 + 停损点
- 确认：certipy auth 用证书拿到 TGT = 确认；拿不到 = 停
- 停损：拿到一个域管 TGT 即停，不批量申请证书

### 证据 / 不要做的事
- 判据：用证书认证拿到 TGT = 确认
- ESC4 改完模板必须恢复原配置
- 禁：批量申请证书 / 长期持有域管
- 证据：certipy 输出（证书/票据脱敏）

---

## Exchange 攻击（邮件服务）

> 视角：黑盒。判断流程优先，命令现场查不背。

### 排他声明
仅当目标含 Exchange、要判 CVE 或拿邮箱。Exchange 是内网/邮件服务，多数场景先确认授权边界；查 CVE 利用脚本语法 → 工具手册。

### 一句话说清
Exchange 攻击面 = 版本对应的 CVE（ProxyLogon/ProxyShell/ProxyToken）+ 认证后的邮箱访问（EWS/OWA）。

### 判断流程（★ 核心）

#### Step 1 — 指纹（1 个请求）
访问 /owa/auth/logon.aspx 或 /owa/auth/x.js 看版本 → 老版本 → 按版本查对应 CVE。

#### Step 2 — CVE 探测（每个 CVE 1 个请求）
ProxyLogon（CVE-2021-26855 SSRF）/ ProxyShell（CVE-2021-34473 RCE）/ ProxyToken（认证绕过）→ 只做「版本匹配 + 探测脚本出结果」的验证，不手动构造攻击链。

#### Step 3 — 邮箱访问（有凭据后）
OWA/EWS 用已有凭据读自己账号邮箱验证 → 拿到邮箱内容即停。

#### Step 4 — 停损点
版本不对 / 探测无果 → 停；拿邮箱只读自己账号，不导出他人邮箱。

### 证据 / 不要做的事
- 判据：探测脚本返回确认 + 版本匹配 = CVE 成立；版本已补丁 = 停
- 禁：MailboxExportRequest 批量导出他人邮箱
- 证据：版本指纹 + 探测结果截图（脱敏）

---

## SharePoint 攻击

> 视角：黑盒。判断流程优先，命令现场查不背。

### 排他声明
仅当目标含 SharePoint、要枚举站点/文件。多数场景先确认授权边界；查 REST API 语法 → 工具手册。

### 一句话说清
SharePoint 攻击面 = _api REST 端点未授权/越权枚举站点、用户、文档，以及搜索接口捞敏感文件。

### 判断流程（★ 核心）

#### Step 1 — 未授权探针（2-3 个请求）
访问 /_api/web/webs、/_api/web/siteusers、/_api/search/query 看是否无认证返回数据 → 返回数据 = 未授权枚举，P2/P1。

#### Step 2 — 搜索敏感文件（1 个请求）
/_api/search/query?querytext='password' 看是否捞出敏感文件名 → 捞到 = 敏感文件暴露。

#### Step 3 — 停损点
未授权端点都不返回 → 停；捞到敏感文件只列文件名，不下载内容。

### 证据 / 不要做的事
- 判据：无认证返回站点/用户/文件列表 = 未授权枚举
- 禁：下载他人敏感文档全文
- 证据：请求 + 响应列表（文件名/用户脱敏）

---

## 隧道 / 代理

> 排他：红队内容。SRC 众测未经授权跳过本文件——隧道是为「内网不出网仍要横向」服务的，属后渗透/红队范畴，多数 SRC 不受理。确需到达 in-scope 内网资产时先确认授权边界，再现场查工具用法（frp/Chisel/ssh -D），不背命令。

---

## 免杀 / 规避（AMSI bypass / ETW / unhook）

> 排他：红队内容，与 SRC 众测无关。SRC 报的是「目标存在漏洞」，不是「怎么绕过 AV/EDR 不被发现」。未授权跳过本文件；确需时现场查工具用法，不背命令。

---

## 权限维持

> 排他：红队内容，与 SRC 众测无关。SRC 不要求（也不该）在目标上维持长期访问，植入后门 = 越界。未授权跳过本文件。
