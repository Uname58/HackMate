# 内网渗透 / 后渗透 — 决策索引

## 子类型路由（按信号读对应 variant）
| 当前阶段 | 任务 | MUST Read |
|---|---|---|
| 已拿 shell,身份是 user | 找系统凭据 / 浏览器密码 / Kerberos 票据 | `10-credentials.md` |
| 已有一组凭据,需要打第二台机器 | SMB / WMI / PsExec / RDP / WinRM / Pass-the-Hash / Ticket | `11-lateral.md` |
| 拿到 user,需要 root/SYSTEM | UAC bypass / sudo 提权 / 内核 / SUID / Token | `12-privesc.md` |
| 防护强,被 AV/EDR 拦 | AMSI bypass / ETW patch / DLL sideload / unhook | `13-evasion.md` |
| 已进域,要打 DC | Kerberoasting / AS-REP / Golden / Silver / DCSync / Constrained | `14-domain.md` |
| 内网不出网 | reGeorg / frp / Chisel / ICMP / DNS tunnel / SOCKS / ssh -D | `15-tunneling.md` |
| 进了陌生网,先摸地形 | 主机发现 / 端口扫描 / Bloodhound 收集 / hostname / hostfile | `16-recon.md` |
| 拿到 admin,要维持长期访问 | 服务 / 计划任务 / 注册表 / WMI 订阅 / Logon / SSP / Skeleton Key | `17-persistence.md` |
| 目标含 Exchange | NTLM Relay / EWS / OAB / CVE-2021-26855 / Mailbox Export | `18-exchange.md` |
| 目标含 ADCS / 证书服务 | ESC1–ESC8 模板滥用 | `19-adcs.md` |
| 目标含 SharePoint | 信息收集 / SOAP / API / OneDrive 同步 | `20-sharepoint.md` |