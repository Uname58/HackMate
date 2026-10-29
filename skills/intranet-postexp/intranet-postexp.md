# Intranet / Post-exploitation overview

> 排他：仅当已拿到内网 shell / 域凭据、要摸地形 / 抓凭据 / 横向 / 打域时用本 skill。⚠️ 内网后渗透在 SRC 多数受限，先确认授权边界再展开。目标只是公网 Web/API 还没拿 shell → 先走 Web 漏洞类（sqli/ssrf/rce 等）；只是查工具命令 / CVE 利用语法 → 工具手册，不是我的判断；SRC 众测未经授权跳过 persistence/evasion/tunneling（红队内容）。

## 一句话说清
后渗透 = 已进内网后，把「当前身份」逐步放大到「域管/目标数据」。每步都有确认点（回显 whoami）和放弃点（横向 3 台机全不通 = 停）。

## 判断流程（核心，正文 Step1-N）
拿 shell 先 whoami /priv 定身份 → 抓凭据按权限分叉（admin/SYSTEM 才碰 LSASS，否则 DPAPI/浏览器/Unattend/GPP）→ 横向按端口分叉（445→PsExec/SMB，135→WMI，5985→WinRM，全不通→停）→ 进域按权限分叉（普通域用户先 Kerberoast/AS-REP，拿到域管才 DCSync/Golden）。

## 工具
无专用 CLI；按分叉点现场选（Impacket / Mimikatz / Rubeus / certipy 等），命令现场查，不背。
