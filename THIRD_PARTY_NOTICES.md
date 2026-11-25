# 第三方组件与许可

CyberCensus 自身以 **Apache License 2.0** 发布（见 `LICENSE` 与 `NOTICE`）。发布包中还包含或调用以下第三方组件，它们分别遵循各自的上游许可。本文件随发布包一起分发。

## Python 依赖

| 组件 | 用途 | 许可 | 上游 |
|---|---|---|---|
| customtkinter | 图形界面 | MIT | https://github.com/TomSchimansky/CustomTkinter |
| dnspython | DNS 查询 | ISC | https://github.com/rthalley/dnspython |
| cryptography | TLS 证书解析 | Apache-2.0 / BSD-3-Clause | https://github.com/pyca/cryptography |
| pypinyin | 区县拼音候选 | MIT | https://github.com/mozillazg/python-pinyin |
| PyInstaller（构建期） | 打包 exe | GPL-2.0-with-bootloader-exception | https://github.com/pyinstaller/pyinstaller |

标准库与 Tcl/Tk 遵循各自随 Python 分发的许可。

## 随完整发布包分发的独立工具

这些程序**不包含在主 exe 内**，而是放在 `tools/` 目录，由 CyberCensus 通过命令行调用。它们的版权归各自作者所有。

| 工具 | 用途 | 许可 | 上游 |
|---|---|---|---|
| subfinder | 被动子域名枚举 | MIT | https://github.com/projectdiscovery/subfinder |
| httpx | 存活探测 / Web 指纹 | MIT | https://github.com/projectdiscovery/httpx |
| nuclei | 模板化漏洞验证 | MIT | https://github.com/projectdiscovery/nuclei |
| wafw00f | WAF 识别 | BSD-3-Clause | https://github.com/EnableSecurity/wafw00f |

nuclei 模板来自 ProjectDiscovery 的官方模板仓库，具体模板可能带有各自的元数据与许可声明，使用前请阅读上游仓库说明。

## 说明

- 本项目与上述厂商/项目**没有隶属或背书关系**，仅为互操作而调用其公开 API 或可执行程序。
- 各上游许可的完整文本请以对应仓库中的 `LICENSE` 为准；发布包如附带这些二进制，请同时保留其原始许可与版权声明。
- 如果你重新分发本项目的完整包，请一并保留本文件、`LICENSE` 以及上游要求的版权声明。
- 平台 API 的使用需遵守各平台的服务条款与配额限制。

## 商标

FOFA、0.zone、Hunter/鹰图、DayDayMap、ZoomEye、Quake、Shodan、Censys 等名称是其各自权利人的商标，仅用于说明兼容性。
