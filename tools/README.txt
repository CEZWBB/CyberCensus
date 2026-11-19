CyberCensus 增强引擎（本地副本）
================================

本目录用于源码模式（python cybercensus.py / asm_gui.pyw）固定使用一套
引擎版本，避免受本机 PATH 里其他版本影响。

查找顺序（由 cybercensus.ext_path 实现）：
  1. 程序同级的 tools\        ← 本目录
  2. 程序同级的 bin\
  3. 程序同级目录
  4. 系统 PATH

当前包含：
  subfinder.exe   被动子域名枚举
  httpx.exe       存活探测 / Web 指纹
  wafw00f.exe     WAF 识别（PyInstaller 冻结版，无需 Python）
  nuclei.exe      模板化漏洞验证

nuclei 模板：源码模式下如果项目根目录存在 nuclei-templates\，会自动
通过 -t 指定；否则使用 nuclei 自己的默认模板目录。

注意：
- *.exe 已被 .gitignore 排除，不会提交到仓库；新克隆的仓库没有本目录时
  会自动退回 PATH 查找，不影响主程序。
- 这些是独立的开源工具，CyberCensus 仅负责调度；升级时用新版 exe 覆盖即可。
- 仅限对已获书面授权的目标使用。
