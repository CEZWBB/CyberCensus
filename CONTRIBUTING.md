# 贡献指南

感谢你愿意改进 CyberCensus。提交前请先读一遍本文件，尤其是「授权与伦理」部分。

## 开发环境

- Windows 10/11（主目标平台）
- Python 3.8+，推荐 3.11
- 依赖：

```bat
pip install -r requirements.txt
pip install customtkinter pyinstaller
```

- 运行界面：

```bat
py -3.11 asm_gui.pyw
```

- 运行测试（不联网、不需要 API Key）：

```bat
py -3.11 -m unittest discover tests -v
```

- 界面自检：

```bat
py -3.11 asm_gui.pyw --smoke
```

## 提交前检查清单

- [ ] 新增/修改逻辑有对应单元测试，`python -m unittest discover tests` 全部通过
- [ ] 没有把真实 API Key、客户数据、扫描结果、内网地址写进代码/测试/文档
- [ ] 没有引入未经说明的新依赖；如必须引入，请更新 `requirements.txt` 和 `THIRD_PARTY_NOTICES.md`
- [ ] 主动扫描相关改动仍然要求显式开关和授权确认
- [ ] 没有加入弱口令、验证码绕过、批量攻击、规避检测等滥用能力
- [ ] README / 帮助文本与实际行为一致

## 代码风格

- 尽量沿用现有风格：函数级中文 docstring、短函数、显式错误处理
- 不重构无关代码；一个 PR 只做一件事
- 日志用 `log(msg, level)`，不要直接 `print`（CLI 摘要除外）
- 网络请求要有超时，失败要降级，不能让单个数据源拖垮整条流水线
- 外部命令必须通过 `_run_ext` 调用，保持 UTF-8 解码和 Windows 隐藏窗口

## 新增平台适配

平台差异集中在 `providers.py`：

1. 继承 `BaseProvider`
2. 定义 `supports`（支持的 Query 类型）
3. 实现 `translate()`（统一 Query → 平台语法）和 `search()`（请求 + 原始行解析）
4. 在 `load_config()`、`ALIASES`、`available_providers()` 中注册
5. 在 `tests/test_fixes.py` 里加翻译和响应解析测试
6. 更新 README 的平台表和 Key 说明

## 授权与伦理

本项目只用于**自有资产或已获书面授权**的暴露面梳理。以下类型的贡献不会被接受：

- 弱口令/默认口令爆破模块
- 验证码绕过、IP 池轮换、规避封禁
- 自维护漏洞 POC / 批量攻击编排
- 抓取爱企查/天眼查等受限制数据源
- 任何默认开启、未提示授权的主动攻击行为

## 提交 PR

- Fork → 新建分支 → 提交 → 开 Pull Request
- PR 描述写清楚：改了什么、为什么、如何测试、是否有行为变化
- 涉及界面变化的，请附截图（注意脱敏）
- 维护者可能会要求拆分或补充测试

## 许可证

提交代码即表示你同意以本仓库的 MIT License 授权你的贡献。
