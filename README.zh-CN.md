# Agent Skill Audit

用于初步审查 AI Agent Skill、插件源码和随附脚本的本地命令行工具。
当前为 0.2.0 新项目，尚无可核验的用户、下载量或长期社区维护记录。
源码仓库：https://github.com/nmdgb/yang 。
真实公开仓库的固定提交实测、误报案例和复现方法见 [实测报告](research/REPORT.md)。

需要 Python 3.10 或更高版本，无第三方运行时依赖。在本目录运行：

```sh
python agent_skill_audit.py examples/benign
python agent_skill_audit.py examples/review-me --format json
python agent_skill_audit.py /你的本地项目路径 --fail-on medium
python agent_skill_audit.py /你的本地项目路径 --format sarif
python -m unittest discover -s tests -v
```

也可以在虚拟环境中运行 `python -m pip install .`，然后使用 `agent-skill-audit` 命令。
已提供 Windows/Linux、Python 3.10/3.12 的 CI 配置。没有发布到 PyPI。

Windows 路径中有空格时加双引号。程序不安装、不执行被检查的 Skill，
不读取所扫描文件引用的凭证文件，也不访问网络。

目前提供 8 组启发式规则：下载后交给 Shell 执行、部分 PowerShell
远程或编码执行、递归删除、部分指令覆盖语句、凭证位置引用、疑似密钥、
动态代码执行和部分 HTTP 上传操作。报告给出文件、行号、规则和风险提示，
不输出匹配到的原文或密钥值。文件名仍会出现在报告中。

退出码 0 表示扫描范围内未命中指定阈值；1 表示命中；2 表示错误或扫描不完整。
示例 review-me 是故意放置的风险文本，预期退出码为 1，不应执行里面的命令。

它只能帮人定位值得检查的位置，不能证明一个 Skill 安全，也不能断言命中项
就是攻击。正常文档和安全测试也会命中。它会漏掉混淆、多行或未覆盖的模式。
默认跳过依赖目录和不支持的扩展名；遇到超限、编码不支持、链接等情况会报告
扫描不完整。精确范围和并发文件系统限制请阅读英文 README。

适合的使用者：Skill 使用者、插件维护者、Agent 集成开发者和 PR 审查者。
当前还没有 API 功能；未来可研究经人工确认、脱敏后的维护辅助工作流。
