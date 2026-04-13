# Claude Code Security Scanner

基于 Anthropic Claude API 的自动化代码安全审计工具。支持批量扫描项目文件，智能过滤误报，生成结构化的安全报告。

## 功能特性

- **批量并发扫描** – 可配置最大并发数，高效处理大量文件
- **断点续扫** – 自动保存进度，中断后可恢复扫描
- **智能大文件处理** – 支持提取关键代码段、截断或跳过超大文件
- **误报过滤** – 内置硬排除规则（如 DOS、速率限制、非 C/C++ 内存安全等问题），可选 AI 二次过滤
- **增量报告** – 每处理 N 个文件即生成临时报告，便于实时监控
- **多格式输出** – 生成 JSON 和 HTML 格式的最终报告
- **可定制扫描范围** – 自定义排除目录、额外文件扩展名

## 快速开始

### 安装依赖

bash

```
pip install anthropic tqdm
```



### 基本使用



```
//base command
python scan_project.py --path /path/to/project --api-key YOUR_API_KEY
//test command
python scan_project.py --path ../to_test_simple_system --api-key YOUR_API_KEY --base-url https://api.kwwai.top --model claude-opus-4-6 --resume --report-interval 5 --large-file-strategy extract
```



## 命令行参数

| 参数                    | 类型                        | 默认值                       | 描述                                           |
| :---------------------- | :-------------------------- | :--------------------------- | :--------------------------------------------- |
| `--path`                | str                         | `.`                          | 项目根目录路径                                 |
| `--exclude`             | str[]                       | 无                           | 额外排除的目录名（空格分隔）                   |
| `--extensions`          | str[]                       | 无                           | 额外扫描的文件扩展名（如 `.kt`）               |
| `--max-concurrent`      | int                         | `5`                          | 最大并发 API 请求数                            |
| `--output-json`         | str                         | `security_report.json`       | 最终 JSON 报告输出路径                         |
| `--output-html`         | str                         | `security_report.html`       | 最终 HTML 报告输出路径                         |
| `--api-key`             | str                         | 环境变量 `ANTHROPIC_API_KEY` | Anthropic API 密钥                             |
| `--base-url`            | str                         | 无                           | 自定义 API 端点（用于代理或兼容服务）          |
| `--model`               | str                         | `claude-3-opus-20240229`     | Claude 模型名称                                |
| `--resume`              | flag                        | `False`                      | 启用断点续扫（基于 `.scan_progress.json`）     |
| `--report-interval`     | int                         | `5`                          | 每处理 N 个文件更新一次临时报告                |
| `--large-file-strategy` | `extract`/`skip`/`truncate` | `extract`                    | 大文件（>1MB）处理策略：提取关键段、跳过、截断 |

## 项目结构

text

```
claudecode/
├── scan_project.py        # 主入口脚本
├── file_scanner.py        # 文件扫描与过滤（扩展名、排除目录、大小限制）
├── api_client.py          # Claude API 封装，支持大文件提取和重试
├── batch_processor.py     # 并发批处理器，进度回调与断点续扫
├── report_generator.py    # JSON/HTML 报告生成，聚合发现项
├── findings_filter.py     # 硬排除规则（内存安全、DOS、开放重定向等）
├── prompts.py             # PR 安全审计提示词模板（用于单独 PR 场景）
└── constants.py           # 常量配置（超时、令牌限制、退出码等）
```



## 工作流程

1. **扫描文件** – `FileScanner` 遍历项目，根据扩展名、排除目录、文件大小和排除模式筛选待审文件。
2. **加载进度** – 若启用 `--resume`，从 `.scan_progress.json` 读取已扫描文件，跳过已完成项。
3. **并发分析** – `BatchProcessor` 使用 `ThreadPoolExecutor` 并发调用 `SecurityReviewClient.analyze_file()`，每个文件：
   - 大文件按策略处理（提取关键函数/SQL/路由，或截断/跳过）
   - 调用 Claude API 获取 JSON 格式的漏洞列表
4. **增量报告** – 每完成一个文件，将结果追加到临时 JSONL 文件；每 `report-interval` 个文件生成一次临时 HTML/JSON 快照。
5. **硬过滤** – `ReportGenerator` 在聚合结果时调用 `FindingsFilter`，自动排除以下误报：
   - Markdown 文件中的发现
   - 通用 DOS/资源耗尽问题
   - 速率限制建议
   - 非 C/C++ 文件中的内存安全警告
   - HTML 文件中的 SSRF 发现
   - 开放重定向、正则注入等低影响项
6. **生成报告** – 扫描结束后，从 JSONL 聚合所有结果，应用过滤，生成最终 JSON 和 HTML 报告，并清理临时文件。

## 输出报告示例

### JSON 结构

json

```
{
  "scan_summary": {
    "total_files_scanned": 42,
    "files_with_issues": 3,
    "total_vulnerabilities": 5,
    "scan_time": "2025-04-13T10:30:00"
  },
  "vulnerabilities_by_severity": {
    "critical": 1,
    "high": 2,
    "medium": 2,
    "low": 0
  },
  "vulnerabilities_by_type": {
    "sql_injection": 2,
    "command_injection": 1,
    "hardcoded_secret": 2
  },
  "file_details": [
    {
      "file": "app/auth.py",
      "line_count": 120,
      "vulnerabilities": [...],
      "summary": "Found SQL injection in login handler"
    }
  ],
  "overall_risk_assessment": "HIGH - Urgent remediation recommended"
}
```



### HTML 报告

生成美观的表格样式报告，按严重程度高亮显示，适合分享或归档。

## 环境变量

- `ANTHROPIC_API_KEY` – API 密钥（可通过 `--api-key` 覆盖）
- `CLAUDE_MODEL` – 默认模型名（在 `constants.py` 中定义）

## 注意事项

- 需要有效的 Anthropic API 密钥（或兼容的自定义端点）
- 大文件提取模式可能丢失部分上下文，建议对关键项目使用 `extract`（默认）并人工复核
- 硬排除规则基于关键词匹配，可能存在漏网之鱼；可扩展 `findings_filter.py` 中的规则
- 断点续扫依赖当前扫描参数（如路径、排除规则），若改变参数建议删除 `.scan_progress.json` 重新扫描
