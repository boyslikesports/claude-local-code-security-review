#!/usr/bin/env python3
import argparse
import os
import sys
import json
from pathlib import Path
from tqdm import tqdm

sys.path.insert(0, str(Path(__file__).parent))

from claudecode.file_scanner import FileScanner
from claudecode.api_client import SecurityReviewClient
from claudecode.batch_processor import BatchProcessor
from claudecode.report_generator import ReportGenerator

PROGRESS_FILE = ".scan_progress.json"
TEMP_RESULTS_FILE = ".tmp_results.jsonl"

def load_progress():
    """加载已扫描的文件列表"""
    if os.path.exists(PROGRESS_FILE):
        with open(PROGRESS_FILE, 'r') as f:
            data = json.load(f)
            return set(data.get("scanned_files", []))
    return set()

def save_progress(scanned_files):
    """保存已扫描的文件列表"""
    with open(PROGRESS_FILE, 'w') as f:
        json.dump({"scanned_files": list(scanned_files)}, f, indent=2)

def main():
    parser = argparse.ArgumentParser(description='Full project security scanner')
    parser.add_argument('--path', type=str, default='.', help='Project root path')
    parser.add_argument('--exclude', type=str, nargs='+', help='Additional directories to exclude')
    parser.add_argument('--extensions', type=str, nargs='+', help='Additional file extensions')
    parser.add_argument('--max-concurrent', type=int, default=5, help='Max concurrent API calls')
    parser.add_argument('--output-json', type=str, default='security_report.json', help='Final JSON output')
    parser.add_argument('--output-html', type=str, default='security_report.html', help='Final HTML output')
    parser.add_argument('--api-key', type=str, help='Anthropic API key')
    parser.add_argument('--base-url', type=str, help='Custom API base URL')
    parser.add_argument('--model', type=str, default='claude-3-opus-20240229', help='Claude model')
    parser.add_argument('--resume', action='store_true', help='Resume from previous scan')
    parser.add_argument('--report-interval', type=int, default=5, help='Update report every N files')
    parser.add_argument('--large-file-strategy', choices=['extract', 'skip', 'truncate'], 
                        default='extract', help='How to handle large files (>1MB)')
    
    args = parser.parse_args()
    
    api_key = args.api_key or os.environ.get('ANTHROPIC_API_KEY')
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY required")
    
    # 加载进度
    scanned_set = load_progress() if args.resume else set()
    print(f"🔍 Scanning project: {args.path}")
    print(f"📋 Resume mode: {'ON' if args.resume else 'OFF'}, already scanned: {len(scanned_set)} files")
    
    # 1. 扫描文件
    scanner = FileScanner(args.path, custom_excludes=args.exclude, custom_extensions=args.extensions)
    all_files = scanner.scan()
    print(f"📁 Found {len(all_files)} scannable files")
    
    # 2. 过滤已扫描的文件
    pending_files = []
    for file_path in all_files:
        rel_path = str(file_path.relative_to(scanner.root_path))
        if args.resume and rel_path in scanned_set:
            continue
        info = scanner.get_file_info(file_path)
        if info['content'] or (info['size'] > 1024*1024 and args.large_file_strategy != 'skip'):
            # 大文件即使 content 为 None 也会被后续处理（extract 模式会重新读取）
            pending_files.append(info)
        else:
            print(f"⚠️ Skipping unreadable file: {rel_path}")
    
    print(f"📄 Files to process: {len(pending_files)} (resumed: {len(scanned_set)})")
    
    # 3. 初始化 API 客户端和批处理器
    client = SecurityReviewClient(
        api_key=api_key,
        model=args.model,
        base_url=args.base_url,
        large_file_strategy=args.large_file_strategy
    )
    
    # 初始化报告生成器，支持增量更新
    report_gen = ReportGenerator()
    # 清空临时文件（如果不是恢复模式）
    if not args.resume and os.path.exists(TEMP_RESULTS_FILE):
        os.remove(TEMP_RESULTS_FILE)
    
    # 进度条回调函数
    progress_bar = tqdm(total=len(pending_files), desc="Scanning", unit="file")
    start_time = None
    last_update_count = 0
    
    def progress_callback(current_count, total, elapsed_seconds, avg_time_per_file):
        """更新进度条和预估剩余时间"""
        nonlocal progress_bar, start_time
        if start_time is None:
            start_time = elapsed_seconds
        progress_bar.n = current_count
        if avg_time_per_file > 0:
            remaining = (total - current_count) * avg_time_per_file
            progress_bar.set_postfix(ETA=f"{remaining:.1f}s", speed=f"{avg_time_per_file:.2f}s/file")
        progress_bar.refresh()
    
    def report_callback(file_result):
        """每个文件处理完成后调用，更新增量报告"""
        nonlocal last_update_count
        # 追加到 JSONL
        report_gen.append_result_to_jsonl(file_result, TEMP_RESULTS_FILE)
        # 每 report_interval 个文件更新一次 HTML
        last_update_count += 1
        if last_update_count % args.report_interval == 0:
            # 从 JSONL 聚合当前结果并生成最新 HTML
            partial_aggregated = report_gen.aggregate_from_jsonl(TEMP_RESULTS_FILE)
            report_gen.save_html_report(partial_aggregated, args.output_html + ".tmp")
            # 可选：同时保存临时 JSON 快照
            report_gen.save_json_report(partial_aggregated, args.output_json + ".tmp")
            # 更新进度文件
            scanned_set.add(file_result.get('file'))
            save_progress(scanned_set)
    
    # 4. 执行批量处理
    processor = BatchProcessor(client, max_concurrent=args.max_concurrent)
    results = processor.process_all(
        pending_files,
        progress_callback=progress_callback,
        report_callback=report_callback,
        scanned_set=scanned_set if args.resume else None
    )
    progress_bar.close()
    
    # 5. 生成最终完整报告
    # 从临时 JSONL 读取所有结果
    final_aggregated = report_gen.aggregate_from_jsonl(TEMP_RESULTS_FILE)
    report_gen.save_json_report(final_aggregated, args.output_json)
    report_gen.save_html_report(final_aggregated, args.output_html)
    
    # 清理临时文件
    if os.path.exists(TEMP_RESULTS_FILE):
        os.remove(TEMP_RESULTS_FILE)
    if os.path.exists(PROGRESS_FILE):
        os.remove(PROGRESS_FILE)
    
    print(f"✅ Scan complete. Found {final_aggregated['scan_summary']['total_vulnerabilities']} vulnerabilities")
    print(f"   Overall risk: {final_aggregated['overall_risk_assessment']}")

if __name__ == '__main__':
    main()