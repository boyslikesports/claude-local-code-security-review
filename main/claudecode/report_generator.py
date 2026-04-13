import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
from .findings_filter import FindingsFilter

class ReportGenerator:
    def __init__(self):
        self.filter = FindingsFilter(use_hard_exclusions=True, use_ai_filtering=False)
    
    def append_result_to_jsonl(self, result: Dict, jsonl_path: str):
        """将单个文件的结果追加到 JSON Lines 文件"""
        with open(jsonl_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(result, ensure_ascii=False) + '\n')
    
    def aggregate_from_jsonl(self, jsonl_path: str) -> Dict:
        """从 JSONL 文件读取所有结果并聚合"""
        results = []
        if not Path(jsonl_path).exists():
            return self._empty_aggregated()
        with open(jsonl_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    results.append(json.loads(line))
        return self.aggregate_results(results)
    
    def _empty_aggregated(self) -> Dict:
        return {
            'scan_summary': {
                'total_files_scanned': 0,
                'files_with_issues': 0,
                'total_vulnerabilities': 0,
                'scan_time': datetime.now().isoformat()
            },
            'vulnerabilities_by_severity': {'critical':0,'high':0,'medium':0,'low':0},
            'vulnerabilities_by_type': {},
            'file_details': [],
            'overall_risk_assessment': 'No data'
        }
    
    def aggregate_results(self, results: List[Dict]) -> Dict:
        """与原始代码相同，略作优化（省略重复代码，保持原有逻辑）"""
        # 此处复用原 aggregate_results 代码，但注意要处理 'large_file' 等新字段
        # 原代码已经可以工作，只需确保正确导入 FindingsFilter
        aggregated = {
            'scan_summary': {
                'total_files_scanned': len(results),
                'files_with_issues': 0,
                'total_vulnerabilities': 0,
                'scan_time': datetime.now().isoformat()
            },
            'vulnerabilities_by_severity': {'critical':0,'high':0,'medium':0,'low':0},
            'vulnerabilities_by_type': {},
            'file_details': [],
            'overall_risk_assessment': ''
        }
        for result in results:
            if 'error' in result:
                aggregated['file_details'].append({'file': result['file'], 'error': result['error']})
                continue
            vulns = result.get('vulnerabilities', [])
            _, filtered_result, _ = self.filter.filter_findings(vulns)
            filtered = filtered_result.get('filtered_findings', [])
            if filtered:
                aggregated['scan_summary']['files_with_issues'] += 1
                aggregated['scan_summary']['total_vulnerabilities'] += len(filtered)
                for v in filtered:
                    sev = v.get('severity', 'medium').lower()
                    if sev not in aggregated['vulnerabilities_by_severity']:
                        sev = 'medium'
                    aggregated['vulnerabilities_by_severity'][sev] += 1
                    typ = v.get('type', 'unknown')
                    aggregated['vulnerabilities_by_type'][typ] = aggregated['vulnerabilities_by_type'].get(typ,0)+1
                aggregated['file_details'].append({
                    'file': result['file'],
                    'line_count': result.get('line_count', 0),
                    'vulnerabilities': filtered,
                    'summary': result.get('summary', '')
                })
        c = aggregated['vulnerabilities_by_severity']['critical']
        h = aggregated['vulnerabilities_by_severity']['high']
        if c>0:
            aggregated['overall_risk_assessment'] = 'CRITICAL - Immediate action required'
        elif h>0:
            aggregated['overall_risk_assessment'] = 'HIGH - Urgent remediation recommended'
        else:
            aggregated['overall_risk_assessment'] = 'MODERATE - Review recommended'
        return aggregated
    
    def save_json_report(self, aggregated: Dict, output_path: str):
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(aggregated, f, indent=2, ensure_ascii=False)
        print(f"JSON report saved to {output_path}")
    
    def save_html_report(self, aggregated: Dict, output_path: str):
        """与原 save_html_report 相同，略（可复用原代码）"""
        # 原代码已存在，此处省略重复
        pass