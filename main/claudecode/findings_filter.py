"""增强版 findings filter - 整合 Claude 原版完整硬排除规则，支持二次过滤"""

import re
import time
from typing import Dict, Any, List, Tuple, Optional, Pattern
from dataclasses import dataclass, field

# 如果你需要二次过滤，可以传入一个 API 客户端实例
# from .api_client import SecurityReviewClient

@dataclass
class FilterStats:
    total_findings: int = 0
    hard_excluded: int = 0
    ai_excluded: int = 0
    kept_findings: int = 0
    exclusion_breakdown: Dict[str, int] = field(default_factory=dict)
    runtime_seconds: float = 0.0


class HardExclusionRules:
    """完整版硬排除规则（来自 claude-code-security-review）"""
    
    _DOS_PATTERNS: List[Pattern] = [
        re.compile(r'\b(denial of service|dos attack|resource exhaustion)\b', re.IGNORECASE),
        re.compile(r'\b(exhaust|overwhelm|overload).*?(resource|memory|cpu)\b', re.IGNORECASE),
        re.compile(r'\b(infinite|unbounded).*?(loop|recursion)\b', re.IGNORECASE),
    ]
    
    _RATE_LIMITING_PATTERNS: List[Pattern] = [
        re.compile(r'\b(missing|lack of|no)\s+rate\s+limit', re.IGNORECASE),
        re.compile(r'\brate\s+limiting\s+(missing|required|not implemented)', re.IGNORECASE),
        re.compile(r'\b(implement|add)\s+rate\s+limit', re.IGNORECASE),
        re.compile(r'\bunlimited\s+(requests|calls|api)', re.IGNORECASE),
    ]
    
    _RESOURCE_PATTERNS: List[Pattern] = [
        re.compile(r'\b(resource|memory|file)\s+leak\s+potential', re.IGNORECASE),
        re.compile(r'\bunclosed\s+(resource|file|connection)', re.IGNORECASE),
        re.compile(r'\b(close|cleanup|release)\s+(resource|file|connection)', re.IGNORECASE),
        re.compile(r'\bpotential\s+memory\s+leak', re.IGNORECASE),
        re.compile(r'\b(database|thread|socket|connection)\s+leak', re.IGNORECASE),
    ]
    
    _OPEN_REDIRECT_PATTERNS: List[Pattern] = [
        re.compile(r'\b(open redirect|unvalidated redirect)\b', re.IGNORECASE),
        re.compile(r'\b(redirect.(attack|exploit|vulnerability))\b', re.IGNORECASE),
        re.compile(r'\b(malicious.redirect)\b', re.IGNORECASE),
    ]
    
    _MEMORY_SAFETY_PATTERNS: List[Pattern] = [
        re.compile(r'\b(buffer overflow|stack overflow|heap overflow)\b', re.IGNORECASE),
        re.compile(r'\b(oob)\s+(read|write|access)\b', re.IGNORECASE),
        re.compile(r'\b(out.?of.?bounds?)\b', re.IGNORECASE),
        re.compile(r'\b(memory safety|memory corruption)\b', re.IGNORECASE),
        re.compile(r'\b(use.?after.?free|double.?free|null.?pointer.?dereference)\b', re.IGNORECASE),
        re.compile(r'\b(segmentation fault|segfault|memory violation)\b', re.IGNORECASE),
        re.compile(r'\b(bounds check|boundary check|array bounds)\b', re.IGNORECASE),
        re.compile(r'\b(integer overflow|integer underflow|integer conversion)\b', re.IGNORECASE),
        re.compile(r'\barbitrary.?(memory read|pointer dereference|memory address|memory pointer)\b', re.IGNORECASE),
    ]
    
    _REGEX_INJECTION: List[Pattern] = [
        re.compile(r'\b(regex|regular expression)\s+injection\b', re.IGNORECASE),
        re.compile(r'\b(regex|regular expression)\s+denial of service\b', re.IGNORECASE),
        re.compile(r'\b(regex|regular expression)\s+flooding\b', re.IGNORECASE),
    ]
    
    _SSRF_PATTERNS: List[Pattern] = [
        re.compile(r'\b(ssrf|server\s+.?side\s+.?request\s+.?forgery)\b', re.IGNORECASE),
    ]
    
    @classmethod
    def get_exclusion_reason(cls, finding: Dict[str, Any]) -> Optional[str]:
        # 1. Markdown 文件直接排除
        file_path = finding.get('file', '')
        if file_path.lower().endswith('.md'):
            return "Finding in Markdown documentation file"
        
        description = finding.get('description', '') or ''
        title = finding.get('title', '') or ''
        combined_text = f"{title} {description}".lower()
        
        # 2. DOS
        for pattern in cls._DOS_PATTERNS:
            if pattern.search(combined_text):
                return "Generic DOS/resource exhaustion finding"
        
        # 3. 速率限制
        for pattern in cls._RATE_LIMITING_PATTERNS:
            if pattern.search(combined_text):
                return "Generic rate limiting recommendation"
        
        # 4. 资源管理
        for pattern in cls._RESOURCE_PATTERNS:
            if pattern.search(combined_text):
                return "Resource management finding (not a security vulnerability)"
        
        # 5. 开放重定向
        for pattern in cls._OPEN_REDIRECT_PATTERNS:
            if pattern.search(combined_text):
                return "Open redirect vulnerability (not high impact)"
        
        # 6. 正则注入
        for pattern in cls._REGEX_INJECTION:
            if pattern.search(combined_text):
                return "Regex injection finding (not applicable)"
        
        # 7. 内存安全：仅在 C/C++ 文件中保留，否则排除
        c_cpp_extensions = {'.c', '.cc', '.cpp', '.h', '.hpp'}
        file_ext = ''
        if '.' in file_path:
            file_ext = f".{file_path.lower().split('.')[-1]}"
        if file_ext not in c_cpp_extensions:
            for pattern in cls._MEMORY_SAFETY_PATTERNS:
                if pattern.search(combined_text):
                    return "Memory safety finding in non-C/C++ code (not applicable)"
        
        # 8. SSRF：仅在 HTML 文件中排除（因为 SSRF 是服务端漏洞）
        html_extensions = {'.html', '.htm'}
        if file_ext in html_extensions:
            for pattern in cls._SSRF_PATTERNS:
                if pattern.search(combined_text):
                    return "SSRF finding in HTML file (not applicable to client-side code)"
        
        return None


class FindingsFilter:
    """主过滤器，支持硬排除和可选的 AI 二次过滤"""
    
    def __init__(self,
                 use_hard_exclusions: bool = True,
                 use_ai_filtering: bool = False,
                 ai_client=None,
                 custom_filtering_instructions: Optional[str] = None):
        """
        Args:
            use_hard_exclusions: 是否启用硬排除规则
            use_ai_filtering: 是否启用 AI 二次过滤（需要提供 ai_client）
            ai_client: 一个实现了 analyze_single_finding 方法的客户端（如 SecurityReviewClient 的封装）
            custom_filtering_instructions: 自定义过滤指令
        """
        self.use_hard_exclusions = use_hard_exclusions
        self.use_ai_filtering = use_ai_filtering
        self.ai_client = ai_client
        self.custom_filtering_instructions = custom_filtering_instructions
    
    def filter_findings(self,
                        findings: List[Dict[str, Any]],
                        context: Optional[Dict[str, Any]] = None) -> Tuple[bool, Dict[str, Any], FilterStats]:
        start_time = time.time()
        stats = FilterStats(total_findings=len(findings))
        
        # 第一步：硬排除
        findings_after_hard = []
        excluded_hard = []
        if self.use_hard_exclusions:
            for finding in findings:
                reason = HardExclusionRules.get_exclusion_reason(finding)
                if reason:
                    excluded_hard.append({"finding": finding, "exclusion_reason": reason})
                    stats.hard_excluded += 1
                    key = reason.split('(')[0].strip()
                    stats.exclusion_breakdown[key] = stats.exclusion_breakdown.get(key, 0) + 1
                else:
                    findings_after_hard.append(finding)
        else:
            findings_after_hard = findings[:]
        
        # 第二步：AI 二次过滤（如果启用且提供了客户端）
        findings_after_ai = []
        excluded_ai = []
        if self.use_ai_filtering and self.ai_client and findings_after_hard:
            for finding in findings_after_hard:
                # 构造一个简单的 prompt 让 AI 判断是否为误报
                # 这里你可以复用现有的 api_client 的 analyze_single_finding 方法
                # 或者直接调用 chat 接口询问 "Is this a real vulnerability? Answer yes/no with confidence."
                # 为了简化，我们暂时不做 AI 过滤，只保留硬排除
                findings_after_ai.append(finding)
            # 注：如果你需要 AI 二次过滤，请实现 analyze_single_finding 方法
        else:
            findings_after_ai = findings_after_hard[:]
        
        stats.kept_findings = len(findings_after_ai)
        stats.ai_excluded = len(excluded_ai)
        stats.runtime_seconds = time.time() - start_time
        
        result = {
            "filtered_findings": findings_after_ai,
            "excluded_findings": excluded_hard + excluded_ai,
            "analysis_summary": {
                "total_findings": stats.total_findings,
                "kept_findings": stats.kept_findings,
                "excluded_findings": len(excluded_hard) + len(excluded_ai),
                "hard_excluded": stats.hard_excluded,
                "ai_excluded": stats.ai_excluded,
                "exclusion_breakdown": stats.exclusion_breakdown,
                "runtime_seconds": stats.runtime_seconds
            }
        }
        return True, result, stats