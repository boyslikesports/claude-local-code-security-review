import time
import json
import re
from typing import Dict, Any
import anthropic

class SecurityReviewClient:
    def __init__(self, api_key, model="claude-3-opus-20240229", timeout=60, base_url=None,
                 large_file_strategy="extract"):
        """
        :param large_file_strategy: 'extract', 'skip', 'truncate'
        """
        self.model = model
        self.timeout = timeout
        self.max_retries = 3
        self.retry_delay = 5
        self.large_file_strategy = large_file_strategy
        
        kwargs = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        self.client = anthropic.Anthropic(**kwargs)
    
    def extract_key_sections(self, content: str, file_path: str) -> str:
        """从大文件中提取关键代码段"""
        lines = content.splitlines()
        extracted = []
        in_function = False
        function_indent = 0
        
        for i, line in enumerate(lines):
            stripped = line.strip()
            # 函数/类定义
            if re.match(r'^(def |class |async def )', stripped):
                in_function = True
                function_indent = len(line) - len(line.lstrip())
                extracted.append(line)
                for j in range(i+1, min(i+21, len(lines))):
                    next_line = lines[j]
                    if len(next_line) - len(next_line.lstrip()) <= function_indent and next_line.strip():
                        break
                    extracted.append(next_line)
                extracted.append("...")
                continue
            
            # SQL 语句
            if re.search(r'\b(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\b', stripped, re.I):
                extracted.append(line)
                start = max(0, i-2)
                end = min(len(lines), i+3)
                for k in range(start, end):
                    if k != i:
                        extracted.append(lines[k])
                extracted.append("...")
                continue
            
            # 路由装饰器
            if re.search(r'@(app|router|route|get|post|put|delete)', stripped):
                extracted.append(line)
                if i+1 < len(lines):
                    extracted.append(lines[i+1])
                continue
        
        if not extracted:
            return content[:5000]
        
        result = "\n".join(extracted)
        if len(result) > 10000:
            result = result[:10000] + "\n...[truncated]"
        return result
    
    def build_prompt(self, file_path: str, content: str, is_large: bool = False) -> str:
        """构建审计提示词"""
        intro = "NOTE: This file is large (>1MB). Only key sections are shown.\n" if is_large else ""
        
        prompt_template = """You are a senior security engineer performing a code security review.

{intro}Analyze the following file for HIGH-CONFIDENCE security vulnerabilities...

File: {file_path}

Code:
{content}

Respond in JSON format exactly like this:
{{
  "vulnerabilities": [
    {{
      "line": 42,
      "type": "sql_injection",
      "severity": "high",
      "description": "...",
      "suggestion": "..."
    }}
  ],
  "summary": "Brief overview of file security status"
}}

Do not include any text outside the JSON."""
        
        return prompt_template.format(intro=intro, file_path=file_path, content=content)
    
    def analyze_file(self, file_info: Dict) -> Dict[str, Any]:
        """分析单个文件 - 这是 batch_processor 调用的方法"""
        file_path = file_info.get('path')
        content = file_info.get('content')
        file_size = file_info.get('size', 0)
        absolute_path = file_info.get('absolute_path', '')
        is_large = file_size > 1024 * 1024  # 1MB
        
        # 大文件处理策略
        if is_large:
            if self.large_file_strategy == 'skip':
                return {
                    'file': file_path,
                    'error': f'Large file ({file_size} bytes) skipped',
                    'vulnerabilities': []
                }
            elif self.large_file_strategy == 'extract':
                if content is None:
                    try:
                        with open(absolute_path, 'r', encoding='utf-8') as f:
                            full_content = f.read()
                    except Exception as e:
                        return {
                            'file': file_path,
                            'error': f'Cannot read large file for extraction: {str(e)}',
                            'vulnerabilities': []
                        }
                else:
                    full_content = content
                extracted = self.extract_key_sections(full_content, file_path)
                prompt = self.build_prompt(file_path, extracted, is_large=True)
            else:  # truncate
                if content and len(content) > 14000:
                    content = content[:14000] + "\n...[truncated]"
                prompt = self.build_prompt(file_path, content or "", is_large=False)
        else:
            # 正常文件，限制长度
            if content and len(content) > 14000:
                content = content[:14000] + "\n...[truncated]"
            prompt = self.build_prompt(file_path, content or "", is_large=False)
        
        # API 调用（带重试）
        last_exception = None
        for attempt in range(self.max_retries):
            try:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=4096,
                    timeout=self.timeout,
                    messages=[{"role": "user", "content": prompt}]
                )
                response_text = response.content[0].text
                
                # 提取 JSON
                json_match = re.search(r'```json\s*(\{.*?\})\s*```', response_text, re.DOTALL)
                if json_match:
                    response_text = json_match.group(1)
                else:
                    start = response_text.find('{')
                    end = response_text.rfind('}')
                    if start != -1 and end != -1:
                        response_text = response_text[start:end+1]
                
                result = json.loads(response_text)
                result['file'] = file_path
                result['line_count'] = len((content or "").splitlines())
                result['large_file'] = is_large
                return result
                
            except anthropic.RateLimitError as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    wait_time = self.retry_delay * (2 ** attempt)
                    time.sleep(wait_time)
                    continue
                raise
            except (json.JSONDecodeError, KeyError, AttributeError) as e:
                return {
                    'file': file_path,
                    'error': f'Invalid JSON response: {str(e)}',
                    'raw_response': response_text[:500] if 'response_text' in locals() else '',
                    'vulnerabilities': []
                }
            except Exception as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay)
                    continue
                raise
        
        # 所有重试失败
        return {
            'file': file_path,
            'error': f'Max retries exceeded: {str(last_exception)}',
            'vulnerabilities': []
        }