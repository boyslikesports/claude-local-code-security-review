import os
import fnmatch
from pathlib import Path

class FileScanner:
    """项目文件扫描器"""
    
    # 值得扫描的文件扩展名
    SCANNABLE_EXTENSIONS = {
        # 后端语言
        '.py', '.js', '.ts', '.java', '.go', '.rs', '.rb', '.php',
        '.c', '.cpp', '.h', '.hpp',  # C/C++
        '.cs', '.kt', '.swift',      # .NET/Kotlin/Swift
        
        # 前端
        '.vue', '.jsx', '.tsx',      # 框架文件
        '.html', '.htm',             # 标记语言
        
        # 配置与脚本
        '.yaml', '.yml', '.json', '.toml', '.ini',
        '.sh', '.bash', '.ps1',
        
        # SQL 与数据库
        '.sql', '.prisma', '.graphql',
        
        # 基础设施
        '.tf', '.tfvars',            # Terraform
        '.dockerfile', '.conf', '.cfg'
    }
    
    # 默认排除的目录
    EXCLUDED_DIRS = {
        '.git', 'node_modules', 'dist', 'build', 'target', 
        'venv', '.venv', '__pycache__', '.idea', '.vscode',
        'logs', 'tmp', 'coverage', '.pytest_cache', '.next'
    }
    
    # 排除的文件模式
    EXCLUDED_PATTERNS = [
        '*.min.js', '*.min.css',      # 压缩文件
        '*.lock', '*.sum',             # 锁文件
        '*.log', '*.tmp',              # 日志和临时文件
        '*.exe', '*.dll', '*.so',      # 二进制文件
        '*.png', '*.jpg', '*.ico',     # 图片资源
        '*.pdf', '*.docx',             # 文档
    ]
    
    def __init__(self, root_path, custom_excludes=None, custom_extensions=None):
        self.root_path = Path(root_path).resolve()
        self.excluded_dirs = self.EXCLUDED_DIRS | set(custom_excludes or [])
        self.scannable_exts = self.SCANNABLE_EXTENSIONS | set(custom_extensions or [])
    
    def is_scannable(self, file_path):
        """判断文件是否值得扫描"""
        rel_path = file_path.relative_to(self.root_path)
        
        # 检查是否在排除目录中
        for part in rel_path.parts:
            if part in self.excluded_dirs:
                return False
        
        # 检查文件扩展名
        if file_path.suffix.lower() not in self.scannable_exts:
            return False
        
        # 检查文件大小（限制 1MB）
        if file_path.stat().st_size > 1024 * 1024:
            return False
        
        # 检查是否匹配排除模式
        for pattern in self.EXCLUDED_PATTERNS:
            if fnmatch.fnmatch(file_path.name, pattern):
                return False
        
        return True
    
    def scan(self):
        """遍历项目，返回值得扫描的文件列表"""
        files = []
        for file_path in self.root_path.rglob('*'):
            if file_path.is_file() and self.is_scannable(file_path):
                files.append(file_path)
        return files
    
    def get_file_info(self, file_path):
        """获取文件信息，用于上传"""
        try:
            content = file_path.read_text(encoding='utf-8')
        except (UnicodeDecodeError, OSError):
            content = None  # 非文本文件跳过
        
        return {
            'path': str(file_path.relative_to(self.root_path)),
            'absolute_path': str(file_path),
            'extension': file_path.suffix.lower(),
            'size': file_path.stat().st_size,
            'content': content
        }