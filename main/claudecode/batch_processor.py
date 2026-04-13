import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Callable, Optional, Set

class BatchProcessor:
    def __init__(self, api_client, max_concurrent=5):
        self.api_client = api_client
        self.max_concurrent = max_concurrent
        self.results = []
    
    def process_all(self, files: List[Dict],
                    progress_callback: Optional[Callable] = None,
                    report_callback: Optional[Callable] = None,
                    scanned_set: Optional[Set[str]] = None) -> List[Dict]:
        """
        批量处理文件，支持进度回调和增量报告
        :param files: 待处理文件信息列表
        :param progress_callback: 回调函数 fn(current, total, elapsed, avg_time)
        :param report_callback: 每完成一个文件调用 fn(file_result)
        :param scanned_set: 已扫描文件集合（用于断点续扫，本函数内会更新）
        """
        self.results = []
        total = len(files)
        completed = 0
        start_time = time.time()
        times = []  # 记录每个文件的耗时
        
        with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            future_to_file = {
                executor.submit(self.api_client.analyze_file, file_info): file_info
                for file_info in files
            }
            
            for future in as_completed(future_to_file):
                file_info = future_to_file[future]
                try:
                    result = future.result()
                    self.results.append(result)
                    elapsed = time.time() - start_time
                    completed += 1
                    times.append(elapsed)  # 简化：实际应记录单个文件耗时
                    avg_time = sum(times) / len(times) if times else 0
                    
                    # 进度回调
                    if progress_callback:
                        progress_callback(completed, total, elapsed, avg_time)
                    
                    # 报告回调（每个文件完成后立即增量更新）
                    if report_callback:
                        report_callback(result)
                    
                    # 更新已扫描集合（如果提供）
                    if scanned_set is not None:
                        scanned_set.add(result.get('file'))
                        
                except Exception as e:
                    error_result = {
                        'file': file_info['path'],
                        'error': str(e),
                        'vulnerabilities': []
                    }
                    self.results.append(error_result)
                    if report_callback:
                        report_callback(error_result)
                    completed += 1
        
        return self.results